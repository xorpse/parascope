use std::fs::File;
use std::io::{stdout, BufWriter, Write};
use std::path::Path;
use std::process::exit;

use clap::{Arg, Command};
use regex::RegexSet;
use weggli_ruleset::RuleSet;

mod binary;
mod common;
mod source;

#[derive(Clone, Copy, clap::ValueEnum)]
enum AnalysisMode {
    /// Binary analysis mode (using IDA)
    Binary,
    /// Source code analysis mode (C)
    C,
    /// Source code analysis mode (C++)
    Cxx,
}

pub struct Configuration {
    pub rules: RuleSet,

    pub input: String,
    pub multi_input: bool,
    pub path_filters: Option<RegexSet>,

    pub display: bool,
    pub display_context: usize,

    pub summary: bool,

    pub output_is_stdout: bool,
    pub writer: Option<Box<dyn Write + Send + 'static>>,
}

fn open_writer(output: impl AsRef<str>) -> (bool, Box<dyn Write + Send + 'static>) {
    let output = output.as_ref();
    if output == "-" {
        return (true, Box::new(stdout()));
    }

    match File::create(output) {
        Ok(file) => (false, Box::new(BufWriter::new(file))),
        Err(e) => {
            eprintln!("cannot open output file for writing: {e}");
            exit(-1);
        }
    }
}

fn main() -> anyhow::Result<()> {
    // NOTE: this allows us to avoid IDA's noisy output
    idalib::force_batch_mode();

    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::new("mode")
                .help("Analysis mode")
                .long("mode")
                .short('m')
                .value_parser(clap::value_parser!(AnalysisMode))
                .default_value("binary"),
        )
        .arg(
            Arg::new("path-filter")
                .help("Restrict analysis to files matching the given regular expression")
                .long_help(
                    "Restrict analysis to files matching the given regular expression.
For C/C++ analysis if no path filters are given analysis is restricted
to a set of default file extensions:

C: c, h
C++: C, cc, cxx, cpp, H, hh, hxx, hpp, h

For binary analysis, all files will be analysed. If an existing IDB is
available, e.g., we have both file and file.i64, only the IDB will be
used for analysis irrespective of the path filter.",
                )
                .long("path-filter")
                .num_args(0..),
        )
        .arg(
            Arg::new("display")
                .help("Render matches to stdout")
                .long("display")
                .num_args(0)
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("display-context")
                .help("Number of lines before/after match to render")
                .long("display-context")
                .default_value("5")
                .value_parser(clap::value_parser!(usize))
                .requires("display"),
        )
        .arg(
            Arg::new("summary")
                .help("Render tabular summary to stdout")
                .long("summary")
                .conflicts_with_all(["display", "display-context"])
                .num_args(0)
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("rules")
                .help("File or directory containing wegglir rules")
                .long("rules")
                .short('r')
                .required(true),
        )
        .arg(
            Arg::new("INPUT")
                .help("File or directory to scan")
                .required(true),
        )
        .arg(
            Arg::new("OUTPUT")
                .help("File to write output results (JSONL)")
                .long("output")
                .short('o')
                .required(false),
        )
        .get_matches();

    let input = matches
        .get_one::<String>("INPUT")
        .expect("required")
        .to_owned();
    let input_path = Path::new(&input);

    if !input_path.exists() {
        eprintln!("input file/directory does not exist");
        exit(-1);
    }
    let multi_input = input_path.is_dir();

    let (output_is_stdout, writer) = if let Some(output) = matches.get_one::<String>("OUTPUT") {
        let (output_is_stdout, writer) = open_writer(output);
        (output_is_stdout, Some(writer))
    } else {
        (false, None)
    };

    let mode = matches
        .get_one::<AnalysisMode>("mode")
        .expect("required; has default");

    let display = matches.get_flag("display");
    let display_context = matches
        .get_one::<usize>("display-context")
        .copied()
        .unwrap_or_default();

    let summary = matches.get_flag("summary");

    if writer.is_none() && !display && !summary {
        eprintln!("no display or reporting options set");
        exit(-1);
    }

    let path_filters = match matches
        .get_many::<String>("path-filter")
        .map(RegexSet::new)
        .transpose()
    {
        Ok(filters) => filters,
        Err(e) => {
            eprintln!("invalid path filter(s): {e}");
            exit(-1);
        }
    };

    let rules = Path::new(matches.get_one::<String>("rules").expect("required"));
    if !rules.exists() {
        eprintln!("rule file/directory does not exist");
        exit(-1);
    }

    let rules = match if rules.is_dir() {
        RuleSet::from_directory(rules, true)
    } else {
        RuleSet::from_file(rules)
    } {
        Ok(rules) => {
            if rules.is_empty() {
                eprintln!("no viable rules available at the path specified");
                exit(-1);
            } else {
                rules
            }
        }
        Err(e) => {
            eprintln!("could not parse rules: {e}");
            exit(-1);
        }
    };

    let config = Configuration {
        rules,
        input,
        multi_input,
        path_filters,
        display,
        display_context,
        summary,
        output_is_stdout,
        writer,
    };

    let result = match mode {
        AnalysisMode::Binary => binary::scan(config),
        AnalysisMode::C => source::scan(config, false),
        AnalysisMode::Cxx => source::scan(config, true),
    };

    if let Err(e) = result {
        eprintln!("scan failed: {e}");
        exit(-1);
    }

    Ok(())
}
