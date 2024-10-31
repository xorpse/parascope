use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::Context;

use fugue_mptp::sources::DirectorySource;
use fugue_mptp::{TaskProcessor, TaskSink, Uuid};

use regex::RegexSet;
use weggli_ruleset::matcher::RuleMatcher;
use weggli_ruleset::RuleSet;

use crate::common::MatchResultGroup;
use crate::Configuration;

static C_RE: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new(["\\.(c|h)$"]).expect("valid regex"));

static CXX_RE: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new(["\\.(C|cc|cxx|cpp|H|hh|hxx|hpp|h)$"]).expect("valid regex"));

pub fn scan(config: Configuration, cxx: bool) -> anyhow::Result<()> {
    if config.multi_input {
        scan_many(config, cxx)
    } else {
        scan_one(config, cxx)
    }
}

fn scan_aux(
    input: impl AsRef<Path>,
    cxx: bool,
    rules: RuleSet,
) -> anyhow::Result<MatchResultGroup> {
    let input = input.as_ref();
    let source = fs::read_to_string(&input).context("cannot open file to scan")?;

    let mut matcher = RuleMatcher::new(rules).context("cannot construct rule matcher")?;

    let matches = matcher
        .matches_with(&source, cxx)
        .context("cannot perform rule matching")?;

    Ok(MatchResultGroup::new(source, matches))
}

fn scan_one(mut config: Configuration, cxx: bool) -> anyhow::Result<()> {
    let input = config.input;
    let filters = config
        .path_filters
        .as_ref()
        .unwrap_or_else(|| if cxx { &*CXX_RE } else { &*C_RE });

    if !filters.is_match(&input) {
        // skipping...
        return Ok(());
    }

    let matches = scan_aux(&input, cxx, config.rules.clone())?;

    if config.display && !config.output_is_stdout {
        matches.display_pretty(&config.rules, &input, config.display_context);
    }

    if config.summary && !config.output_is_stdout {
        matches.display_table(&config.rules, &input);
    }

    if let Some(mut writer) = config.writer.as_mut() {
        matches.write_record(&config.rules, &input, &mut writer)?;
    }

    Ok(())
}

fn scan_many(config: Configuration, cxx: bool) -> anyhow::Result<()> {
    struct SourceCodeProcessor {
        rules: RuleSet,
        cxx: bool,
    }

    impl TaskProcessor for SourceCodeProcessor {
        type TaskError = (PathBuf, String);
        type TaskInput = PathBuf;
        type TaskOutput = (PathBuf, MatchResultGroup);

        fn process_task(
            &mut self,
            _id: Uuid,
            input: PathBuf,
        ) -> Result<(PathBuf, MatchResultGroup), (PathBuf, String)> {
            match scan_aux(&input, self.cxx, self.rules.clone()) {
                Ok(r) => Ok((input, r)),
                Err(e) => Err((input, e.to_string())),
            }
        }
    }

    struct SourceCodeResults {
        rules: RuleSet,
        display: bool,
        display_context: usize,
        summary: bool,
        output_is_stdout: bool,
        writer: Option<Box<dyn Write + Send + 'static>>,
    }

    impl TaskSink for SourceCodeResults {
        type Error = io::Error;

        type TaskError = (PathBuf, String);
        type TaskOutput = (PathBuf, MatchResultGroup);

        fn process_task_result(
            &mut self,
            _id: Uuid,
            result: Result<Self::TaskOutput, Self::TaskError>,
        ) -> Result<(), Self::Error> {
            let (input, results) = match result {
                Ok(ok) => ok,
                Err((path, err)) => {
                    if !self.output_is_stdout {
                        println!("failed to analyse {}: {err}", path.display());
                    }
                    return Ok(());
                }
            };

            if self.display && !self.output_is_stdout {
                results.display_pretty(&self.rules, &input, self.display_context);
            }

            if self.summary && !self.output_is_stdout {
                results.display_table(&self.rules, &input);
            }

            if let Some(mut writer) = self.writer.as_mut() {
                results.write_record(&self.rules, &input, &mut writer)?;
            }
            Ok(())
        }
    }

    let mut source = DirectorySource::new_with(&config.input, move |path| {
        let filters =
            config
                .path_filters
                .as_ref()
                .unwrap_or_else(|| if cxx { &*CXX_RE } else { &*C_RE });

        filters.is_match(&path.to_string_lossy())
    });

    let mut processor = SourceCodeProcessor {
        rules: config.rules.clone(),
        cxx,
    };

    let mut sink = SourceCodeResults {
        rules: config.rules,
        display: config.display,
        display_context: config.display_context,
        summary: config.summary,
        output_is_stdout: config.output_is_stdout,
        writer: config.writer,
    };

    fugue_mptp::run(&mut source, &mut processor, &mut sink)?;

    Ok(())
}
