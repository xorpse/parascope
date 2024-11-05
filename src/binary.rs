use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};

use fugue_mptp::sources::DirectorySource;
use fugue_mptp::{TaskProcessor, TaskSink, Uuid};

use idalib::idb::IDB;

use weggli_ruleset::matcher::RuleMatcher;
use weggli_ruleset::RuleSet;

use crate::common::MatchResultGroup;
use crate::Configuration;

pub fn scan(config: Configuration) -> anyhow::Result<()> {
    if config.multi_input {
        scan_many(config)
    } else {
        scan_one(config)
    }
}

fn scan_aux(input: impl AsRef<Path>, rules: RuleSet) -> anyhow::Result<Vec<MatchResultGroup>> {
    let input = input.as_ref();
    let idb = IDB::open_with(&input, true, true).context("cannot create IDB for scan target")?;

    if !idb.decompiler_available() {
        return Err(anyhow!("cannot process IDB as decompiler is not available"));
    }

    let mut matcher = RuleMatcher::new(rules).context("cannot construct rule matcher")?;
    let mut matches = Vec::new();

    for (_, f) in idb.functions() {
        let Some(decomp) = idb.decompile(&f) else {
            continue;
        };

        let source = decomp.pseudocode();

        let Ok(results) = matcher.matches_with(&source, false) else {
            continue;
        };

        if results.is_empty() {
            continue;
        }

        matches.push(MatchResultGroup::new_with(
            f.name(),
            f.start_address(),
            source,
            results,
        ));
    }

    Ok(matches)
}

fn scan_one(mut config: Configuration) -> anyhow::Result<()> {
    let input = config.input;
    let filters = config.path_filters;

    if !filters
        .as_ref()
        .map(|filters| filters.is_match(&input))
        .unwrap_or(true)
    {
        // skipping...
        return Ok(());
    }

    let matches = scan_aux(&input, config.rules.clone())?;

    if config.display && !config.output_is_stdout {
        matches.iter().for_each(|result| {
            result.display_pretty(&config.rules, &input, config.display_context)
        });
    }

    if config.summary && !config.output_is_stdout {
        matches
            .iter()
            .for_each(|result| result.display_table(&config.rules, &input));
    }

    if let Some(mut writer) = config.writer.as_mut() {
        matches
            .iter()
            .try_for_each(|result| result.write_record(&config.rules, &input, &mut writer))?;
    }

    Ok(())
}

fn scan_many(config: Configuration) -> anyhow::Result<()> {
    struct IDAProcessor {
        rules: RuleSet,
    }

    impl TaskProcessor for IDAProcessor {
        type TaskError = (PathBuf, String);
        type TaskInput = PathBuf;
        type TaskOutput = (PathBuf, Vec<MatchResultGroup>);

        fn process_task(
            &mut self,
            _id: Uuid,
            input: PathBuf,
        ) -> Result<(PathBuf, Vec<MatchResultGroup>), (PathBuf, String)> {
            match scan_aux(&input, self.rules.clone()) {
                Ok(r) => Ok((input, r)),
                Err(e) => Err((input, e.to_string())),
            }
        }
    }

    struct IDAResults {
        rules: RuleSet,
        display: bool,
        display_context: usize,
        summary: bool,
        output_is_stdout: bool,
        writer: Option<Box<dyn Write + Send + 'static>>,
    }

    impl TaskSink for IDAResults {
        type Error = io::Error;

        type TaskError = (PathBuf, String);
        type TaskOutput = (PathBuf, Vec<MatchResultGroup>);

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
                results.iter().for_each(|result| {
                    result.display_pretty(&self.rules, &input, self.display_context)
                });
            }

            if self.summary && !self.output_is_stdout {
                results
                    .iter()
                    .for_each(|result| result.display_table(&self.rules, &input));
            }

            if let Some(mut writer) = self.writer.as_mut() {
                results
                    .iter()
                    .try_for_each(|result| result.write_record(&self.rules, &input, &mut writer))?;
            }

            Ok(())
        }
    }

    let mut source = DirectorySource::new_with(&config.input, move |path| {
        config
            .path_filters
            .as_ref()
            .map(|filters| filters.is_match(&path.to_string_lossy()))
            .unwrap_or(true)
            && (matches!(path.extension(), Some(ext) if ext == "i64")
                || !path.with_extension("i64").exists())
    });

    let mut processor = IDAProcessor {
        rules: config.rules.clone(),
    };

    let mut sink = IDAResults {
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
