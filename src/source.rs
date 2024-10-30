use std::fs;

use anyhow::Context;
use weggli_ruleset::matcher::RuleMatcher;

use crate::Configuration;

pub fn scan(config: Configuration, cxx: bool) -> anyhow::Result<()> {
    if config.multi_input {
        scan_many(config, cxx)
    } else {
        scan_one(config, cxx)
    }
}

fn scan_one(config: Configuration, cxx: bool) -> anyhow::Result<()> {
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

    let source = fs::read_to_string(&input).context("cannot open file to scan")?;

    let mut matcher = RuleMatcher::new(config.rules).context("cannot construct rule matcher")?;

    let results = matcher
        .matches_with(&source, cxx)
        .context("cannot perform rule matching")?;

    if results.is_empty() {
        return Ok(());
    }

    if config.output_is_stdout {
        // TODO: ...
    } else if config.display {
        for result in results.iter() {
            println!(
                "[{:?}] rule {}, check {} triggered for {source}",
                result.rule().severity(),
                result.rule().id(),
                result.checker().name(),
            );

            let rendered = result.display(config.display_context, config.display_context, true);

            println!("{rendered}");
        }
    }

    Ok(())
}

fn scan_many(config: Configuration, cxx: bool) -> anyhow::Result<()> {
    todo!()
}
