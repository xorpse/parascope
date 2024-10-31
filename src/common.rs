use std::borrow::Cow;
use std::fmt::Display;
use std::io;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled};

use weggli_ruleset::matcher::RuleMatch;
use weggli_ruleset::rule::Severity;
use weggli_ruleset::RuleSet;

use wegglix::result::QueryResult;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct MatchResult {
    pub rule: usize,
    pub checker: usize,
    pub result: QueryResult,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MatchResultGroup {
    pub source: String,
    pub function_name: Option<String>,
    pub function_address: Option<u64>,
    pub results: Vec<MatchResult>,
}

#[derive(Deserialize, Serialize)]
pub struct MatchResultRecord<'a> {
    pub rule: Cow<'a, str>,
    pub checker: Cow<'a, str>,
    pub severity: Severity,
    pub result: Cow<'a, QueryResult>,
}

#[derive(Deserialize, Serialize)]
pub struct MatchResultGroupRecord<'a> {
    pub path: Cow<'a, Path>,
    pub source: Cow<'a, str>,
    pub function_name: Option<Cow<'a, str>>,
    pub function_address: Option<u64>,
    pub results: Vec<MatchResultRecord<'a>>,
}

// The types below are to display the summary table

struct Address(Option<u64>);
struct FunctionName<'a>(&'a Option<String>);

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(addr) = self.0 {
            write!(f, "{addr:#x}")
        } else {
            f.write_str("-")
        }
    }
}

impl Display for FunctionName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = self.0 {
            f.write_str(name)
        } else {
            f.write_str("-")
        }
    }
}

#[derive(Tabled)]
struct PathWithFindingRow<'a> {
    #[tabled(display_with = "Path::display", rename = "File")]
    path: &'a Path,
    #[tabled(inline)]
    finding: FindingRow<'a>,
}

#[derive(Tabled)]
struct FindingRow<'a> {
    #[tabled(rename = "Function name")]
    function_name: FunctionName<'a>,
    #[tabled(rename = "Function address")]
    function_address: Address,
    #[tabled(rename = "Rule")]
    rule: &'a str,
    #[tabled(rename = "Checker")]
    checker: &'a str,
    #[tabled(rename = "Severity")]
    severity: Severity,
}

impl From<RuleMatch> for MatchResult {
    fn from(m: RuleMatch) -> Self {
        Self {
            rule: m.rule_id(),
            checker: m.checker_id(),
            result: m.into_result(),
        }
    }
}

impl MatchResultGroup {
    pub(crate) fn new_with(
        function_name: impl Into<Option<String>>,
        function_address: impl Into<Option<u64>>,
        source: String,
        matches: Vec<RuleMatch>,
    ) -> Self {
        MatchResultGroup {
            source,
            function_name: function_name.into(),
            function_address: function_address.into(),
            results: matches.into_iter().map(MatchResult::from).collect(),
        }
    }

    pub(crate) fn new(source: String, matches: Vec<RuleMatch>) -> Self {
        Self::new_with(None, None, source, matches)
    }

    pub(crate) fn display_pretty(
        &self,
        rules: &RuleSet,
        origin: impl AsRef<Path>,
        display_context: usize,
    ) {
        let origin = origin.as_ref();

        for result in self.results.iter() {
            let rule = rules.get(result.rule).expect("valid rule");
            let checker = rule.checks().get(result.checker).expect("valid checker");

            print!(
                "[{:?}] rule {}, check {} triggered in {}",
                rule.severity(),
                rule.id(),
                checker.name(),
                origin.display(),
            );

            if let Some(name) = self.function_name.as_ref() {
                print!(" in function {name}");
            }

            if let Some(addr) = self.function_address {
                print!(" at address {addr:#x}");
            }

            println!();

            let rendered =
                result
                    .result
                    .display(&self.source, display_context, display_context, true);

            println!("{rendered}");
        }
    }

    pub(crate) fn display_table(&self, rules: &RuleSet, origin: impl AsRef<Path>) {
        let origin = origin.as_ref();
        println!(
            "{}",
            Table::new(self.results.iter().map(move |result| {
                let rule = rules.get_ref(result.rule).expect("valid rule");
                let checker = rule.checks().get(result.checker).expect("valid checker");

                PathWithFindingRow {
                    path: origin,
                    finding: FindingRow {
                        function_name: FunctionName(&self.function_name),
                        function_address: Address(self.function_address),
                        rule: rule.id(),
                        checker: checker.name(),
                        severity: rule.severity(),
                    },
                }
            }))
            .with(tabled::settings::Style::sharp())
        );
    }

    pub(crate) fn write_record(
        &self,
        rules: &RuleSet,
        origin: impl AsRef<Path>,
        mut writer: impl Write,
    ) -> Result<(), io::Error> {
        // write as a single json line...
        serde_json::to_writer(
            &mut writer,
            &MatchResultGroupRecord {
                path: Cow::Borrowed(origin.as_ref()),
                function_name: self.function_name.as_deref().map(Cow::Borrowed),
                function_address: self.function_address,
                source: Cow::Borrowed(&self.source),
                // unfortunate allocation... maybe rethink this format?
                results: self
                    .results
                    .iter()
                    .map(|result| {
                        let rule = rules.get_ref(result.rule).expect("valid rule");
                        let checker = rule.checks().get(result.checker).expect("valid checker");
                        MatchResultRecord {
                            rule: Cow::Borrowed(rule.id()),
                            checker: Cow::Borrowed(checker.name()),
                            severity: rule.severity(),
                            result: Cow::Borrowed(&result.result),
                        }
                    })
                    .collect(),
            },
        )?;
        writer.write_all(b"\n")?;

        Ok(())
    }
}
