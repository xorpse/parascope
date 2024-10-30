use serde::{Deserialize, Serialize};
use weggli_ruleset::matcher::RuleMatch;
use wegglix::result::QueryResult;

#[derive(Deserialize, Serialize)]
pub(crate) struct MatchResult {
    pub rule: usize,
    pub checker: usize,
    pub result: QueryResult,
}

#[derive(Deserialize, Serialize)]
pub struct MatchResultGroup {
    pub source: String,
    pub function_name: Option<String>,
    pub function_address: Option<u64>,
    pub results: Vec<MatchResult>,
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
}

/*
pub(crate) fn display_match(result: &RuleMatchReport) {
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
*/
