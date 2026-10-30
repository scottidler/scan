// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/grader/grader.js, the scoring in
// src/scanner/index.js, test/grader.test.js).

//! Score and grade: the sum of the 12 test modifiers, bonuses only when the penalty-only score is
//! already an A, mapped through the 21-bucket chart.

use super::TestResult;
use super::charts::{GRADE_CHART, MINIMUM_SCORE_FOR_EXTRA_CREDIT, SCORE_TABLE, ScoreEntry, TEST_TOPIC_LINKS};
use super::types::Expectation;

/// Observatory's 13 letter grades.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GradeLetter {
    APlus,
    A,
    AMinus,
    BPlus,
    B,
    BMinus,
    CPlus,
    C,
    CMinus,
    DPlus,
    D,
    DMinus,
    F,
}

impl GradeLetter {
    pub fn as_str(&self) -> &'static str {
        match self {
            GradeLetter::APlus => "A+",
            GradeLetter::A => "A",
            GradeLetter::AMinus => "A-",
            GradeLetter::BPlus => "B+",
            GradeLetter::B => "B",
            GradeLetter::BMinus => "B-",
            GradeLetter::CPlus => "C+",
            GradeLetter::C => "C",
            GradeLetter::CMinus => "C-",
            GradeLetter::DPlus => "D+",
            GradeLetter::D => "D",
            GradeLetter::DMinus => "D-",
            GradeLetter::F => "F",
        }
    }
}

impl std::fmt::Display for GradeLetter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `getGradeForScore`: the score floored at 0 (never capped), and the grade of
/// `min(score - score % 5, 100)`.
pub fn grade_for_score(score: i32) -> (i32, GradeLetter) {
    let score = score.max(0);
    let key = (score - score % 5).min(100);
    let grade = GRADE_CHART
        .iter()
        .find(|(bucket, _)| *bucket == key)
        .map(|(_, grade)| *grade)
        .expect("GRADE_CHART covers every multiple of 5 from 0 to 100");
    (score, grade)
}

/// The scoring in `analyzeScan`: `uncurved = 100 + Σ negative modifiers`,
/// `with_credit = 100 + Σ all modifiers`; the score is `with_credit` when `uncurved` reaches
/// [`MINIMUM_SCORE_FOR_EXTRA_CREDIT`], else `uncurved`.
pub fn grade(tests: &[TestResult]) -> (i32, GradeLetter) {
    let with_credit: i32 = 100 + tests.iter().map(|t| t.score_modifier).sum::<i32>();
    let uncurved: i32 = 100 + tests.iter().map(|t| t.score_modifier.min(0)).sum::<i32>();
    let score = if uncurved >= MINIMUM_SCORE_FOR_EXTRA_CREDIT { with_credit } else { uncurved };
    let (score, letter) = grade_for_score(score);
    log::debug!(
        "[observatory::grade] grade: tests={} uncurved={} with_credit={} score={} grade={}",
        tests.len(),
        uncurved,
        with_credit,
        score,
        letter
    );
    (score, letter)
}

fn score_entry(expectation: Expectation) -> Option<&'static ScoreEntry> {
    SCORE_TABLE.iter().find(|entry| entry.expectation == expectation)
}

/// `getScoreModifier`.
pub fn score_modifier(expectation: Expectation) -> i32 {
    score_entry(expectation).map_or(0, |entry| entry.modifier)
}

/// `getScoreDescription` (HTML).
pub fn score_description(expectation: Expectation) -> &'static str {
    score_entry(expectation).map_or("", |entry| entry.description)
}

/// `getRecommendation` (HTML).
pub fn recommendation(expectation: Expectation) -> &'static str {
    score_entry(expectation).map_or("", |entry| entry.recommendation)
}

/// `getTopicLink`: the MDN path documenting a test.
pub fn topic_link(test_name: &str) -> &'static str {
    TEST_TOPIC_LINKS
        .iter()
        .find(|(name, _)| *name == test_name)
        .map_or("", |(_, link)| link)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_with_modifier(score_modifier: i32) -> TestResult {
        TestResult {
            name: "synthetic",
            result: Expectation::CspNotImplemented,
            score_modifier,
            pass: false,
        }
    }

    /// Ported from test/grader.test.js, one test per upstream `it(`.
    mod upstream {
        use super::super::*;

        #[test]
        fn gets_the_score_description() {
            let res = score_description(Expectation::CspNotImplemented);
            assert!(
                res.contains("Content Security Policy (CSP) header not implemented"),
                "{res}"
            );
        }

        #[test]
        fn gets_the_score_modifier() {
            assert_eq!(score_modifier(Expectation::CspNotImplemented), -25);
        }

        #[test]
        fn gets_the_recommendation() {
            let res = recommendation(Expectation::CspNotImplemented);
            assert!(res.contains("Implement one, see "), "{res}");
        }

        #[test]
        fn gets_the_topic_link_for_a_test_name() {
            assert!(topic_link("cookies").contains("/en-US/docs/Web/Security/Practical_implementation_guides/Cookies"));
        }

        #[test]
        fn gets_the_grade() {
            assert_eq!(grade_for_score(100), (100, GradeLetter::APlus));
            assert_eq!(grade_for_score(0), (0, GradeLetter::F));
            assert_eq!(grade_for_score(120), (120, GradeLetter::APlus));
            assert_eq!(grade_for_score(-10), (0, GradeLetter::F));
        }
    }

    /// Every bucket of `GRADE_CHART`, a score inside each bucket, and the clamps at both ends.
    #[test]
    fn every_score_maps_to_its_bucket() {
        let table: [(i32, &str); 27] = [
            (100, "A+"),
            (135, "A+"),
            (99, "A"),
            (95, "A"),
            (90, "A"),
            (89, "A-"),
            (85, "A-"),
            (80, "B+"),
            (79, "B"),
            (75, "B"),
            (70, "B"),
            (65, "B-"),
            (60, "C+"),
            (55, "C"),
            (50, "C"),
            (45, "C-"),
            (44, "D+"),
            (40, "D+"),
            (35, "D"),
            (30, "D"),
            (25, "D-"),
            (20, "F"),
            (15, "F"),
            (10, "F"),
            (5, "F"),
            (0, "F"),
            (-40, "F"),
        ];
        for (score, expected) in table {
            let (_, letter) = grade_for_score(score);
            assert_eq!(letter.as_str(), expected, "score {score}");
        }
    }

    /// Penalties that leave 89 drop every bonus; at 90 the bonuses count.
    #[test]
    fn bonuses_count_only_from_a_penalty_only_score_of_90() {
        let at_89 = [test_with_modifier(-11), test_with_modifier(10), test_with_modifier(5)];
        assert_eq!(grade(&at_89), (89, GradeLetter::AMinus));

        let at_90 = [test_with_modifier(-10), test_with_modifier(10), test_with_modifier(5)];
        assert_eq!(grade(&at_90), (105, GradeLetter::APlus));
    }

    /// The score is floored at 0, and the bonus rule never lifts a failing score.
    #[test]
    fn heavy_penalties_floor_at_zero() {
        let tests = [test_with_modifier(-50), test_with_modifier(-60), test_with_modifier(10)];
        assert_eq!(grade(&tests), (0, GradeLetter::F));
    }

    #[test]
    fn every_result_has_a_score_table_row() {
        for expectation in Expectation::ALL {
            assert!(score_entry(*expectation).is_some(), "{expectation}");
        }
        assert_eq!(SCORE_TABLE.len(), Expectation::ALL.len());
    }
}
