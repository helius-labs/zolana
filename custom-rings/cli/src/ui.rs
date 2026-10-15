//! The look of every printed line and the dialogue behind every question.

use std::{fmt::Display, io::IsTerminal};

use anyhow::{bail, Context as _, Result};
use console::Style;
use dialoguer::theme::ColorfulTheme;

const SAGE: u8 = 108;
const AMBER: u8 = 179;
const RED: u8 = 167;

/// One glyph per section heading or final line, never per row.
pub mod icon {
    pub const RING: &str = "🪐";
    pub const POLICY: &str = "📜";
    pub const LISTS: &str = "🗂";
    pub const CURATOR: &str = "🤝";
    pub const TREE: &str = "🌳";
    pub const PIN: &str = "🔏";
    pub const AUDITOR: &str = "🧾";
    pub const PAUSE: &str = "⏸";
    pub const RESUME: &str = "▶";
    pub const WIZARD: &str = "🧭";
}

/// The `check` reason is shown to the operator.
pub type Check<'a> = &'a dyn Fn(&str) -> Result<(), String>;

/// Every question a command asks goes through one of these.
pub trait Ask {
    fn interactive(&self) -> bool;
    fn text(
        &mut self,
        prompt: &str,
        default: Option<String>,
        empty: bool,
        check: Check<'_>,
    ) -> Result<String>;
    fn pick(&mut self, prompt: &str, items: &[String], default: usize) -> Result<usize>;
    fn pick_many(&mut self, prompt: &str, items: &[String]) -> Result<Vec<usize>>;
    fn confirm(&mut self, prompt: &str, default: bool) -> Result<bool>;
}

pub struct Terminal;

/// Every question takes its default, a choice picks nothing.
pub struct Defaults;

/// Prompts draw on stderr, both it and stdin must be terminals to ask.
pub fn ask_for(silent: bool) -> Box<dyn Ask> {
    if !silent && std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        Box::new(Terminal)
    } else {
        Box::new(Defaults)
    }
}

pub fn accept(_answer: &str) -> Result<(), String> {
    Ok(())
}

/// The aligned label of every status line, an outcome word takes its tone.
pub fn line(label: &str, value: impl Display) {
    let text = value.to_string();
    let styled = tone(&text).unwrap_or_default().apply_to(text);
    println!("{}{styled}", dim().apply_to(format!("{label:<12}")));
}

pub fn heading(icon: &str, text: &str) {
    println!("{icon} {}", Style::new().bold().apply_to(text));
}

pub fn hint(text: impl Display) {
    println!("{}", dim().italic().apply_to(text));
}

pub fn warn(text: impl Display) {
    println!("{}", Style::new().color256(AMBER).apply_to(text));
}

pub fn refusal(text: impl Display) {
    println!("{}", Style::new().color256(RED).apply_to(text));
}

fn dim() -> Style {
    Style::new().dim()
}

fn tone(text: &str) -> Option<Style> {
    match text {
        "created" | "registered" | "replaced" | "transferred" | "paused" | "resumed" => {
            Some(Style::new().color256(SAGE))
        }
        "already present" => Some(dim()),
        "refused" => Some(Style::new().color256(RED)),
        _ => None,
    }
}

/// Prompts render on stderr, every style marked for it.
fn prompt_theme() -> ColorfulTheme {
    let (done, plain) = (Style::new().color256(SAGE), Style::new());
    let mark = |text: &str, style: &Style| style.clone().for_stderr().apply_to(text.to_owned());
    ColorfulTheme {
        defaults_style: dim().italic().for_stderr(),
        prompt_style: Style::new().bold().for_stderr(),
        prompt_prefix: mark("?", &Style::new().color256(AMBER)),
        prompt_suffix: mark("›", &dim()),
        success_prefix: mark("·", &done),
        success_suffix: mark("·", &dim()),
        error_prefix: mark("!", &Style::new().color256(RED)),
        error_style: Style::new().color256(RED).for_stderr(),
        hint_style: dim().italic().for_stderr(),
        values_style: done.clone().for_stderr(),
        active_item_style: done.clone().for_stderr(),
        inactive_item_style: plain.clone().for_stderr(),
        active_item_prefix: mark("›", &done),
        inactive_item_prefix: mark(" ", &plain),
        checked_item_prefix: mark("[x]", &done),
        unchecked_item_prefix: mark("[ ]", &dim()),
        picked_item_prefix: mark("›", &done),
        unpicked_item_prefix: mark(" ", &plain),
    }
}

fn unread(prompt: &str) -> String {
    format!("cannot read the answer to {prompt}")
}

impl Ask for Terminal {
    fn interactive(&self) -> bool {
        true
    }

    fn text(
        &mut self,
        prompt: &str,
        default: Option<String>,
        empty: bool,
        check: Check<'_>,
    ) -> Result<String> {
        let theme = prompt_theme();
        let mut input = dialoguer::Input::<String>::with_theme(&theme)
            .with_prompt(prompt)
            .allow_empty(empty)
            .validate_with(|answer: &String| check(answer));
        if let Some(default) = default {
            input = input.default(default);
        }
        input.interact_text().with_context(|| unread(prompt))
    }

    fn pick(&mut self, prompt: &str, items: &[String], default: usize) -> Result<usize> {
        dialoguer::Select::with_theme(&prompt_theme())
            .with_prompt(prompt)
            .items(items)
            .default(default)
            .interact()
            .with_context(|| unread(prompt))
    }

    fn pick_many(&mut self, prompt: &str, items: &[String]) -> Result<Vec<usize>> {
        dialoguer::MultiSelect::with_theme(&prompt_theme())
            .with_prompt(prompt)
            .items(items)
            .interact()
            .with_context(|| unread(prompt))
    }

    fn confirm(&mut self, prompt: &str, default: bool) -> Result<bool> {
        dialoguer::Confirm::with_theme(&prompt_theme())
            .with_prompt(prompt)
            .default(default)
            .interact()
            .with_context(|| unread(prompt))
    }
}

impl Ask for Defaults {
    fn interactive(&self) -> bool {
        false
    }

    fn text(
        &mut self,
        prompt: &str,
        default: Option<String>,
        empty: bool,
        check: Check<'_>,
    ) -> Result<String> {
        let answer = default.unwrap_or_default();
        if answer.is_empty() && !empty {
            bail!("no default answers {prompt}");
        }
        if let Err(reason) = check(&answer) {
            bail!("the answer to {prompt} is refused, {reason}");
        }
        Ok(answer)
    }

    fn pick(&mut self, _prompt: &str, _items: &[String], default: usize) -> Result<usize> {
        Ok(default)
    }

    fn pick_many(&mut self, _prompt: &str, _items: &[String]) -> Result<Vec<usize>> {
        Ok(Vec::new())
    }

    fn confirm(&mut self, _prompt: &str, default: bool) -> Result<bool> {
        Ok(default)
    }
}

#[cfg(test)]
pub use scripted::{Answer, Scripted};

#[cfg(test)]
mod scripted {
    use std::collections::VecDeque;

    use anyhow::{bail, Context as _, Result};

    use super::{Ask, Check};

    /// Answers in question order, a text answers `pick` by its item label.
    pub struct Scripted {
        answers: VecDeque<Answer>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Answer {
        Text(String),
        Many(Vec<String>),
        Yes(bool),
    }

    impl Scripted {
        pub fn new(answers: impl IntoIterator<Item = Answer>) -> Self {
            Self {
                answers: answers.into_iter().collect(),
            }
        }

        pub fn is_drained(&self) -> bool {
            self.answers.is_empty()
        }

        fn next(&mut self, prompt: &str) -> Result<Answer> {
            self.answers
                .pop_front()
                .with_context(|| format!("no scripted answer for {prompt}"))
        }

        fn text_answer(&mut self, prompt: &str) -> Result<String> {
            match self.next(prompt)? {
                Answer::Text(answer) => Ok(answer),
                _ => bail!("the scripted answer to {prompt} has the wrong kind"),
            }
        }
    }

    fn index_of(items: &[String], label: &str, prompt: &str) -> Result<usize> {
        items
            .iter()
            .position(|item| item == label)
            .with_context(|| format!("the answer to {prompt} is refused, {label} is not an item"))
    }

    impl Ask for Scripted {
        fn interactive(&self) -> bool {
            true
        }

        fn text(
            &mut self,
            prompt: &str,
            default: Option<String>,
            empty: bool,
            check: Check<'_>,
        ) -> Result<String> {
            let answer = self.text_answer(prompt)?;
            let answer = match default {
                Some(default) if answer.is_empty() => default,
                _ => answer,
            };
            if answer.is_empty() && !empty {
                bail!("the answer to {prompt} is refused, an answer is needed");
            }
            if let Err(reason) = check(&answer) {
                bail!("the answer to {prompt} is refused, {reason}");
            }
            Ok(answer)
        }

        fn pick(&mut self, prompt: &str, items: &[String], _default: usize) -> Result<usize> {
            let label = self.text_answer(prompt)?;
            index_of(items, &label, prompt)
        }

        fn pick_many(&mut self, prompt: &str, items: &[String]) -> Result<Vec<usize>> {
            let Answer::Many(labels) = self.next(prompt)? else {
                bail!("the scripted answer to {prompt} has the wrong kind");
            };
            labels
                .iter()
                .map(|label| index_of(items, label, prompt))
                .collect()
        }

        fn confirm(&mut self, prompt: &str, _default: bool) -> Result<bool> {
            match self.next(prompt)? {
                Answer::Yes(answer) => Ok(answer),
                _ => bail!("the scripted answer to {prompt} has the wrong kind"),
            }
        }
    }

    impl From<&str> for Answer {
        fn from(text: &str) -> Self {
            Self::Text(text.to_owned())
        }
    }

    impl From<bool> for Answer {
        fn from(yes: bool) -> Self {
            Self::Yes(yes)
        }
    }

    impl<const N: usize> From<[&str; N]> for Answer {
        fn from(labels: [&str; N]) -> Self {
            Self::Many(labels.iter().map(|label| (*label).to_owned()).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items() -> Vec<String> {
        ["allow", "block"].map(str::to_owned).to_vec()
    }

    #[test]
    fn a_script_answers_in_order_and_refuses_past_its_end() {
        let mut ask = Scripted::new([
            Answer::from("x"),
            Answer::from("block"),
            Answer::from(["allow"]),
            Answer::from(true),
        ]);
        assert_eq!(ask.text("t", None, false, &accept).expect("text"), "x");
        let items = items();
        assert_eq!(ask.pick("p", &items, 0).expect("pick"), 1);
        assert_eq!(ask.pick_many("m", &items).expect("many"), vec![0]);
        assert!(ask.confirm("c", false).expect("confirm"));
        assert!(ask.is_drained());
        let error = ask.confirm("c", false).expect_err("drained");
        assert_eq!(error.to_string(), "no scripted answer for c");
    }

    #[test]
    fn a_script_is_checked_like_a_typed_answer() {
        let mut ask = Scripted::new(["", "nine", "frozen"].map(Answer::from));
        let numeric = |answer: &str| {
            answer
                .parse::<u64>()
                .map(|_| ())
                .map_err(|_| "not a number".to_owned())
        };
        let with_default = ask
            .text("n", Some("7".to_owned()), false, &numeric)
            .expect("default fills an empty answer");
        assert_eq!(with_default, "7");
        let refused = ask.text("n", None, false, &numeric).expect_err("refused");
        assert!(refused.to_string().ends_with("not a number"), "{refused}");
        let items = items();
        assert!(ask.pick("p", &items, 0).is_err());
    }

    #[test]
    fn defaults_answer_without_a_terminal() {
        let mut ask = Defaults;
        assert!(!ask.interactive());
        let items = items();
        assert_eq!(ask.pick("p", &items, 1).expect("default index"), 1);
        assert!(ask.pick_many("m", &items).expect("nothing").is_empty());
        assert!(!ask.confirm("c", false).expect("default"));
        assert!(ask.text("t", None, false, &accept).is_err());
    }

    #[test]
    fn only_the_outcome_words_take_a_tone() {
        let done = Some(Style::new().color256(SAGE));
        assert_eq!(tone("created"), done);
        assert_eq!(tone("replaced"), done);
        assert_eq!(tone("transferred"), done);
        assert_eq!(tone("already present"), Some(dim()));
        assert_eq!(tone("refused"), Some(Style::new().color256(RED)));
        assert_eq!(tone("already paused"), None);
        assert_eq!(tone("deployed"), None);
    }
}
