//! The look of every printed line and the dialogue behind every question.

use std::{collections::VecDeque, fmt::Display, io::IsTerminal, sync::LazyLock};

use console::Style;
use dialoguer::theme::ColorfulTheme;
use thiserror::Error;

const SAGE: u8 = 108;
const AMBER: u8 = 179;
const RED: u8 = 167;

pub struct Theme {
    pub label: Style,
    pub value: Style,
    pub done: Style,
    pub skipped: Style,
    pub waiting: Style,
    pub refused: Style,
    pub heading: Style,
    pub hint: Style,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Done,
    Skipped,
    Waiting,
    Refused,
}

/// One glyph per section heading or final line, never per row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Ring,
    Policy,
    Lists,
    Curator,
    Tree,
    Pin,
    Auditor,
    Pause,
    Resume,
    Wizard,
}

#[derive(Debug, Error)]
pub enum AskError {
    #[error("cannot read the answer to {prompt}")]
    Terminal {
        prompt: String,
        #[source]
        source: dialoguer::Error,
    },
    #[error("no scripted answer for {prompt}")]
    NoAnswer { prompt: String },
    #[error("the scripted answer to {prompt} has the wrong kind")]
    WrongKind { prompt: String },
    #[error("the answer to {prompt} is refused, {reason}")]
    Refused { prompt: String, reason: String },
}

/// The `check` reason is shown to the operator.
pub struct Text<'a> {
    pub prompt: &'a str,
    pub default: Option<String>,
    pub empty: bool,
    pub check: &'a dyn Fn(&str) -> Result<(), String>,
}

pub struct Pick<'a> {
    pub prompt: &'a str,
    pub items: &'a [String],
    pub default: usize,
}

pub struct PickMany<'a> {
    pub prompt: &'a str,
    pub items: &'a [String],
}

/// Every question a command asks goes through one of these.
pub trait Ask {
    fn interactive(&self) -> bool;
    fn text(&mut self, text: Text<'_>) -> Result<String, AskError>;
    fn pick(&mut self, pick: Pick<'_>) -> Result<usize, AskError>;
    fn pick_many(&mut self, pick: PickMany<'_>) -> Result<Vec<usize>, AskError>;
    fn confirm(&mut self, prompt: &str, default: bool) -> Result<bool, AskError>;
}

pub struct Terminal;

/// Every question takes its default, a choice picks nothing.
pub struct Defaults;

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

static THEME: LazyLock<Theme> = LazyLock::new(Theme::new);

const OUTCOMES: [(&str, Tone); 8] = [
    ("created", Tone::Done),
    ("registered", Tone::Done),
    ("replaced", Tone::Done),
    ("transferred", Tone::Done),
    ("already present", Tone::Skipped),
    ("paused", Tone::Done),
    ("resumed", Tone::Done),
    ("refused", Tone::Refused),
];

pub fn theme() -> &'static Theme {
    &THEME
}

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
    let theme = theme();
    let text = value.to_string();
    let styled = match outcome_tone(&text) {
        Some(tone) => theme.tone(tone).apply_to(text),
        None => theme.value.apply_to(text),
    };
    println!("{}{styled}", theme.label.apply_to(format!("{label:<12}")));
}

pub fn heading(icon: Icon, text: &str) {
    println!("{} {}", icon.glyph(), theme().heading.apply_to(text));
}

pub fn hint(text: impl Display) {
    println!("{}", theme().hint.apply_to(text));
}

pub fn warn(text: impl Display) {
    println!("{}", theme().waiting.apply_to(text));
}

pub fn refusal(text: impl Display) {
    println!("{}", theme().refused.apply_to(text));
}

fn outcome_tone(text: &str) -> Option<Tone> {
    OUTCOMES
        .iter()
        .find(|(word, _)| *word == text)
        .map(|(_, tone)| *tone)
}

impl Theme {
    fn new() -> Self {
        Self {
            label: Style::new().dim(),
            value: Style::new(),
            done: Style::new().color256(SAGE),
            skipped: Style::new().dim(),
            waiting: Style::new().color256(AMBER),
            refused: Style::new().color256(RED),
            heading: Style::new().bold(),
            hint: Style::new().dim().italic(),
        }
    }

    pub fn tone(&self, tone: Tone) -> &Style {
        match tone {
            Tone::Done => &self.done,
            Tone::Skipped => &self.skipped,
            Tone::Waiting => &self.waiting,
            Tone::Refused => &self.refused,
        }
    }

    /// Prompts render on stderr, every style marked for it.
    pub fn dialoguer(&self) -> ColorfulTheme {
        let stderr = |style: &Style| style.clone().for_stderr();
        let mark = |text: &str, style: &Style| stderr(style).apply_to(text.to_owned());
        ColorfulTheme {
            defaults_style: stderr(&self.hint),
            prompt_style: stderr(&self.heading),
            prompt_prefix: mark("?", &self.waiting),
            prompt_suffix: mark("›", &self.label),
            success_prefix: mark("·", &self.done),
            success_suffix: mark("·", &self.label),
            error_prefix: mark("!", &self.refused),
            error_style: stderr(&self.refused),
            hint_style: stderr(&self.hint),
            values_style: stderr(&self.done),
            active_item_style: stderr(&self.done),
            inactive_item_style: stderr(&self.value),
            active_item_prefix: mark("›", &self.done),
            inactive_item_prefix: mark(" ", &self.value),
            checked_item_prefix: mark("[x]", &self.done),
            unchecked_item_prefix: mark("[ ]", &self.label),
            picked_item_prefix: mark("›", &self.done),
            unpicked_item_prefix: mark(" ", &self.value),
        }
    }
}

impl Icon {
    pub const fn glyph(self) -> &'static str {
        match self {
            Self::Ring => "💍",
            Self::Policy => "📜",
            Self::Lists => "🗂",
            Self::Curator => "🤝",
            Self::Tree => "🌳",
            Self::Pin => "🔏",
            Self::Auditor => "🧾",
            Self::Pause => "⏸",
            Self::Resume => "▶",
            Self::Wizard => "🧭",
        }
    }
}

impl Ask for Terminal {
    fn interactive(&self) -> bool {
        true
    }

    fn text(&mut self, text: Text<'_>) -> Result<String, AskError> {
        let theme = theme().dialoguer();
        let mut input = dialoguer::Input::<String>::with_theme(&theme)
            .with_prompt(text.prompt)
            .allow_empty(text.empty)
            .validate_with(|answer: &String| (text.check)(answer));
        if let Some(default) = text.default {
            input = input.default(default);
        }
        input.interact_text().map_err(|source| AskError::Terminal {
            prompt: text.prompt.to_owned(),
            source,
        })
    }

    fn pick(&mut self, pick: Pick<'_>) -> Result<usize, AskError> {
        let theme = theme().dialoguer();
        dialoguer::Select::with_theme(&theme)
            .with_prompt(pick.prompt)
            .items(pick.items)
            .default(pick.default)
            .interact()
            .map_err(|source| AskError::Terminal {
                prompt: pick.prompt.to_owned(),
                source,
            })
    }

    fn pick_many(&mut self, pick: PickMany<'_>) -> Result<Vec<usize>, AskError> {
        let theme = theme().dialoguer();
        dialoguer::MultiSelect::with_theme(&theme)
            .with_prompt(pick.prompt)
            .items(pick.items)
            .interact()
            .map_err(|source| AskError::Terminal {
                prompt: pick.prompt.to_owned(),
                source,
            })
    }

    fn confirm(&mut self, prompt: &str, default: bool) -> Result<bool, AskError> {
        let theme = theme().dialoguer();
        dialoguer::Confirm::with_theme(&theme)
            .with_prompt(prompt)
            .default(default)
            .interact()
            .map_err(|source| AskError::Terminal {
                prompt: prompt.to_owned(),
                source,
            })
    }
}

impl Ask for Defaults {
    fn interactive(&self) -> bool {
        false
    }

    fn text(&mut self, text: Text<'_>) -> Result<String, AskError> {
        let answer = text.default.unwrap_or_default();
        if answer.is_empty() && !text.empty {
            return Err(AskError::NoAnswer {
                prompt: text.prompt.to_owned(),
            });
        }
        (text.check)(&answer).map_err(|reason| AskError::Refused {
            prompt: text.prompt.to_owned(),
            reason,
        })?;
        Ok(answer)
    }

    fn pick(&mut self, pick: Pick<'_>) -> Result<usize, AskError> {
        Ok(pick.default)
    }

    fn pick_many(&mut self, _pick: PickMany<'_>) -> Result<Vec<usize>, AskError> {
        Ok(Vec::new())
    }

    fn confirm(&mut self, _prompt: &str, default: bool) -> Result<bool, AskError> {
        Ok(default)
    }
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

    fn next(&mut self, prompt: &str) -> Result<Answer, AskError> {
        self.answers.pop_front().ok_or_else(|| AskError::NoAnswer {
            prompt: prompt.to_owned(),
        })
    }
}

fn wrong_kind(prompt: &str) -> AskError {
    AskError::WrongKind {
        prompt: prompt.to_owned(),
    }
}

fn index_of(items: &[String], label: &str, prompt: &str) -> Result<usize, AskError> {
    items
        .iter()
        .position(|item| item == label)
        .ok_or_else(|| AskError::Refused {
            prompt: prompt.to_owned(),
            reason: format!("{label} is not an item"),
        })
}

impl Ask for Scripted {
    fn interactive(&self) -> bool {
        true
    }

    fn text(&mut self, text: Text<'_>) -> Result<String, AskError> {
        let Answer::Text(answer) = self.next(text.prompt)? else {
            return Err(wrong_kind(text.prompt));
        };
        let answer = if answer.is_empty() {
            text.default.unwrap_or(answer)
        } else {
            answer
        };
        if answer.is_empty() && !text.empty {
            return Err(AskError::Refused {
                prompt: text.prompt.to_owned(),
                reason: "an answer is needed".to_owned(),
            });
        }
        (text.check)(&answer).map_err(|reason| AskError::Refused {
            prompt: text.prompt.to_owned(),
            reason,
        })?;
        Ok(answer)
    }

    fn pick(&mut self, pick: Pick<'_>) -> Result<usize, AskError> {
        let Answer::Text(label) = self.next(pick.prompt)? else {
            return Err(wrong_kind(pick.prompt));
        };
        index_of(pick.items, &label, pick.prompt)
    }

    fn pick_many(&mut self, pick: PickMany<'_>) -> Result<Vec<usize>, AskError> {
        let Answer::Many(labels) = self.next(pick.prompt)? else {
            return Err(wrong_kind(pick.prompt));
        };
        labels
            .iter()
            .map(|label| index_of(pick.items, label, pick.prompt))
            .collect()
    }

    fn confirm(&mut self, prompt: &str, _default: bool) -> Result<bool, AskError> {
        match self.next(prompt)? {
            Answer::Yes(answer) => Ok(answer),
            _ => Err(wrong_kind(prompt)),
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
        let text = ask
            .text(Text {
                prompt: "t",
                default: None,
                empty: false,
                check: &accept,
            })
            .expect("text");
        assert_eq!(text, "x");
        let items = items();
        assert_eq!(
            ask.pick(Pick {
                prompt: "p",
                items: &items,
                default: 0
            })
            .expect("pick"),
            1
        );
        assert_eq!(
            ask.pick_many(PickMany {
                prompt: "m",
                items: &items
            })
            .expect("many"),
            vec![0]
        );
        assert!(ask.confirm("c", false).expect("confirm"));
        assert!(ask.is_drained());
        assert!(matches!(
            ask.confirm("c", false),
            Err(AskError::NoAnswer { prompt }) if prompt == "c"
        ));
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
            .text(Text {
                prompt: "n",
                default: Some("7".to_owned()),
                empty: false,
                check: &numeric,
            })
            .expect("default fills an empty answer");
        assert_eq!(with_default, "7");
        assert!(matches!(
            ask.text(Text {
                prompt: "n",
                default: None,
                empty: false,
                check: &numeric,
            }),
            Err(AskError::Refused { reason, .. }) if reason == "not a number"
        ));
        let items = items();
        assert!(matches!(
            ask.pick(Pick {
                prompt: "p",
                items: &items,
                default: 0
            }),
            Err(AskError::Refused { .. })
        ));
    }

    #[test]
    fn defaults_answer_without_a_terminal() {
        let mut ask = Defaults;
        assert!(!ask.interactive());
        let items = items();
        assert_eq!(
            ask.pick(Pick {
                prompt: "p",
                items: &items,
                default: 1
            })
            .expect("default index"),
            1
        );
        assert!(ask
            .pick_many(PickMany {
                prompt: "m",
                items: &items
            })
            .expect("nothing picked")
            .is_empty());
        assert!(!ask.confirm("c", false).expect("default"));
        assert!(matches!(
            ask.text(Text {
                prompt: "t",
                default: None,
                empty: false,
                check: &accept,
            }),
            Err(AskError::NoAnswer { .. })
        ));
    }

    #[test]
    fn only_the_outcome_words_take_a_tone() {
        assert_eq!(outcome_tone("created"), Some(Tone::Done));
        assert_eq!(outcome_tone("replaced"), Some(Tone::Done));
        assert_eq!(outcome_tone("transferred"), Some(Tone::Done));
        assert_eq!(outcome_tone("already present"), Some(Tone::Skipped));
        assert_eq!(outcome_tone("refused"), Some(Tone::Refused));
        assert_eq!(outcome_tone("already paused"), None);
        assert_eq!(outcome_tone("deployed"), None);
    }
}
