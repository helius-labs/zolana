/// Serde through `Display` and `FromStr`, the spelling `ring.toml` and the command line share.
macro_rules! serde_via_str {
    ($($name:ty),+ $(,)?) => {$(
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                <String as serde::Deserialize>::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    )+};
}

/// A fieldless enum spelled by name, `ALL` in declaration order.
macro_rules! named_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident($kind:literal) {
        $($(#[$doc:meta])* $variant:ident = $text:literal),+ $(,)?
    }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis enum $name {
            $($(#[$doc])* $variant),+
        }

        impl $name {
            pub const ALL: [Self; [$($text),+].len()] = [$(Self::$variant),+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::macros::UnknownName;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::ALL
                    .into_iter()
                    .find(|named| named.as_str() == text)
                    .ok_or_else(|| $crate::macros::UnknownName {
                        kind: $kind,
                        name: text.to_owned(),
                    })
            }
        }

        impl clap::ValueEnum for $name {
            fn value_variants<'a>() -> &'a [Self] {
                &Self::ALL
            }

            fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
                Some(clap::builder::PossibleValue::new(self.as_str()))
            }
        }

        $crate::macros::serde_via_str!($name);
    };
}

pub(crate) use {named_enum, serde_via_str};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown {kind} {name}")]
pub struct UnknownName {
    pub kind: &'static str,
    pub name: String,
}
