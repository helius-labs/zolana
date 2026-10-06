use std::fmt;

use serde::{Deserialize, Serialize};

use super::{
    dstack::{self, DstackIdentity, DstackPolicy},
    nitro::{self, NitroIdentity, NitroPolicy},
    verify::{Claims, Measured, Trust},
    TeeError,
};

/// Sealed by its private module.
pub trait TeePlatform {
    const HOSTS_GPU: bool;
    const ROTATES_KEY_PER_BOOT: bool;
    const ANCHORS: Self::Anchors;
    type Evidence;
    type Policy;
    type Identity;
    type Anchors;

    fn inspect(
        evidence: Self::Evidence,
        anchors: &Self::Anchors,
        now_secs: u64,
    ) -> Result<Measured<Self::Identity>, TeeError>;

    fn check(
        identity: &Self::Identity,
        pins: &Self::Policy,
        claims: &Claims<'_>,
    ) -> Result<(), TeeError>;

    fn image_id(identity: &Self::Identity) -> Vec<u8>;

    fn tcb_status(_identity: &Self::Identity) -> Option<String> {
        None
    }
}

macro_rules! platforms {
    ($(
        $module:ident::$platform:ident as $variant:ident = $tag:literal {
            policy: $policy:ty,
            identity: $identity:ty $(,)?
        }
    ),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Platform {
            $($variant),+
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(tag = "platform")]
        #[non_exhaustive]
        pub enum PlatformPolicy {
            $(#[serde(rename = $tag)] $variant($policy)),+
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum PlatformIdentity {
            $($variant($identity)),+
        }

        #[derive(Clone, Debug, Deserialize)]
        #[serde(tag = "platform", content = "evidence")]
        pub(super) enum Evidence {
            $(#[serde(rename = $tag)] $variant(<$module::$platform as TeePlatform>::Evidence)),+
        }

        pub(super) struct Anchors {
            $(pub $module: <$module::$platform as TeePlatform>::Anchors),+
        }

        impl Anchors {
            pub(super) const PRODUCTION: Self = Self {
                $($module: <$module::$platform as TeePlatform>::ANCHORS),+
            };
        }

        impl Platform {
            /// The wire `platform` tag.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $tag),+
                }
            }

            pub const fn hosts_gpu(self) -> bool {
                match self {
                    $(Self::$variant => <$module::$platform as TeePlatform>::HOSTS_GPU),+
                }
            }

            /// A prover answering `tee_decryption_failed` is worth attesting again.
            pub const fn rotates_key_per_boot(self) -> bool {
                match self {
                    $(Self::$variant => <$module::$platform as TeePlatform>::ROTATES_KEY_PER_BOOT),+
                }
            }
        }

        impl PlatformPolicy {
            pub fn platform(&self) -> Platform {
                match self {
                    $(Self::$variant(_) => Platform::$variant),+
                }
            }
        }

        impl PlatformIdentity {
            pub fn platform(&self) -> Platform {
                match self {
                    $(Self::$variant(_) => Platform::$variant),+
                }
            }

            pub(super) fn check(
                &self,
                pins: &PlatformPolicy,
                claims: &Claims<'_>,
            ) -> Result<(), TeeError> {
                match (self, pins) {
                    $((Self::$variant(found), PlatformPolicy::$variant(pins)) => {
                        <$module::$platform as TeePlatform>::check(found, pins, claims)
                    })+
                    (found, pins) => Err(mismatch(pins.platform(), found.platform())),
                }
            }

            pub(super) fn image_id(&self) -> Vec<u8> {
                match self {
                    $(Self::$variant(found) => <$module::$platform as TeePlatform>::image_id(found)),+
                }
            }

            pub(super) fn tcb_status(&self) -> Option<String> {
                match self {
                    $(Self::$variant(found) => <$module::$platform as TeePlatform>::tcb_status(found)),+
                }
            }
        }

        impl Evidence {
            pub(super) fn platform(&self) -> Platform {
                match self {
                    $(Self::$variant(_) => Platform::$variant),+
                }
            }

            pub(super) fn inspect(
                self,
                trust: Trust<'_>,
            ) -> Result<Measured<PlatformIdentity>, TeeError> {
                Ok(match self {
                    $(Self::$variant(evidence) => <$module::$platform as TeePlatform>::inspect(
                        evidence,
                        &trust.anchors.$module,
                        trust.now_secs,
                    )?
                    .map(PlatformIdentity::$variant)),+
                })
            }
        }
    };
}

// Restates each platform's public associated types for rustdoc.
platforms! {
    dstack::Dstack as DstackTdx = "dstack-tdx" {
        policy: DstackPolicy,
        identity: DstackIdentity,
    },
    nitro::Nitro as AwsNitro = "aws-nitro" {
        policy: NitroPolicy,
        identity: NitroIdentity,
    },
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub(super) fn mismatch(expected: Platform, got: Platform) -> TeeError {
    TeeError::PlatformMismatch {
        expected: expected.as_str().into(),
        got: got.as_str().into(),
    }
}
