//! A typed GitHub credential: one config shape for every way a pleme-io
//! process can come to hold a GitHub token, and one resolver behind it.
//!
//! Feature-gated behind `github`.
//!
//! # Why this exists
//!
//! Before this module the fleet had the same idea five times, each a partial
//! copy: `fleet`'s `TokenSource` (env → nix.conf → sops scrape, with a
//! [`GithubToken`]-shaped `ResolvedToken` that refuses a bare accessor),
//! pangea-operator's `GitHubAppCredentialsConfig` (App credentials so the
//! consumer mints its own tokens instead of carrying one that dies), engenho's
//! inline-vs-file `TokenSource`, the nix `github-runners` module's `app | pat`
//! union, and the `github-app-installation-token` action's JWT minting. None
//! of them could express the others' sources, so every new consumer picked
//! the subset its author needed that week. [`GithubAuth`] is the union, and
//! [`GithubAuth::Chain`] is the composition all five were hand-rolling.
//!
//! # Config shape
//!
//! Externally tagged, `snake_case`, and every token source is a
//! [`SecretSource`], so anything the secret module can read is a PAT source:
//!
//! ```yaml
//! github_auth:
//!   chain:
//!     - token: { env: TEND_GITHUB_TOKEN }
//!     - gh_cli: { host: github.com }
//!     - token: { file: ~/.config/github/token }
//!     - app: { app_id: 123, owner: pleme-io, private_key: { file: /run/secrets/app.pem } }
//! ```
//!
//! [`GithubAuth::default_chain`] is the fleet default — the env vars a tool
//! names for itself, then the two the GitHub ecosystem standardised on, then
//! the operator's `gh` login, then a token file.
//!
//! # What a resolved token will and will not do
//!
//! [`GithubToken`] has no `Display` or `Debug` that prints the secret and no
//! `String`-returning accessor named after the secret. Every sink gets a
//! renderer that produces the exact shape that sink expects —
//! [`GithubToken::authorization_header`], [`GithubToken::git_extraheader`],
//! [`GithubToken::git_config_env`], [`GithubToken::nix_access_tokens_line`],
//! [`GithubToken::env_pairs`] — so `tracing::info!("{token}")` logs a
//! fingerprint and a source, never the credential.
//!
//! Each token carries [`GithubTokenProvenance`]: which chain element produced
//! it and what that element was. When a request later 401s or 404s, the
//! operator reads which of N sources was actually used instead of guessing.
//!
//! # GitHub Apps
//!
//! [`GithubApp`] holds a capability, not a credential with a date on it: the
//! resolver signs an RS256 JWT (`iss` = app id, `iat` backdated 60 s for clock
//! skew, `exp` 9 min out — GitHub's ceiling is 10), finds the installation
//! (given, or looked up by `owner` through `GET /app/installations`), and
//! exchanges the JWT at `POST /app/installations/{id}/access_tokens`. The
//! one-hour installation token is cached in the [`GithubAuthResolver`] and
//! re-minted once it is within `refresh_before_secs` of expiry, so a
//! long-running process calls [`GithubAuth::resolve`] before each use and
//! never holds a dead token — the failure pangea-operator measured
//! (2026-08-23) with a token injected once as a pod env var.
//!
//! # Blocking
//!
//! Resolution is blocking (`std::process` for `gh`, `reqwest::blocking` for
//! the App endpoints). From async code, call it inside
//! `tokio::task::spawn_blocking`; `reqwest::blocking` panics when driven from
//! inside a runtime's worker thread.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::{self, Write as _};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::ShikumiError;
use crate::secret::{self, SecretBackend, SecretBackendKind, SecretSource};

/// The public GitHub host, used by [`GithubAuth::GhCli`] when no host is set.
pub const DEFAULT_GITHUB_HOST: &str = "github.com";

/// The public GitHub REST API root, used by [`GithubApp::api_url`] by default.
pub const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com";

/// Default for [`GithubApp::refresh_before_secs`]: re-mint an installation
/// token once it has five minutes or less left.
pub const DEFAULT_REFRESH_BEFORE_SECS: u64 = 300;

/// Seconds the App JWT's `iat` is backdated, absorbing clock skew between
/// this host and GitHub (GitHub's own recommendation).
pub const APP_JWT_BACKDATE_SECS: u64 = 60;

/// Seconds from now the App JWT expires. GitHub rejects a JWT whose `exp` is
/// more than 10 minutes out; 9 leaves a minute of skew margin.
pub const APP_JWT_LIFETIME_SECS: u64 = 9 * 60;

const USER_AGENT: &str = concat!("shikumi/", env!("CARGO_PKG_VERSION"));

// ─────────────────────────────────────────────────────────────────────
// Config surface
// ─────────────────────────────────────────────────────────────────────

/// Where a GitHub token comes from.
///
/// Externally tagged in `snake_case`: `token`, `gh_cli`, `app` or `chain`.
///
/// `Serialize` and `Deserialize` are hand-written (below) rather than
/// derived, for one measured reason: `serde_yaml` 0.9 reads a *derived*
/// externally tagged enum only from a YAML tag (`!token …`), rejecting the
/// single-key map (`token: …`) every config in the fleet is written as, and
/// refuses to emit one nested in another enum (`chain:` of `token:`). The
/// impls read both forms and write the map form, which for `serde_json` and
/// figment is byte-identical to the derive — so the derived `JsonSchema`
/// (driven by the `serde` attributes here) still describes the format.
#[derive(Debug, Clone, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GithubAuth {
    /// A personal access, OAuth or fine-grained token read from any secret
    /// backend: `{ env: GITHUB_TOKEN }`, `{ file: ~/.config/github/token }`,
    /// `{ sops: … }`, `{ op: … }`, and the rest.
    Token(SecretSource),
    /// The token the GitHub CLI holds for a host, read with
    /// `gh auth token --hostname <host>`.
    GhCli {
        /// GitHub host the `gh` login belongs to.
        #[serde(default = "default_github_host")]
        host: String,
    },
    /// A GitHub App installation token, minted from the App's private key,
    /// cached, and re-minted shortly before it expires.
    App(GithubApp),
    /// Try each source in order; the first that yields a non-empty token wins.
    /// When none does, the error lists every source and why it failed.
    Chain(Vec<GithubAuth>),
}

const GITHUB_AUTH_VARIANTS: &[&str] = &["token", "gh_cli", "app", "chain"];

/// The body of `gh_cli:` — `{ host }`, `{}`, or nothing at all.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct GhCliBody {
    #[serde(default = "default_github_host")]
    host: String,
}

impl GithubAuth {
    fn from_tagged<'de, A>(tag: &str, value: A) -> Result<Self, A::Error>
    where
        A: TaggedValue<'de>,
    {
        Ok(match tag {
            "token" => Self::Token(value.take()?),
            "gh_cli" => {
                let body: Option<GhCliBody> = value.take()?;
                Self::GhCli {
                    host: body.map_or_else(default_github_host, |b| b.host),
                }
            }
            "app" => Self::App(value.take()?),
            "chain" => Self::Chain(value.take()?),
            other => {
                return Err(serde::de::Error::unknown_variant(
                    other,
                    GITHUB_AUTH_VARIANTS,
                ));
            }
        })
    }
}

/// The value half of a `tag: value` pair, from either a map entry or a
/// YAML-tagged enum — so [`GithubAuth::from_tagged`] is written once.
trait TaggedValue<'de> {
    type Error: serde::de::Error;
    fn take<T: Deserialize<'de>>(self) -> Result<T, Self::Error>;
}

struct MapValue<'a, A>(&'a mut A);

impl<'de, A: serde::de::MapAccess<'de>> TaggedValue<'de> for MapValue<'_, A> {
    type Error = A::Error;
    fn take<T: Deserialize<'de>>(self) -> Result<T, A::Error> {
        self.0.next_value()
    }
}

struct EnumValue<V>(V);

impl<'de, V: serde::de::VariantAccess<'de>> TaggedValue<'de> for EnumValue<V> {
    type Error = V::Error;
    fn take<T: Deserialize<'de>>(self) -> Result<T, V::Error> {
        self.0.newtype_variant()
    }
}

impl Serialize for GithubAuth {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        #[derive(Serialize)]
        struct GhCliRef<'a> {
            host: &'a str,
        }
        let mut map = serializer.serialize_map(Some(1))?;
        let tag = self.kind().as_str();
        match self {
            Self::Token(source) => map.serialize_entry(tag, source)?,
            Self::GhCli { host } => map.serialize_entry(tag, &GhCliRef { host })?,
            Self::App(app) => map.serialize_entry(tag, app)?,
            Self::Chain(items) => map.serialize_entry(tag, items)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for GithubAuth {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = GithubAuth;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a GitHub auth source: a map with exactly one of the keys token, gh_cli, app, chain")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<GithubAuth, A::Error> {
                let Some(tag) = map.next_key::<String>()? else {
                    return Err(serde::de::Error::invalid_length(0, &self));
                };
                let auth = GithubAuth::from_tagged(&tag, MapValue(&mut map))?;
                if let Some(extra) = map.next_key::<String>()? {
                    return Err(serde::de::Error::custom(format!(
                        "a GitHub auth source has exactly one key; found `{tag}` and `{extra}` \
                         (use `chain:` to list several sources)"
                    )));
                }
                Ok(auth)
            }

            fn visit_enum<A: serde::de::EnumAccess<'de>>(
                self,
                data: A,
            ) -> Result<GithubAuth, A::Error> {
                let (tag, variant) = data.variant::<String>()?;
                GithubAuth::from_tagged(&tag, EnumValue(variant))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// A GitHub App's credentials — enough to mint installation tokens on demand.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GithubApp {
    /// The App's numeric id: a number, or a secret source holding one.
    pub app_id: GithubId,
    /// The App's PEM-encoded RSA private key (PKCS#1 or PKCS#8).
    pub private_key: SecretSource,
    /// The installation to mint tokens for. When absent, the installation is
    /// found through `GET /app/installations` by `owner`, or is the App's only
    /// installation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<GithubId>,
    /// Account (organization or user) login whose installation to use when
    /// `installation_id` is absent. Matched case-insensitively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// GitHub REST API root; set for GitHub Enterprise Server.
    #[serde(default = "default_github_api_url")]
    pub api_url: String,
    /// Re-mint the installation token once it has this many seconds or fewer
    /// left before it expires.
    #[serde(default = "default_refresh_before_secs")]
    pub refresh_before_secs: u64,
}

/// A numeric GitHub id (App id, installation id), given inline or read from a
/// secret source.
///
/// Why not a bare `u64`: the fleet already stores these next to the key they
/// belong to — the nix `github-runners` module takes `appIdSecret` and
/// `installationIdSecret` as sops secrets — so a `u64`-only field would force
/// every such consumer to template the number into config by hand. An id is
/// not secret, so the inline number stays the first, plainest form; the
/// source form only means "read it from where it already lives".
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum GithubId {
    /// The id itself, e.g. `123456`.
    Number(u64),
    /// A secret source whose value is the id in decimal, e.g. `{ file: /run/secrets/app-id }`.
    Source(SecretSource),
}

fn default_github_host() -> String {
    DEFAULT_GITHUB_HOST.to_owned()
}

fn default_github_api_url() -> String {
    DEFAULT_GITHUB_API_URL.to_owned()
}

const fn default_refresh_before_secs() -> u64 {
    DEFAULT_REFRESH_BEFORE_SECS
}

impl GithubApp {
    /// An App reference with every optional field at its default.
    #[must_use]
    pub fn new(app_id: u64, private_key: SecretSource) -> Self {
        Self {
            app_id: GithubId::Number(app_id),
            private_key,
            installation_id: None,
            owner: None,
            api_url: default_github_api_url(),
            refresh_before_secs: DEFAULT_REFRESH_BEFORE_SECS,
        }
    }

    /// Mint for the installation on `owner`'s account.
    #[must_use]
    pub fn with_owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    /// Mint for this installation id.
    #[must_use]
    pub fn with_installation_id(mut self, id: u64) -> Self {
        self.installation_id = Some(GithubId::Number(id));
        self
    }

    /// Use a different API root (GitHub Enterprise Server, or a test server).
    #[must_use]
    pub fn with_api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = api_url.into();
        self
    }
}

impl GithubId {
    fn resolve(&self, field: &'static str) -> Result<u64, GithubAuthError> {
        match self {
            Self::Number(n) => Ok(*n),
            Self::Source(source) => {
                let raw = secret::resolve(source).map_err(|e| GithubAuthError::Secret {
                    what: format!("GitHub App {field} ({})", source.describe_reference()),
                    source: e,
                })?;
                raw.trim()
                    .parse()
                    .map_err(|_| GithubAuthError::IdNotNumeric { field, value: raw })
            }
        }
    }
}

/// Data-free discriminant of [`GithubAuth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum GithubAuthKind {
    /// [`GithubAuth::Token`].
    Token,
    /// [`GithubAuth::GhCli`].
    GhCli,
    /// [`GithubAuth::App`].
    App,
    /// [`GithubAuth::Chain`].
    Chain,
}

impl GithubAuthKind {
    /// Every kind, in [`GithubAuth`] declaration order.
    pub const ALL: &'static [Self] = &[Self::Token, Self::GhCli, Self::App, Self::Chain];

    /// The serde tag of the matching [`GithubAuth`] variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::GhCli => "gh_cli",
            Self::App => "app",
            Self::Chain => "chain",
        }
    }
}

impl fmt::Display for GithubAuthKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl GithubAuth {
    /// The fleet default chain for an application named `app_env_prefix`:
    ///
    /// 1. `token: { env: <PREFIX>_GITHUB_TOKEN }` — a token scoped to this tool
    /// 2. `token: { env: GITHUB_TOKEN }` — the Actions / ecosystem convention
    /// 3. `token: { env: GH_TOKEN }` — the `gh` CLI's own variable
    /// 4. `gh_cli: { host: github.com }` — the operator's interactive login
    /// 5. `token: { file: ~/.config/github/token }` — a token file
    ///
    /// The prefix is upper-cased with `-` turned into `_` (`tend` →
    /// `TEND_GITHUB_TOKEN`, `my-tool` → `MY_TOOL_GITHUB_TOKEN`); an empty
    /// prefix drops element 1.
    #[must_use]
    pub fn default_chain(app_env_prefix: &str) -> Self {
        let prefix: String = app_env_prefix
            .trim()
            .chars()
            .map(|c| {
                if c == '-' {
                    '_'
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect();
        let env = |var: String| Self::Token(SecretSource::Backend(SecretBackend::Env(var)));
        let mut chain = Vec::with_capacity(5);
        if !prefix.is_empty() {
            chain.push(env(format!("{prefix}_GITHUB_TOKEN")));
        }
        chain.push(env("GITHUB_TOKEN".to_owned()));
        chain.push(env("GH_TOKEN".to_owned()));
        chain.push(Self::GhCli {
            host: default_github_host(),
        });
        chain.push(Self::Token(SecretSource::Backend(SecretBackend::File(
            PathBuf::from("~/.config/github/token"),
        ))));
        Self::Chain(chain)
    }

    /// Data-free discriminant of this source.
    #[must_use]
    pub const fn kind(&self) -> GithubAuthKind {
        match self {
            Self::Token(_) => GithubAuthKind::Token,
            Self::GhCli { .. } => GithubAuthKind::GhCli,
            Self::App(_) => GithubAuthKind::App,
            Self::Chain(_) => GithubAuthKind::Chain,
        }
    }

    /// Operator-facing description of this source; never contains a secret.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Token(source) => format!("token from {}", source.describe_reference()),
            Self::GhCli { host } => format!("gh auth token --hostname {host}"),
            Self::App(app) => {
                let id = match &app.app_id {
                    GithubId::Number(n) => n.to_string(),
                    GithubId::Source(s) => format!("<{}>", s.describe_reference()),
                };
                match (&app.installation_id, &app.owner) {
                    (Some(GithubId::Number(i)), _) => format!("GitHub App {id} installation {i}"),
                    (Some(GithubId::Source(s)), _) => {
                        format!("GitHub App {id} installation <{}>", s.describe_reference())
                    }
                    (None, Some(owner)) => format!("GitHub App {id} installed on {owner}"),
                    (None, None) => format!("GitHub App {id} (sole installation)"),
                }
            }
            Self::Chain(items) => format!("chain of {} sources", items.len()),
        }
    }

    /// Resolve a token through the process-wide [`GithubAuthResolver`]
    /// (real `gh`, real HTTP, the shared App-token cache).
    ///
    /// # Errors
    ///
    /// [`GithubAuthError`] naming the source that failed; for a
    /// [`Self::Chain`], [`GithubAuthError::Chain`] lists every element's
    /// failure.
    pub fn resolve(&self) -> Result<GithubToken, GithubAuthError> {
        GithubAuthResolver::global().resolve(self)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Resolved token
// ─────────────────────────────────────────────────────────────────────

/// Which source produced a [`GithubToken`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubTokenProvenance {
    /// Index path through nested [`GithubAuth::Chain`]s to the source that
    /// produced the token — `[2]` is the third element of the top chain,
    /// `[]` a source resolved directly.
    pub chain_path: Vec<usize>,
    /// Kind of the producing source (never [`GithubAuthKind::Chain`]).
    pub kind: GithubAuthKind,
    /// For [`GithubAuthKind::Token`], the secret backend it was read from.
    pub secret_backend: Option<SecretBackendKind>,
    /// [`GithubAuth::describe`] of the producing source.
    pub description: String,
}

impl fmt::Display for GithubTokenProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)?;
        if !self.chain_path.is_empty() {
            let path: Vec<String> = self.chain_path.iter().map(ToString::to_string).collect();
            write!(f, " (chain[{}])", path.join("]["))?;
        }
        Ok(())
    }
}

/// A non-empty GitHub token, where it came from, and when it expires.
///
/// There is no accessor that hands out the token as a plain value under its
/// own name and no formatter that prints it: each consumer asks for the
/// exact shape its sink takes (an `Authorization` header, a git
/// `http.extraheader`, a nix `access-tokens` line, env pairs).
#[derive(Clone)]
pub struct GithubToken {
    value: String,
    provenance: GithubTokenProvenance,
    expires_at: Option<SystemTime>,
}

impl GithubToken {
    fn new(
        value: &str,
        provenance: GithubTokenProvenance,
        expires_at: Option<SystemTime>,
    ) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        Some(Self {
            value: value.to_owned(),
            provenance,
            expires_at,
        })
    }

    /// Where this token came from.
    #[must_use]
    pub fn provenance(&self) -> &GithubTokenProvenance {
        &self.provenance
    }

    /// When the token stops working — `Some` for App installation tokens,
    /// `None` for sources that do not say (PATs, `gh`).
    #[must_use]
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// `Bearer <token>`, the value of an `Authorization` header for the
    /// GitHub REST and GraphQL APIs (accepted for every token kind).
    #[must_use]
    pub fn authorization_header(&self) -> String {
        format!("Bearer {}", self.value)
    }

    /// The bare token, for an HTTP client builder that composes its own
    /// `Authorization` header (`octocrab::OctocrabBuilder::personal_token`,
    /// say). Prefer a renderer; anything that stores or prints this value
    /// defeats the type.
    #[must_use]
    pub fn expose_for_header(&self) -> &str {
        &self.value
    }

    /// The value for git's `http.<url>.extraheader`:
    /// `AUTHORIZATION: basic <base64(x-access-token:<token>)>` — the shape
    /// `actions/checkout` uses, valid for PATs and App tokens alike.
    #[must_use]
    pub fn git_extraheader(&self) -> String {
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("x-access-token:{}", self.value));
        format!("AUTHORIZATION: basic {basic}")
    }

    /// `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_0` / `GIT_CONFIG_VALUE_0` setting
    /// `http.https://<host>/.extraheader` for one git child process, without
    /// writing a credential into any config file.
    #[must_use]
    pub fn git_config_env(&self, host: &str) -> Vec<(String, String)> {
        vec![
            ("GIT_CONFIG_COUNT".to_owned(), "1".to_owned()),
            (
                "GIT_CONFIG_KEY_0".to_owned(),
                format!("http.https://{host}/.extraheader"),
            ),
            ("GIT_CONFIG_VALUE_0".to_owned(), self.git_extraheader()),
        ]
    }

    /// `access-tokens = github.com=<token>`, a nix.conf line.
    ///
    /// The host is `github.com`, fixed: nix's github fetcher keys on
    /// `github.com=`, and a token filed under `api.github.com=` is invisible
    /// to it — the same 404 as no token at all (`fleet`'s
    /// `github_token.rs` measured this).
    #[must_use]
    pub fn nix_access_tokens_line(&self) -> String {
        format!("access-tokens = github.com={}", self.value)
    }

    /// `GH_TOKEN` and `GITHUB_TOKEN`, for a child process (`gh`, Actions
    /// tooling, most GitHub SDKs read one or the other).
    #[must_use]
    pub fn env_pairs(&self) -> [(&'static str, String); 2] {
        [
            ("GH_TOKEN", self.value.clone()),
            ("GITHUB_TOKEN", self.value.clone()),
        ]
    }

    /// A safe-to-log fingerprint: GitHub's own type prefix when the token
    /// has one (`ghp_`, `ghs_`, `gho_`, `github_pat_`, …) and the length.
    /// A token without a recognised prefix shows only its length, so the
    /// fingerprint never leaks secret characters.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!(
            "{}****({} chars)",
            token_type_prefix(&self.value),
            self.value.len()
        )
    }
}

/// GitHub's documented token-type prefix, if `token` carries one.
fn token_type_prefix(token: &str) -> &'static str {
    const PREFIXES: [&str; 6] = ["github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"];
    PREFIXES
        .into_iter()
        .find(|p| token.starts_with(p))
        .unwrap_or("")
}

// `value` is rendered as its fingerprint under the name `token`; leaving the
// raw field out of `Debug` is the point of the impl.
#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for GithubToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubToken")
            .field("token", &self.redacted())
            .field("provenance", &self.provenance)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl fmt::Display for GithubToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} via {}", self.redacted(), self.provenance)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

/// Why a [`GithubAuth`] source yielded no token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GithubAuthError {
    /// A secret backend failed (unset env var, unreadable file, `sops`
    /// error, …).
    #[error("{what}: {source}")]
    Secret {
        /// The source being read, from [`SecretSource::describe_reference`].
        what: String,
        /// The backend's error.
        #[source]
        source: ShikumiError,
    },
    /// The source answered, but with nothing.
    #[error("{what} yielded an empty token")]
    Empty {
        /// The source that answered empty.
        what: String,
    },
    /// `gh auth token` could not run or refused.
    #[error("`{program} auth token --hostname {host}` failed: {reason}")]
    GhCli {
        /// The program run (`gh` unless overridden).
        program: String,
        /// The host asked for.
        host: String,
        /// Spawn error, or exit status and stderr.
        reason: String,
    },
    /// An App or installation id read from a secret source is not a number.
    #[error("GitHub App {field} is not a decimal number: {value:?}")]
    IdNotNumeric {
        /// `app_id` or `installation_id`.
        field: &'static str,
        /// The text read.
        value: String,
    },
    /// The App private key could not be used to sign the JWT.
    #[error("GitHub App {app_id}: private key is not a usable RSA PEM: {reason}")]
    AppKey {
        /// The App.
        app_id: u64,
        /// The parser's or signer's error.
        reason: String,
    },
    /// A GitHub API call made for the App failed.
    #[error("GitHub App {app_id}: {method} {url} failed: {reason}")]
    AppHttp {
        /// The App.
        app_id: u64,
        /// `GET` or `POST`.
        method: &'static str,
        /// The URL called.
        url: String,
        /// HTTP status when the server answered.
        status: Option<u16>,
        /// Transport error, or the response body.
        reason: String,
    },
    /// No installation of the App belongs to `owner`.
    #[error(
        "GitHub App {app_id} is not installed on {owner:?} (installed on: {})",
        if installed_on.is_empty() { "nothing".to_owned() } else { installed_on.join(", ") }
    )]
    InstallationNotFound {
        /// The App.
        app_id: u64,
        /// The login asked for.
        owner: String,
        /// Every account the App is installed on.
        installed_on: Vec<String>,
    },
    /// No `installation_id` or `owner` was given and the App does not have
    /// exactly one installation to default to.
    #[error(
        "GitHub App {app_id}: set installation_id or owner — the App has {} installations ({})",
        installed_on.len(),
        installed_on.join(", ")
    )]
    InstallationAmbiguous {
        /// The App.
        app_id: u64,
        /// Every account the App is installed on.
        installed_on: Vec<String>,
    },
    /// Every element of a [`GithubAuth::Chain`] failed; each reason is kept.
    #[error("{}", render_chain_failures(failures))]
    Chain {
        /// One entry per chain element, in chain order.
        failures: Vec<ChainFailure>,
    },
}

/// One failed element of a [`GithubAuth::Chain`].
#[derive(Debug)]
pub struct ChainFailure {
    /// The element's position in its chain.
    pub index: usize,
    /// [`GithubAuth::describe`] of the element.
    pub description: String,
    /// Why it yielded no token.
    pub error: GithubAuthError,
}

fn render_chain_failures(failures: &[ChainFailure]) -> String {
    if failures.is_empty() {
        return "no GitHub token: the chain is empty".to_owned();
    }
    let mut out = format!("no GitHub token from any of {} sources:", failures.len());
    for failure in failures {
        let reason = failure.error.to_string().replace('\n', "\n    ");
        let _ = write!(
            out,
            "\n  [{}] {}: {reason}",
            failure.index, failure.description
        );
    }
    out
}

// ─────────────────────────────────────────────────────────────────────
// HTTP seam
// ─────────────────────────────────────────────────────────────────────

/// HTTP method of a [`GithubHttpRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubHttpMethod {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

impl GithubHttpMethod {
    /// The method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// One GitHub API request the App flow makes.
#[derive(Clone)]
pub struct GithubHttpRequest {
    /// Method.
    pub method: GithubHttpMethod,
    /// Absolute URL.
    pub url: String,
    /// Bearer credential (the App JWT) — redacted in `Debug`.
    pub bearer: String,
    /// JSON body for `POST`.
    pub body: Option<serde_json::Value>,
}

impl fmt::Debug for GithubHttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("bearer", &"<redacted>")
            .field("body", &self.body)
            .finish()
    }
}

/// A GitHub API response.
#[derive(Debug, Clone)]
pub struct GithubHttpResponse {
    /// HTTP status.
    pub status: u16,
    /// Response body.
    pub body: String,
}

/// The transport the App flow calls GitHub through. [`ReqwestGithubHttp`]
/// is the real one; tests substitute a recording fake.
pub trait GithubHttp: Send + Sync {
    /// Send one request.
    ///
    /// # Errors
    ///
    /// A transport-level failure (connect, TLS, timeout) as text. An HTTP
    /// error status is NOT an `Err` — it is a response.
    fn send(&self, request: &GithubHttpRequest) -> Result<GithubHttpResponse, String>;
}

/// [`GithubHttp`] over `reqwest::blocking`, rustls, 30 s timeout.
#[derive(Default)]
pub struct ReqwestGithubHttp {
    client: OnceLock<Result<reqwest::blocking::Client, String>>,
}

impl ReqwestGithubHttp {
    /// A transport whose client is built on first use.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn client(&self) -> Result<&reqwest::blocking::Client, String> {
        self.client
            .get_or_init(|| {
                reqwest::blocking::Client::builder()
                    .user_agent(USER_AGENT)
                    .timeout(Duration::from_secs(30))
                    .build()
                    .map_err(|e| format!("building HTTP client: {e}"))
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

impl GithubHttp for ReqwestGithubHttp {
    fn send(&self, request: &GithubHttpRequest) -> Result<GithubHttpResponse, String> {
        let client = self.client()?;
        let builder = match request.method {
            GithubHttpMethod::Get => client.get(&request.url),
            GithubHttpMethod::Post => client.post(&request.url),
        };
        let mut builder = builder
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(&request.bearer);
        if let Some(body) = &request.body {
            builder = builder.json(body);
        }
        let response = builder.send().map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let body = response.text().map_err(|e| format!("reading body: {e}"))?;
        Ok(GithubHttpResponse { status, body })
    }
}

// ─────────────────────────────────────────────────────────────────────
// Resolver
// ─────────────────────────────────────────────────────────────────────

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Which installation an App token is for, as configured (cache key half).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum InstallationTarget {
    Id(u64),
    Owner(String),
    Sole,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AppCacheKey {
    api_url: String,
    app_id: u64,
    target: InstallationTarget,
}

struct CachedAppToken {
    value: String,
    expires_at_unix: u64,
}

/// Resolves [`GithubAuth`] values: owns the HTTP transport, the `gh` program
/// to run, the clock, and the App installation-token cache.
///
/// [`GithubAuth::resolve`] uses [`Self::global`]; build one explicitly to
/// substitute a transport or clock (tests), or to keep a cache private.
pub struct GithubAuthResolver {
    http: Arc<dyn GithubHttp>,
    gh_program: OsString,
    clock: Clock,
    cache: Mutex<HashMap<AppCacheKey, CachedAppToken>>,
}

impl Default for GithubAuthResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl GithubAuthResolver {
    /// A resolver with the real transport, `gh` from `PATH`, the system
    /// clock, and an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            http: Arc::new(ReqwestGithubHttp::new()),
            gh_program: OsString::from("gh"),
            clock: Arc::new(unix_now),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The process-wide resolver behind [`GithubAuth::resolve`]; its App
    /// token cache is shared by every caller in the process.
    pub fn global() -> &'static Self {
        static GLOBAL: OnceLock<GithubAuthResolver> = OnceLock::new();
        GLOBAL.get_or_init(Self::new)
    }

    /// Substitute the HTTP transport.
    #[must_use]
    pub fn with_http(mut self, http: Arc<dyn GithubHttp>) -> Self {
        self.http = http;
        self
    }

    /// Run this program instead of `gh` for [`GithubAuth::GhCli`].
    #[must_use]
    pub fn with_gh_program(mut self, program: impl Into<OsString>) -> Self {
        self.gh_program = program.into();
        self
    }

    /// Substitute the clock (unix seconds).
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Resolve `auth` to a token.
    ///
    /// # Errors
    ///
    /// See [`GithubAuth::resolve`].
    pub fn resolve(&self, auth: &GithubAuth) -> Result<GithubToken, GithubAuthError> {
        self.resolve_at(auth, &mut Vec::new())
    }

    fn resolve_at(
        &self,
        auth: &GithubAuth,
        path: &mut Vec<usize>,
    ) -> Result<GithubToken, GithubAuthError> {
        let provenance = |secret_backend| GithubTokenProvenance {
            chain_path: path.clone(),
            kind: auth.kind(),
            secret_backend,
            description: auth.describe(),
        };
        match auth {
            GithubAuth::Token(source) => {
                let value = secret::resolve(source).map_err(|e| GithubAuthError::Secret {
                    what: source.describe_reference(),
                    source: e,
                })?;
                GithubToken::new(&value, provenance(Some(source.backend_kind())), None).ok_or_else(
                    || GithubAuthError::Empty {
                        what: source.describe_reference(),
                    },
                )
            }
            GithubAuth::GhCli { host } => {
                let value = self.gh_auth_token(host)?;
                GithubToken::new(&value, provenance(None), None).ok_or_else(|| {
                    GithubAuthError::Empty {
                        what: auth.describe(),
                    }
                })
            }
            GithubAuth::App(app) => {
                let (value, expires_at_unix) = self.app_token(app)?;
                let expires_at = UNIX_EPOCH + Duration::from_secs(expires_at_unix);
                GithubToken::new(&value, provenance(None), Some(expires_at)).ok_or_else(|| {
                    GithubAuthError::Empty {
                        what: auth.describe(),
                    }
                })
            }
            GithubAuth::Chain(items) => {
                let mut failures = Vec::new();
                for (index, item) in items.iter().enumerate() {
                    path.push(index);
                    let outcome = self.resolve_at(item, path);
                    path.pop();
                    match outcome {
                        Ok(token) => {
                            if !failures.is_empty() {
                                tracing::debug!(
                                    source = %token.provenance(),
                                    skipped = failures.len(),
                                    "github token resolved after earlier chain sources failed"
                                );
                            }
                            return Ok(token);
                        }
                        Err(error) => failures.push(ChainFailure {
                            index,
                            description: item.describe(),
                            error,
                        }),
                    }
                }
                Err(GithubAuthError::Chain { failures })
            }
        }
    }

    fn gh_auth_token(&self, host: &str) -> Result<String, GithubAuthError> {
        let program = self.gh_program.to_string_lossy().into_owned();
        let fail = |reason: String| GithubAuthError::GhCli {
            program: program.clone(),
            host: host.to_owned(),
            reason,
        };
        let output = Command::new(&self.gh_program)
            .args(["auth", "token", "--hostname", host])
            .output()
            .map_err(|e| fail(format!("could not run: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(fail(format!(
                "exited with {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        String::from_utf8(output.stdout).map_err(|_| fail("stdout is not UTF-8".to_owned()))
    }

    /// An installation token for `app`: the cached one while it has more than
    /// `refresh_before_secs` left, otherwise a fresh mint.
    fn app_token(&self, app: &GithubApp) -> Result<(String, u64), GithubAuthError> {
        let app_id = app.app_id.resolve("app_id")?;
        let target = match (&app.installation_id, &app.owner) {
            (Some(id), _) => InstallationTarget::Id(id.resolve("installation_id")?),
            (None, Some(owner)) => InstallationTarget::Owner(owner.clone()),
            (None, None) => InstallationTarget::Sole,
        };
        let key = AppCacheKey {
            api_url: app.api_url.trim_end_matches('/').to_owned(),
            app_id,
            target,
        };

        // Held across the mint on purpose: N threads finding the same token
        // stale mint it once, not N times.
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = (self.clock)();
        if let Some(cached) = cache.get(&key)
            && now.saturating_add(app.refresh_before_secs) < cached.expires_at_unix
        {
            return Ok((cached.value.clone(), cached.expires_at_unix));
        }

        let pem = secret::resolve(&app.private_key).map_err(|e| GithubAuthError::Secret {
            what: format!(
                "GitHub App {app_id} private key ({})",
                app.private_key.describe_reference()
            ),
            source: e,
        })?;
        let jwt = sign_app_jwt(app_id, &pem, now)?;
        let installation_id = match &key.target {
            InstallationTarget::Id(id) => *id,
            InstallationTarget::Owner(owner) => {
                self.find_installation(&key.api_url, app_id, &jwt, Some(owner))?
            }
            InstallationTarget::Sole => self.find_installation(&key.api_url, app_id, &jwt, None)?,
        };

        let url = format!(
            "{}/app/installations/{installation_id}/access_tokens",
            key.api_url
        );
        let body = self.call(
            app_id,
            GithubHttpMethod::Post,
            &url,
            &jwt,
            Some(serde_json::json!({})),
        )?;
        let minted: InstallationTokenResponse =
            serde_json::from_str(&body).map_err(|e| GithubAuthError::AppHttp {
                app_id,
                method: "POST",
                url: url.clone(),
                status: None,
                reason: format!("unexpected response shape: {e}"),
            })?;
        // An unparseable expiry is treated as "expires in 50 minutes" rather
        // than failing a token GitHub just issued: refreshing early is safe,
        // refusing a working token is not.
        let expires_at_unix = parse_github_timestamp(&minted.expires_at).unwrap_or_else(|| {
            tracing::warn!(
                expires_at = %minted.expires_at,
                "unparseable GitHub installation-token expiry; assuming 50 minutes"
            );
            now + 50 * 60
        });
        cache.insert(
            key,
            CachedAppToken {
                value: minted.token.clone(),
                expires_at_unix,
            },
        );
        Ok((minted.token, expires_at_unix))
    }

    /// The installation id for `owner` (or the App's only installation),
    /// paging through `GET /app/installations`.
    fn find_installation(
        &self,
        api_url: &str,
        app_id: u64,
        jwt: &str,
        owner: Option<&str>,
    ) -> Result<u64, GithubAuthError> {
        const PER_PAGE: usize = 100;
        const MAX_PAGES: usize = 100;
        let mut all: Vec<Installation> = Vec::new();
        for page in 1..=MAX_PAGES {
            let url = format!("{api_url}/app/installations?per_page={PER_PAGE}&page={page}");
            let body = self.call(app_id, GithubHttpMethod::Get, &url, jwt, None)?;
            let batch: Vec<Installation> =
                serde_json::from_str(&body).map_err(|e| GithubAuthError::AppHttp {
                    app_id,
                    method: "GET",
                    url: url.clone(),
                    status: None,
                    reason: format!("unexpected response shape: {e}"),
                })?;
            let last = batch.len() < PER_PAGE;
            if let Some(owner) = owner
                && let Some(hit) = batch
                    .iter()
                    .find(|i| i.account.login.eq_ignore_ascii_case(owner))
            {
                return Ok(hit.id);
            }
            all.extend(batch);
            if last {
                break;
            }
        }
        let installed_on: Vec<String> = all.iter().map(|i| i.account.login.clone()).collect();
        match owner {
            Some(owner) => Err(GithubAuthError::InstallationNotFound {
                app_id,
                owner: owner.to_owned(),
                installed_on,
            }),
            None if all.len() == 1 => Ok(all[0].id),
            None => Err(GithubAuthError::InstallationAmbiguous {
                app_id,
                installed_on,
            }),
        }
    }

    fn call(
        &self,
        app_id: u64,
        method: GithubHttpMethod,
        url: &str,
        jwt: &str,
        body: Option<serde_json::Value>,
    ) -> Result<String, GithubAuthError> {
        let request = GithubHttpRequest {
            method,
            url: url.to_owned(),
            bearer: jwt.to_owned(),
            body,
        };
        let fail = |status, reason| GithubAuthError::AppHttp {
            app_id,
            method: method.as_str(),
            url: url.to_owned(),
            status,
            reason,
        };
        let response = self.http.send(&request).map_err(|e| fail(None, e))?;
        if !(200..300).contains(&response.status) {
            return Err(fail(
                Some(response.status),
                format!("HTTP {}: {}", response.status, response.body.trim()),
            ));
        }
        Ok(response.body)
    }
}

#[derive(Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
    account: InstallationAccount,
}

#[derive(Deserialize)]
struct InstallationAccount {
    login: String,
}

#[derive(Serialize)]
struct AppJwtClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

/// Sign the App JWT GitHub exchanges for an installation token: RS256,
/// `iss` = the App id, `iat` = `now` − [`APP_JWT_BACKDATE_SECS`], `exp` =
/// `now` + [`APP_JWT_LIFETIME_SECS`].
///
/// # Errors
///
/// [`GithubAuthError::AppKey`] when `private_key_pem` is not an RSA key.
pub fn sign_app_jwt(
    app_id: u64,
    private_key_pem: &str,
    now: u64,
) -> Result<String, GithubAuthError> {
    let key_error = |reason: String| GithubAuthError::AppKey { app_id, reason };
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| key_error(e.to_string()))?;
    let claims = AppJwtClaims {
        iat: now.saturating_sub(APP_JWT_BACKDATE_SECS),
        exp: now + APP_JWT_LIFETIME_SECS,
        iss: app_id.to_string(),
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &key,
    )
    .map_err(|e| key_error(format!("signing: {e}")))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Parse GitHub's `YYYY-MM-DDTHH:MM:SS[.fff]Z` timestamps to unix seconds.
/// Anything else (an offset other than `Z`, a malformed field) is `None`.
fn parse_github_timestamp(text: &str) -> Option<u64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let time = time.split_once('.').map_or(time, |(whole, _)| whole);
    let mut d = date.splitn(3, '-').map(str::parse::<i64>);
    let (year, month, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let mut t = time.splitn(3, ':').map(str::parse::<i64>);
    let (hour, minute, second) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(secs).ok()
}

/// Days since 1970-01-01 of a proleptic-Gregorian date (Howard Hinnant's
/// `days_from_civil`).
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests;
