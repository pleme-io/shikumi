//! Unified secret-client abstraction.
//!
//! `SecretClient` is a single async trait that every vault backend
//! implements. Consumers write against `Arc<dyn SecretClient>` and swap
//! backends without rewriting code.
//!
//! The free functions in `crate::secret` remain the low-level API
//! (direct resolvers per backend, CLI or native). This module layers an
//! object-safe trait on top so daemons can depend on the abstraction
//! and wire up a concrete backend at startup.
//!
//! # Capability matrix
//!
//! Not every backend supports every operation. Methods that aren't
//! universally available return [`SecretError::Unsupported`] by default
//! — the trait advertises capabilities via [`SecretClient::capabilities`]
//! so consumers can check up-front.
//!
//! | Backend | get | list | put | delete | rotate | versions |
//! |---|---|---|---|---|---|---|
//! | MemClient (in-memory) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
//! | CommandClient (shell) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
//! | AkeylessClient | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
//! | AwsClient | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
//! | OpConnectClient | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
//! | VaultClient (KV v2) | ✅ | ✅ | ✅ | ✅ | ⚠️ (engine) | ✅ |
//! | GcpSecretClient | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
//! | SOPS (file-based) | stays CLI-only (no HTTP API) |
//!
//! "✅" = implemented. "⚠️" = supported but backend-specific.
//! "❌" = fundamentally unsupported.
//! "planned" = queued in RFC 0001 (`op-connect-api`, `vault-api`,
//! `gcp-secretmanager-api` need generating via forge-gen).
//!
//! "✅" = universally supported via the backend's API.
//! "⚠️" = supported but with backend-specific caveats (see per-impl docs).
//! "❌" = not supported — returns [`SecretError::Unsupported`].
//!
//! # Usage
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use shikumi::secret_client::{SecretClient, MemClient};
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let client: Arc<dyn SecretClient> = Arc::new(MemClient::new());
//! client.put("jwt_secret", "dev-only").await?;
//! let value = client.get("jwt_secret").await?;
//! assert_eq!(value, "dev-only");
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::error::ShikumiError;

/// Typed error for secret-client operations.
///
/// Callers can match on specific variants for retry logic (e.g. retry
/// `NotFound` but not `Unauthorized`) instead of parsing strings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// The secret does not exist on the backend.
    #[error("secret not found: {name}")]
    NotFound { name: String },

    /// The caller lacks permission to perform this operation.
    #[error("unauthorized: {message}")]
    Unauthorized { message: String },

    /// The backend does not support this operation (e.g. SOPS doesn't
    /// do `list`; shell commands don't do `put`).
    #[error("{backend} does not support {operation}")]
    Unsupported {
        backend: &'static str,
        operation: &'static str,
    },

    /// Transport / network / serialization error.
    #[error("backend error: {0}")]
    Backend(String),

    /// Pass-through shikumi error (used by the command/CLI backends).
    #[error(transparent)]
    Shikumi(#[from] ShikumiError),
}

impl SecretError {
    /// Retryable errors: network hiccups, rate limits, 5xx responses.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Backend(msg) if msg.contains("timeout") || msg.contains("5"))
    }

    /// Construct an [`Self::Unsupported`] from a typed [`SecretOperation`]
    /// — the canonical [`SecretOperation::as_str`] string becomes the
    /// `operation` field.
    ///
    /// The closed constructor that names every `Unsupported` site through
    /// one [`SecretOperation`] variant rather than a `&'static str`
    /// literal. Default trait impls on [`SecretClient`] route through
    /// this constructor, so the operation-name strings live at one site
    /// ([`SecretOperation::as_str`]) instead of being re-stated at each
    /// `Err(SecretError::Unsupported { operation: "list" })` arm.
    ///
    /// A future operation landing on [`SecretOperation`] (`Metadata`,
    /// `Tags`, etc.) extends the canonical-label site once and every
    /// default trait impl using this constructor picks the new label up
    /// without per-site edits.
    #[must_use]
    pub const fn unsupported(backend: &'static str, op: SecretOperation) -> Self {
        Self::Unsupported {
            backend,
            operation: op.as_str(),
        }
    }

    /// Closed-enum classification of this error's variant — the typed
    /// kind partition over the [`SecretError`] variant space.
    ///
    /// One source of truth for the kind axis: consumers route on the
    /// returned [`SecretErrorKind`] (in `match`, `HashMap` keys, log
    /// labels, alerting buckets, retry-policy dispatch tables, telemetry
    /// recording the per-kind refusal mix across backends, attestation
    /// manifests recording the kind histogram of secret-resolution
    /// failures) instead of pattern-matching the five payload-carrying
    /// variants by hand at every observation site. Equivalent to
    /// `matches!` on the underlying variant — but the closed-enum
    /// return value composes further (it's `Copy + Eq + Hash + 'static`),
    /// where a `matches!` predicate does not, and crosses thread
    /// boundaries the borrowed payloads cannot.
    ///
    /// Peer projection to [`ShikumiError::kind`] on the [`ShikumiError`]
    /// variant space — same typescape discipline (closed exhaustive
    /// match, `'static` codomain, `Copy + Eq + Hash`) applied to the
    /// secret-client error axis. The two error kinds compose
    /// structurally: a [`Self::Shikumi`] error carries a [`ShikumiError`]
    /// whose own [`ShikumiError::kind`] refines the partition further on
    /// the wrapped-shikumi sub-axis, so observers wanting the underlying
    /// shikumi kind on a wrapped error read
    /// `err.as_shikumi().map(ShikumiError::kind)` without inlining a
    /// per-variant pattern match.
    ///
    /// The implementation is one exhaustive `match`, so a future
    /// [`SecretError`] variant landing forces a corresponding
    /// [`SecretErrorKind`] variant in lockstep at compile time — the
    /// kind partition stays coherent by construction.
    #[must_use]
    pub const fn kind(&self) -> SecretErrorKind {
        match self {
            Self::NotFound { .. } => SecretErrorKind::NotFound,
            Self::Unauthorized { .. } => SecretErrorKind::Unauthorized,
            Self::Unsupported { .. } => SecretErrorKind::Unsupported,
            Self::Backend(_) => SecretErrorKind::Backend,
            Self::Shikumi(_) => SecretErrorKind::Shikumi,
        }
    }

    /// Borrow the underlying [`ShikumiError`] if this is a
    /// [`Self::Shikumi`] pass-through, else `None`.
    ///
    /// One source of truth for the (`SecretError → wrapped-shikumi`)
    /// partial projection. Consumers wanting to refine the kind
    /// partition on the wrapped-shikumi sub-axis (via
    /// [`ShikumiError::kind`]) read
    /// `err.as_shikumi().map(ShikumiError::kind)` through this accessor
    /// instead of inlining `if let Self::Shikumi(inner) = err { … }` at
    /// every cross-kind dispatch site. Dual to [`Self::kind`]'s
    /// `Self::Shikumi` arm — `as_shikumi().is_some()` ↔
    /// `kind() == SecretErrorKind::Shikumi` by construction.
    #[must_use]
    pub const fn as_shikumi(&self) -> Option<&ShikumiError> {
        match self {
            Self::Shikumi(inner) => Some(inner),
            _ => None,
        }
    }
}

/// Data-free, `'static` discriminant of [`SecretError`]: the kind of
/// secret-client error independent of the payload-carrying fields.
///
/// Closed five-way partition over the [`SecretError`] variant space,
/// returned by [`SecretError::kind`]. The enum exists so consumers that
/// care only about the kind axis (per-kind retry-policy dispatch,
/// per-kind telemetry counters, structured-diagnostic legends naming
/// the failing kind, alerting buckets histogramming refusal classes
/// across backends, attestation manifests recording the kind mix of
/// secret-resolution failures, cross-thread log fields naming the kind
/// after the borrowed [`SecretError`] payload has been dropped) match
/// on one closed enum instead of pattern-matching against the
/// payload-carrying [`SecretError`] (whose `Backend(String)` and
/// `Shikumi(ShikumiError)` payloads hold owned data that cannot be
/// trivially cloned for cross-thread observation).
///
/// Peer of [`crate::ShikumiErrorKind`] on the [`crate::ShikumiError`]
/// variant axis, and of the other closed-enum kind primitives
/// ([`crate::SecretBackendKind`] on the secret-resolution backend axis,
/// [`crate::SecretRefShape`] on the cross-type ref-extraction-shape
/// axis, [`SecretOperation`] on the cross-surface operation axis,
/// [`crate::ConfigSourceKind`] on the layer axis,
/// [`crate::FigmentSourceKind`] / [`crate::FigmentNameTagKind`] on
/// the figment-`Metadata::{source, name}` axes): same typescape
/// discipline (closed, allocation-free,
/// `Copy + Eq + Hash + #[non_exhaustive]`, exhaustive forward map),
/// applied to the secret-client error axis.
///
/// `'static` and allocation-free — survives the borrow on the
/// originating [`SecretError`]'s owned payloads and can therefore
/// cross thread boundaries, serialize, and live in long-lived
/// structures the way [`crate::ShikumiErrorKind`] does on the
/// captured cross-thread observable form of [`crate::ReloadFailure`].
///
/// Adding a future [`SecretError`] variant means adding one
/// [`SecretErrorKind`] variant in lockstep — the exhaustive
/// [`SecretError::kind`] match forces the assignment at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SecretErrorKind {
    /// Maps to [`SecretError::NotFound`] regardless of inner secret
    /// name. The backend confirmed the secret does not exist on the
    /// store — distinct from [`Self::Backend`] (transport failure) and
    /// [`Self::Unauthorized`] (permission denied).
    NotFound,
    /// Maps to [`SecretError::Unauthorized`] regardless of inner
    /// message. The caller lacks permission for the operation — distinct
    /// from [`Self::Unsupported`] (the backend cannot perform the
    /// operation at all, regardless of caller).
    Unauthorized,
    /// Maps to [`SecretError::Unsupported`] regardless of inner backend
    /// or operation tags. The backend does not advertise the requested
    /// operation in its [`Capabilities`] — pairs with [`SecretOperation`]
    /// on the operation axis ([`SecretError::unsupported`] is the
    /// canonical constructor, naming the operation through one typed
    /// primitive).
    Unsupported,
    /// Maps to [`SecretError::Backend`] regardless of inner message.
    /// Transport, network, or serialization failure — the catch-all for
    /// backend-side faults that aren't captured by the structural kinds
    /// above. The only kind [`SecretError::is_retryable`] currently
    /// returns `true` for (on timeout / 5xx substring match).
    Backend,
    /// Maps to [`SecretError::Shikumi`] regardless of inner
    /// [`ShikumiError`] variant. Pass-through wrapper for errors
    /// originating in the [`crate::secret`] resolver layer or the
    /// CLI/shell backends — observers wanting the underlying
    /// [`ShikumiError`] variant refine the partition via
    /// [`SecretError::as_shikumi`] +
    /// [`crate::ShikumiError::kind`].
    Shikumi,
}

impl SecretErrorKind {
    /// Every [`SecretErrorKind`] variant, in the same declaration order
    /// as the [`SecretError`] arms in [`SecretError::kind`]
    /// ([`Self::NotFound`], [`Self::Unauthorized`], [`Self::Unsupported`],
    /// [`Self::Backend`], [`Self::Shikumi`]).
    ///
    /// The closed list of error kinds the secret-client surface
    /// recognizes today, in the same declaration order as the
    /// [`SecretError`] variant list. Iterate to enumerate the kind space
    /// without listing variants by hand at every consumer site — e.g.
    /// dashboards initializing per-kind retry-policy buckets, attestation
    /// manifests recording the failure-mix histogram across backends,
    /// CLI flag values listing the filterable kind set, partition-
    /// coverage tests asserting disjointness over the whole universe.
    ///
    /// One source of truth for the kind enumeration on the
    /// [`SecretErrorKind`] axis: peer to [`crate::ShikumiErrorKind::ALL`]
    /// on the [`crate::ShikumiError`] variant axis, the same typescape
    /// discipline applied across the closed-enum primitive set.
    ///
    /// Adding a new variant to [`Self`] means extending this slice in
    /// lockstep with the variant itself. The compiler enforces nothing
    /// here directly, so the `secret_error_kind_all_covers_every_variant`
    /// test pins the contract by asserting that every kind produced by
    /// [`SecretError::kind`] over the construction-table surface appears
    /// in [`Self::ALL`], and the `secret_error_kind_all_has_no_duplicates`
    /// test pins that the constant is a set (no double-listed variant).
    pub const ALL: &'static [Self] = &[
        Self::NotFound,
        Self::Unauthorized,
        Self::Unsupported,
        Self::Backend,
        Self::Shikumi,
    ];

    /// Canonical operator-facing lowercase name of the error kind —
    /// [`Self::NotFound`] renders as `"not-found"`, [`Self::Unauthorized`]
    /// as `"unauthorized"`, [`Self::Unsupported`] as `"unsupported"`,
    /// [`Self::Backend`] as `"backend"`, [`Self::Shikumi`] as
    /// `"shikumi"`.
    ///
    /// Single source of truth for the five canonical strings on the
    /// secret-client kind axis. Inherent mirror of the
    /// [`crate::ClosedAxisLabel`] trait method; the trait impl delegates
    /// here so the canonical names live at one site instead of being
    /// re-stated at every operator-facing surface (a future structured-
    /// log field naming the surfaced kind, a CLI flag filtering captured
    /// failures by kind, a per-kind retry-policy dispatch table, an
    /// alerting bucket histogramming the kind partition, an attestation
    /// manifest recording the kind histogram).
    ///
    /// Kebab-case for the compound-noun variant [`Self::NotFound`]
    /// (`"not-found"`) — the same convention shared with
    /// [`crate::ShikumiErrorKind::as_str`]
    /// ([`crate::ShikumiErrorKind::NotFound`] → `"not-found"`),
    /// [`crate::FormatProvenance::as_str`] (`"figment-builtin"` /
    /// `"shikumi-built"`), and [`crate::AttributionAxis::as_str`]
    /// (`"metadata-source"` / `"metadata-name"`): compound-noun variant
    /// identifiers route the punctuation at the type level
    /// (operator-facing string) rather than at the call site. The
    /// remaining four single-word variants render as their lowercase
    /// identifier ([`Self::Unauthorized`] → `"unauthorized"`,
    /// [`Self::Unsupported`] → `"unsupported"`, [`Self::Backend`] →
    /// `"backend"`, [`Self::Shikumi`] → `"shikumi"`), matching the
    /// single-word lowercase convention shared with the sibling kind
    /// primitives.
    ///
    /// Pairs with [`crate::ClosedAxisLabel::from_canonical_str`] via the
    /// trait-default linear-scan parse; the round-trip law
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` holds for every
    /// variant uniformly through the trait-uniform
    /// `closed_axis_label_round_trips_for_every_implementor` test in
    /// `cube::tests`. The concrete-position pin at
    /// `secret_error_kind_as_str_yields_canonical_lowercase_names` holds
    /// the literal strings stable so a future rename (e.g. capitalizing
    /// `"NotFound"`, switching `"backend"` to `"transport"`) fails at
    /// that site before drifting through the round-trip law.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::Unauthorized => "unauthorized",
            Self::Unsupported => "unsupported",
            Self::Backend => "backend",
            Self::Shikumi => "shikumi",
        }
    }
}

impl crate::ClosedAxis for SecretErrorKind {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for SecretErrorKind {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

impl fmt::Display for SecretErrorKind {
    /// Write the canonical operator-facing label [`Self::as_str`]
    /// returns (`"not-found"` / `"unauthorized"` / `"unsupported"` /
    /// `"backend"` / `"shikumi"`) — the same scalar
    /// [`<Self as serde::Serialize>::serialize`] emits and the same
    /// scalar [`<Self as std::str::FromStr>::from_str`] accepts.
    /// Idiom-peer of the `Display` impl on
    /// [`crate::ShikumiErrorKind`] (commit `911b598`),
    /// [`SecretClientKind`] (commit `24c7b33`),
    /// [`crate::SecretBackendKind`] (commit `9b1da86`),
    /// [`crate::SecretRefShape`] (commit `8a84bb6`), and
    /// [`crate::ConfigSourceKind`] (commit `e0b96d1`) lifted onto the
    /// secret-client error-variant axis sibling closed-enum.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SecretErrorKind {
    type Err = ShikumiError;

    /// Parse the canonical operator-facing label (`"not-found"` /
    /// `"unauthorized"` / `"unsupported"` / `"backend"` / `"shikumi"`)
    /// produced by [`Self::as_str`]; case-insensitive over ASCII via
    /// the trait-default
    /// [`<Self as crate::ClosedAxisLabel>::from_canonical_str`] parse.
    /// On unrecognized input, returns [`ShikumiError::Parse`] with the
    /// offending label embedded verbatim — matching the
    /// verbatim-substring rejection discipline already established by
    /// [`<crate::ShikumiErrorKind as FromStr>::from_str`]
    /// (commit `911b598`),
    /// [`<SecretClientKind as FromStr>::from_str`]
    /// (commit `24c7b33`),
    /// [`<crate::SecretBackendKind as FromStr>::from_str`]
    /// (commit `9b1da86`),
    /// [`<crate::SecretRefShape as FromStr>::from_str`]
    /// (commit `8a84bb6`), and
    /// [`<crate::ConfigSourceKind as FromStr>::from_str`]
    /// (commit `e0b96d1`) so the same localization story (the operator
    /// sees the offending substring in the rendered diagnostic)
    /// carries to the secret-client error-variant axis kind.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <Self as crate::ClosedAxisLabel>::from_canonical_str(s)
            .ok_or_else(|| ShikumiError::Parse(format!("unknown secret error kind: {s}")))
    }
}

impl serde::Serialize for SecretErrorKind {
    /// Serialize the secret-client error-variant axis kind as the
    /// canonical operator-facing label [`Self::as_str`] returns — the
    /// same scalar the [`fmt::Display`] impl writes. Routes through
    /// [`serde::Serializer::collect_str`] so the serialized
    /// representation is exactly `format!("{self}")` with no
    /// intermediate allocation.
    ///
    /// Closes the canonical (`Serialize`, `Deserialize`) serde
    /// idiom-peer of the (`Display`, [`std::str::FromStr`]) stdlib
    /// pair on the secret-client error-variant axis kind primitive.
    /// A kind emitted into a YAML attestation manifest field, a JSON
    /// observability payload, or any consumer struct holding a
    /// [`SecretErrorKind`] field under
    /// `#[derive(Serialize, Deserialize)]` round-trips through the
    /// canonical label without a consumer-side rename helper.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for SecretErrorKind {
    /// Deserialize the secret-client error-variant axis kind from the
    /// canonical operator-facing label [`Self::as_str`] returns via
    /// [`serde::Deserializer::deserialize_str`] with a visitor whose
    /// `visit_str` lowers to [`<Self as FromStr>::from_str`] and
    /// routes any [`ShikumiError`] through
    /// [`serde::de::Error::custom`].
    ///
    /// **Case insensitivity inherits from [`FromStr`]** — the
    /// [`crate::ClosedAxisLabel::from_canonical_str`] trait default
    /// uses [`str::eq_ignore_ascii_case`] over [`Self::ALL`], so
    /// uppercase or mixed-case scalars (e.g. `NOT-FOUND`, `Backend`)
    /// parse pointwise.
    ///
    /// **Unknown-kind rejection carries the offending label verbatim**
    /// — a manifest field carrying an unrecognized kind surfaces at
    /// the serde error site with the offending substring verbatim in
    /// the rendered message, lifted through [`ShikumiError::Parse`]'s
    /// `Display` impl.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretErrorKindVisitor;

        impl serde::de::Visitor<'_> for SecretErrorKindVisitor {
            type Value = SecretErrorKind;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a canonical SecretErrorKind label \
                     (`not-found`, `unauthorized`, `unsupported`, \
                     `backend`, `shikumi`; case-insensitive)",
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<SecretErrorKind, E> {
                v.parse::<SecretErrorKind>().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(SecretErrorKindVisitor)
    }
}

/// Operations a [`SecretClient`] backend may expose — the closed
/// six-way axis over the (Capabilities-field × default-trait-method
/// × [`SecretError::Unsupported`]-tag) cross-surface space.
///
/// Three surfaces previously named the same operation universe
/// independently:
///
/// - [`Capabilities`]'s six `bool` fields (`get`, `list`, `put`,
///   `delete`, `rotate`, `versions`) — the advertised capability the
///   backend claims to support.
/// - The six default trait methods on [`SecretClient`] (`get`, `list`,
///   `put`, `delete`, `rotate`, `get_version`) — the actual dispatch
///   point.
/// - The five `Err(SecretError::Unsupported { operation: "X", .. })`
///   arms each default impl raised (`"list"`, `"put"`, `"delete"`,
///   `"rotate"`, `"get_version"`) — the operator-facing label naming
///   which operation the backend refused.
///
/// The three-way agreement was implicit in the dispatch table only —
/// a future operation landing meant editing the [`Capabilities`]
/// struct, adding a default trait method, and inventing a fresh
/// magic-string label in lockstep, with nothing in the type system
/// pinning the alignment. Lifting the universe to one typed primitive
/// closes the cross-surface agreement: every operation has exactly
/// one [`SecretOperation`] variant, [`Capabilities::supports`] picks
/// the matching field by closed-enum dispatch, and
/// [`SecretError::unsupported`] uses [`Self::as_str`] for the
/// operator-facing label. A future variant landing (e.g. a hypothetical
/// `Metadata` operation pairing with a `metadata` Capabilities flag
/// and a default `metadata` trait method) lands as one new arm on
/// each of the three surfaces, with the [`SecretOperation`] enum
/// forcing the assignment at compile time.
///
/// Closed-axis discipline: `Copy + Eq + Hash + #[non_exhaustive]`,
/// allocation-free, [`crate::ClosedAxis`] + [`crate::ClosedAxisLabel`]
/// — same trait-bounds parity as [`SecretBackendKind`] /
/// [`crate::SecretRefShape`] on the secret-axis primitives, and as
/// [`crate::ConfigSourceKind`] / [`crate::FigmentSourceKind`] /
/// [`crate::FigmentNameTagKind`] on the resolution-axis primitives.
///
/// [`SecretBackendKind`]: crate::secret::SecretBackendKind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SecretOperation {
    /// Read the current secret value — [`SecretClient::get`]. Maps to
    /// [`Capabilities::get`]. Every backend supports `Get`; the variant
    /// exists for symmetry on the axis (so [`Capabilities::supports`]
    /// is total over [`Self::ALL`]) and so a future per-operation
    /// telemetry surface need not special-case the read path.
    Get,
    /// Enumerate secret names — [`SecretClient::list`]. Maps to
    /// [`Capabilities::list`].
    List,
    /// Create or update a secret — [`SecretClient::put`]. Maps to
    /// [`Capabilities::put`].
    Put,
    /// Delete a secret — [`SecretClient::delete`]. Maps to
    /// [`Capabilities::delete`].
    Delete,
    /// Trigger backend-side rotation — [`SecretClient::rotate`]. Maps
    /// to [`Capabilities::rotate`].
    Rotate,
    /// Fetch a specific historical version — [`SecretClient::get_version`].
    /// Maps to [`Capabilities::versions`]. The Capabilities field's
    /// `versions` plural and the trait method's `get_version` singular
    /// previously disagreed at the string level; [`SecretOperation`]
    /// names the operation once and both surfaces project onto it.
    GetVersion,
}

impl SecretOperation {
    /// Every [`SecretOperation`] variant, in declaration order
    /// ([`Self::Get`], [`Self::List`], [`Self::Put`], [`Self::Delete`],
    /// [`Self::Rotate`], [`Self::GetVersion`]).
    ///
    /// The closed list of operations the [`SecretClient`] surface
    /// recognizes today — same six entries as [`Capabilities`]'s field
    /// set, in the same declaration order. Adding a new variant means
    /// extending this slice in lockstep with the variant itself; the
    /// `secret_operation_all_*` tests pin the contract.
    pub const ALL: &'static [Self] = &[
        Self::Get,
        Self::List,
        Self::Put,
        Self::Delete,
        Self::Rotate,
        Self::GetVersion,
    ];

    /// Canonical operator-facing `snake_case` name — `"get"`, `"list"`,
    /// `"put"`, `"delete"`, `"rotate"`, or `"get_version"`.
    ///
    /// The single source of truth for the operation-name strings the
    /// [`SecretError::Unsupported`] arm carries on its `operation`
    /// field. The labels coincide with the [`SecretClient`] trait
    /// method names pointwise (rather than with the [`Capabilities`]
    /// field names, which would render `"versions"` for the `versions`
    /// field — disagreeing with the trait method's `get_version`
    /// singular). Picking the trait-method shape keeps the
    /// [`SecretError::Unsupported`] message (`"backend X does not
    /// support get_version"`) naming the same identifier an operator
    /// would call from code, instead of the Capabilities-side plural
    /// that has no matching dispatch site.
    ///
    /// Pairs with [`crate::ClosedAxisLabel::from_canonical_str`] via
    /// the trait-default linear-scan parse; the round-trip law
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` holds for
    /// every variant uniformly through the trait-uniform
    /// `closed_axis_label_round_trips_for_every_implementor` test in
    /// `cube::tests`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::List => "list",
            Self::Put => "put",
            Self::Delete => "delete",
            Self::Rotate => "rotate",
            Self::GetVersion => "get_version",
        }
    }

    /// Whether `caps` advertises this operation — the typed projection
    /// of [`SecretOperation`] onto the matching [`Capabilities`] field.
    ///
    /// Dual of [`Capabilities::supports`]; the two methods delegate to
    /// the same arm by symmetry. Consumers that carry a
    /// [`SecretOperation`] (e.g. dispatch-side code deciding "should I
    /// call `.list()` on this client?") read the capability through
    /// this projection without inlining a six-arm `match` over the
    /// Capabilities boolean fields at each site.
    #[must_use]
    pub const fn is_supported_by(self, caps: Capabilities) -> bool {
        match self {
            Self::Get => caps.get,
            Self::List => caps.list,
            Self::Put => caps.put,
            Self::Delete => caps.delete,
            Self::Rotate => caps.rotate,
            Self::GetVersion => caps.versions,
        }
    }
}

impl crate::ClosedAxis for SecretOperation {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for SecretOperation {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

/// Which operations a [`SecretClient`] backend supports.
///
/// Queried via [`SecretClient::capabilities`]. Daemons that need
/// write-access can reject read-only clients at startup instead of
/// discovering the limitation at the first `put()` call.
///
/// Projects onto the [`SecretOperation`] axis via [`Self::supports`] —
/// `caps.supports(SecretOperation::Foo)` reads the matching boolean
/// field by closed-enum dispatch, so consumers that carry a typed
/// [`SecretOperation`] (per-operation telemetry, dispatch-side
/// "should I call this method?" gating, attestation manifests
/// recording the operation mix of refused calls) read the capability
/// through one projection instead of pattern-matching the six
/// boolean fields by name at each site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Read operations always supported — every backend can `get`.
    /// Maps to [`SecretOperation::Get`].
    pub get: bool,
    /// Enumerate secrets by prefix. Maps to [`SecretOperation::List`].
    pub list: bool,
    /// Create or update a secret. Maps to [`SecretOperation::Put`].
    pub put: bool,
    /// Delete a secret. Maps to [`SecretOperation::Delete`].
    pub delete: bool,
    /// Trigger backend-side rotation. Maps to [`SecretOperation::Rotate`].
    pub rotate: bool,
    /// Read historical versions. Maps to [`SecretOperation::GetVersion`]
    /// — note the (Capabilities-side plural × trait-side singular)
    /// disagreement that [`SecretOperation`] reconciles structurally.
    pub versions: bool,
}

impl Capabilities {
    /// Read-only capability set (get only). Used by CLI/shell backends
    /// that only invoke a read command.
    #[must_use]
    pub const fn read_only() -> Self {
        Self {
            get: true,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        }
    }

    /// Full read+write capability set. Used by native HTTP backends
    /// with complete API coverage (Akeyless, AWS, Vault, GCP).
    #[must_use]
    pub const fn full() -> Self {
        Self {
            get: true,
            list: true,
            put: true,
            delete: true,
            rotate: true,
            versions: true,
        }
    }

    /// Whether this capability set advertises `op` — the typed
    /// projection from [`SecretOperation`] onto the matching boolean
    /// field.
    ///
    /// One source of truth for the (operation × capability) dispatch
    /// surface. Mirrors [`SecretOperation::is_supported_by`] in the
    /// dual direction; both methods delegate to the same arm by
    /// symmetry. Dispatch-side consumers (a `daemon.has_write_access()`
    /// gate that checks `caps.supports(SecretOperation::Put)` rather
    /// than `caps.put`, a per-operation reject-counter keyed by
    /// [`SecretOperation`]) read the capability through one projection
    /// instead of re-deriving the six boolean reads inline.
    #[must_use]
    pub const fn supports(self, op: SecretOperation) -> bool {
        op.is_supported_by(self)
    }
}

/// Closed-axis primitive over the shikumi-provided [`SecretClient`]
/// implementor universe — the seven runtime clients shikumi ships, with
/// each variant pinned pointwise to the matching impl's
/// [`SecretClient::backend_name`]: [`MemClient`] → [`Self::Mem`]
/// (in-memory test scaffold, label `"mem"`), [`CommandClient`] →
/// [`Self::Command`] (shell-subprocess `get` shim, label `"command"`),
/// `AkeylessClient` → [`Self::Akeyless`] (native HTTP, Akeyless gateway,
/// label `"akeyless"`), `AwsClient` → [`Self::AwsSecretsManager`] (AWS
/// Secrets Manager SDK, label `"aws-secrets-manager"`), `OpConnectClient`
/// → [`Self::OpConnect`] (1Password Connect HTTP, label `"op-connect"`),
/// `VaultClient` → [`Self::Vault`] (`HashiCorp` Vault KV v2 HTTP, label
/// `"vault"`), `GcpSecretClient` → [`Self::GcpSecretManager`] (GCP Secret
/// Manager SDK, label `"gcp-secret-manager"`).
///
/// Distinct universe from [`SecretBackendKind`] on the secret-axis
/// primitive set: that primitive partitions the [`crate::secret::SecretBackend`]
/// variant space (what a YAML config author writes —
/// `literal`/`command`/`op`/`sops`/`akeyless`/`vault`/`aws_secret`/`gcp_secret`),
/// while this primitive partitions the [`SecretClient`] implementor
/// space (what the daemon dispatches against at runtime). The two
/// surfaces overlap (every [`SecretClient`] impl resolves _some_
/// [`crate::secret::SecretBackend`]-shaped value) but are not in
/// bijection: [`Self::Mem`] (test scaffold) has no [`crate::secret::SecretBackend`]
/// peer, [`Self::OpConnect`] is a distinct HTTP transport from
/// [`SecretBackendKind::Op`] (which dispatches the `op` CLI), and the
/// SOPS backend ([`SecretBackendKind::Sops`]) has no [`SecretClient`]
/// peer (resolved via [`crate::secret::resolve_sops_file`] /
/// [`crate::secret::resolve_sops_field`] directly). The label strings
/// likewise diverge — `SecretBackendKind` follows
/// [`crate::secret::SecretBackend`]'s `#[serde(rename_all =
/// "snake_case")]` (`"aws_secret"`, `"gcp_secret"`), while
/// `SecretClientKind` mirrors the runtime client's `backend_name()`
/// kebab-case (`"aws-secrets-manager"`, `"gcp-secret-manager"`,
/// `"op-connect"`).
///
/// Before this lift, [`SecretClient::backend_name`] was an open
/// `&'static str` axis: each impl returned a hand-picked label with no
/// type-level pin that distinct impls picked distinct labels, no closed
/// enumeration for per-client dispatch (telemetry recording the client
/// mix of resolved secrets, per-client retry policies, attestation
/// manifests recording the client histogram of refusals, CLI flag
/// values listing the filterable client set, structured-diagnostic
/// legends naming the failing client by typed primitive across thread
/// boundaries), and no structural agreement between the
/// [`SecretError::Unsupported`] `backend` field's string and any typed
/// classification. Lifting the universe to one closed enum closes the
/// runtime-client axis structurally: every shikumi-shipped impl's
/// [`SecretClient::backend_name`] maps to exactly one [`SecretClientKind`]
/// variant through the default [`SecretClient::client_kind`] projection,
/// and the canonical labels live at one site
/// ([`SecretClientKind::as_str`]) instead of being re-stated as a
/// magic-string `&'static str` literal in every `impl SecretClient
/// for X { fn backend_name(&self) -> &'static str { "x" } }` arm.
///
/// Peer of [`SecretBackendKind`] (config-author backend axis),
/// [`SecretErrorKind`] (error-variant axis), [`SecretOperation`]
/// (cross-surface operation axis), and the other closed-enum kind
/// primitives ([`crate::ConfigSourceKind`] on the layer axis,
/// [`crate::FigmentSourceKind`] / [`crate::FigmentNameTagKind`] on the
/// figment-`Metadata::{source, name}` axes): same typescape discipline
/// (closed, allocation-free, `Copy + Eq + Hash + #[non_exhaustive]`,
/// canonical operator-facing label), applied to the secret-client
/// runtime-implementor axis.
///
/// `'static` and allocation-free, suitable for crossing thread
/// boundaries — observable on a captured [`SecretError`] envelope
/// without retaining the borrowed [`SecretClient`] reference that
/// produced it.
///
/// Adding a future [`SecretClient`] implementor on the shikumi side
/// (e.g. a `KubernetesSecretClient` for in-cluster `Secret` resources,
/// a `KeychainClient` for the macOS Keychain) means adding one
/// [`SecretClientKind`] variant in lockstep with the
/// `impl SecretClient for X` declaration; the default
/// [`SecretClient::client_kind`] derivation projects through
/// [`crate::ClosedAxisLabel::from_canonical_str`], so the new impl's
/// `backend_name()` string lands at one place
/// ([`SecretClientKind::as_str`]) and the typed projection follows
/// automatically. External implementors (out-of-crate consumers writing
/// their own [`SecretClient`]) get [`None`] from the default
/// [`SecretClient::client_kind`] — the closed axis covers the
/// shikumi-shipped universe only and explicitly does not claim to
/// cover every possible implementor.
///
/// `Ord` / `PartialOrd` are declaration-order lex over [`Self::ALL`]
/// (`Mem < Command < Akeyless < AwsSecretsManager < OpConnect < Vault
/// < GcpSecretManager`): a `BTreeMap<SecretClientKind, T>` keyed on
/// the runtime-client kind (per-client request-rate histograms,
/// per-client latency dashboards, attestation manifests recording
/// the client-mix histogram of resolved secrets, structured-
/// diagnostic legends bucketing per-client counters in declaration
/// order) emits rows in that order deterministically without a hand-
/// rolled comparator at the renderer. Idiom-peer of the same derive
/// on [`crate::SecretBackendKind`] (commit `9b1da86`),
/// [`crate::SecretRefShape`] (commit `8a84bb6`),
/// [`crate::DiffLineKind`] (commit `c403e1a`),
/// [`crate::WatchEventClass`] (commit `94f8a8b`),
/// [`crate::EnvMetadataTagKind`] (commit `b556b75`),
/// [`crate::FigmentNameTagKind`] (commit `64a47e7`),
/// [`crate::FigmentSourceKind`] (commit `5df265c`), and
/// [`crate::ConfigSourceKind`] (commit `e0b96d1`) lifted onto the
/// runtime-client axis closed-enum.
///
/// [`SecretBackendKind`]: crate::secret::SecretBackendKind
/// [`SecretBackendKind::Op`]: crate::secret::SecretBackendKind::Op
/// [`SecretBackendKind::Sops`]: crate::secret::SecretBackendKind::Sops
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SecretClientKind {
    /// Maps to [`MemClient`] — the thread-safe in-memory test scaffold.
    /// [`SecretClient::backend_name`] returns `"mem"`.
    Mem,
    /// Maps to [`CommandClient`] — the shell-subprocess `get` shim.
    /// [`SecretClient::backend_name`] returns `"command"`.
    Command,
    /// Maps to `AkeylessClient` (feature `akeyless-native`) — native HTTP
    /// against an Akeyless gateway. [`SecretClient::backend_name`]
    /// returns `"akeyless"`. Coincides with [`SecretBackendKind::Akeyless`]'s
    /// label since the runtime client matches the config-author backend
    /// 1:1 on this axis.
    Akeyless,
    /// Maps to `AwsClient` (feature `aws-native`) — native AWS Secrets
    /// Manager SDK. [`SecretClient::backend_name`] returns
    /// `"aws-secrets-manager"`. Distinct from [`SecretBackendKind::AwsSecret`]'s
    /// `"aws_secret"` label by typescape design: the runtime client
    /// labels its transport (`"aws-secrets-manager"`, naming the AWS
    /// service) while the config-author backend labels its YAML key
    /// (`"aws_secret"`, the `#[serde(rename_all = "snake_case")]` tag).
    AwsSecretsManager,
    /// Maps to `OpConnectClient` (feature `op-native`) — 1Password
    /// Connect HTTP transport. [`SecretClient::backend_name`] returns
    /// `"op-connect"`. Distinct from [`SecretBackendKind::Op`]'s `"op"`
    /// label: that backend dispatches the `op` CLI, this client talks
    /// HTTP to a 1Password Connect server (different transport, same
    /// upstream 1Password vault).
    OpConnect,
    /// Maps to `VaultClient` (feature `vault-native`) — `HashiCorp` Vault
    /// KV v2 HTTP transport. [`SecretClient::backend_name`] returns
    /// `"vault"`. Coincides with [`SecretBackendKind::Vault`]'s label
    /// since the runtime client matches the config-author backend 1:1
    /// on this axis.
    Vault,
    /// Maps to `GcpSecretClient` (feature `gcp-native`) — native GCP
    /// Secret Manager SDK. [`SecretClient::backend_name`] returns
    /// `"gcp-secret-manager"`. Distinct from [`SecretBackendKind::GcpSecret`]'s
    /// `"gcp_secret"` label (same reasoning as the
    /// [`Self::AwsSecretsManager`] / [`SecretBackendKind::AwsSecret`]
    /// pair).
    GcpSecretManager,
}

impl SecretClientKind {
    /// Every [`SecretClientKind`] variant, in declaration order
    /// ([`Self::Mem`], [`Self::Command`], [`Self::Akeyless`],
    /// [`Self::AwsSecretsManager`], [`Self::OpConnect`], [`Self::Vault`],
    /// [`Self::GcpSecretManager`]).
    ///
    /// The closed list of shikumi-shipped [`SecretClient`] impls. Iterate
    /// to enumerate the runtime-client space without listing variants by
    /// hand at every consumer site — e.g. dashboards initializing per-
    /// client telemetry counters, attestation manifests recording the
    /// client-mix histogram of resolved secrets, CLI flag values listing
    /// the filterable client set, partition-coverage tests asserting
    /// disjointness across the runtime-client classification.
    ///
    /// One source of truth for the runtime-client enumeration on the
    /// [`SecretClientKind`] axis: peer to [`SecretBackendKind::ALL`] on
    /// the config-author backend axis, [`SecretErrorKind::ALL`] on the
    /// error-variant axis, [`SecretOperation::ALL`] on the operation
    /// axis, and the other closed-enum kind primitives — same typescape
    /// discipline applied to the runtime [`SecretClient`] implementor
    /// axis.
    ///
    /// Adding a new variant to [`Self`] (in lockstep with a new
    /// shikumi-shipped `impl SecretClient`) means extending this slice
    /// in lockstep with the variant itself. The compiler enforces nothing
    /// here directly, so the
    /// `secret_client_kind_all_covers_every_variant` test pins the
    /// contract via the `Self::ALL.iter().copied()` round-trip with the
    /// closed enum's variant set, and the
    /// `secret_client_kind_all_has_no_duplicates` test pins that the
    /// constant is a set (no double-listed variant).
    ///
    /// [`SecretBackendKind`]: crate::secret::SecretBackendKind
    pub const ALL: &'static [Self] = &[
        Self::Mem,
        Self::Command,
        Self::Akeyless,
        Self::AwsSecretsManager,
        Self::OpConnect,
        Self::Vault,
        Self::GcpSecretManager,
    ];

    /// Canonical operator-facing name of the runtime client — pinned
    /// pointwise to each [`SecretClient`] impl's
    /// [`SecretClient::backend_name`] return string: `"mem"`,
    /// `"command"`, `"akeyless"`, `"aws-secrets-manager"`,
    /// `"op-connect"`, `"vault"`, `"gcp-secret-manager"`.
    ///
    /// Single source of truth for the seven runtime backend-name strings
    /// that previously lived inline as magic-string literals at each
    /// `impl SecretClient for X { fn backend_name(&self) -> &'static str
    /// { "x" } }` arm. Inherent mirror of the
    /// [`crate::ClosedAxisLabel`] trait method; the trait impl delegates
    /// here so the canonical names live at one site instead of being
    /// re-stated at every operator-facing surface (a future structured-
    /// log field naming the failing client by typed primitive, a CLI
    /// flag filtering captured failures by client, an alerting bucket
    /// histogramming the client partition over the captured-failure
    /// surface, an attestation manifest recording the client histogram).
    ///
    /// The label space is heterogeneous on the kebab-case axis by
    /// runtime-transport design — `"aws-secrets-manager"`,
    /// `"op-connect"`, `"gcp-secret-manager"` are kebab-cased to name
    /// the specific transport (AWS Secrets Manager SDK, 1Password
    /// Connect HTTP, GCP Secret Manager SDK), while `"mem"`,
    /// `"command"`, `"akeyless"`, `"vault"` are single-word lowercase
    /// matching the typescape's other single-word kind labels
    /// ([`crate::ConfigSourceKind::as_str`], [`SecretOperation::as_str`]).
    /// Within an axis, the trait-uniform distinctness law
    /// (`closed_axis_label_as_str_distinct_for_every_implementor`) pins
    /// pairwise distinctness; cross-axis label coincidence
    /// ([`Self::Akeyless`] / [`SecretBackendKind::Akeyless`] both
    /// labeled `"akeyless"`, [`Self::Vault`] / [`SecretBackendKind::Vault`]
    /// both labeled `"vault"`) is structural and intentional — the
    /// runtime client and the config-author backend agree on the YAML
    /// key at the resolution boundary.
    ///
    /// Pairs with [`crate::ClosedAxisLabel::from_canonical_str`] via the
    /// trait-default linear-scan parse; the round-trip law
    /// `Self::from_canonical_str(v.as_str()) == Some(v)` holds for every
    /// variant uniformly through the trait-uniform
    /// `closed_axis_label_round_trips_for_every_implementor` test in
    /// `cube::tests`. The concrete-position pin at
    /// `secret_client_kind_as_str_yields_canonical_names` holds the
    /// literal strings stable so a future rename (e.g. shortening
    /// `"aws-secrets-manager"` to `"aws"`, expanding `"mem"` to
    /// `"in-memory"`) fails at that site before drifting through the
    /// round-trip law and the per-impl `backend_name()` pins.
    ///
    /// [`SecretBackendKind`]: crate::secret::SecretBackendKind
    /// [`SecretBackendKind::Akeyless`]: crate::secret::SecretBackendKind::Akeyless
    /// [`SecretBackendKind::Vault`]: crate::secret::SecretBackendKind::Vault
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mem => "mem",
            Self::Command => "command",
            Self::Akeyless => "akeyless",
            Self::AwsSecretsManager => "aws-secrets-manager",
            Self::OpConnect => "op-connect",
            Self::Vault => "vault",
            Self::GcpSecretManager => "gcp-secret-manager",
        }
    }
}

impl crate::ClosedAxis for SecretClientKind {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for SecretClientKind {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

impl fmt::Display for SecretClientKind {
    /// Write the canonical operator-facing label [`Self::as_str`]
    /// returns (`"mem"` / `"command"` / `"akeyless"` /
    /// `"aws-secrets-manager"` / `"op-connect"` / `"vault"` /
    /// `"gcp-secret-manager"`) — the same scalar
    /// [`<Self as serde::Serialize>::serialize`] emits and the same
    /// scalar [`<Self as std::str::FromStr>::from_str`] accepts.
    /// Idiom-peer of the `Display` impl on
    /// [`crate::SecretBackendKind`] (commit `9b1da86`),
    /// [`crate::SecretRefShape`] (commit `8a84bb6`),
    /// [`crate::DiffLineKind`] (commit `c403e1a`),
    /// [`crate::WatchEventClass`] (commit `94f8a8b`),
    /// [`crate::EnvMetadataTagKind`] (commit `b556b75`),
    /// [`crate::FigmentNameTagKind`] (commit `64a47e7`),
    /// [`crate::FigmentSourceKind`] (commit `5df265c`), and
    /// [`crate::ConfigSourceKind`] (commit `e0b96d1`) lifted onto the
    /// runtime-client axis sibling closed-enum.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SecretClientKind {
    type Err = ShikumiError;

    /// Parse the canonical operator-facing label (`"mem"` /
    /// `"command"` / `"akeyless"` / `"aws-secrets-manager"` /
    /// `"op-connect"` / `"vault"` / `"gcp-secret-manager"`) produced
    /// by [`Self::as_str`]; case-insensitive over ASCII via the
    /// trait-default
    /// [`<Self as crate::ClosedAxisLabel>::from_canonical_str`] parse.
    /// On unrecognized input, returns [`ShikumiError::Parse`] with the
    /// offending label embedded verbatim — matching the
    /// verbatim-substring rejection discipline already established by
    /// [`<crate::SecretBackendKind as FromStr>::from_str`]
    /// (commit `9b1da86`),
    /// [`<crate::SecretRefShape as FromStr>::from_str`]
    /// (commit `8a84bb6`),
    /// [`<crate::DiffLineKind as FromStr>::from_str`]
    /// (commit `c403e1a`),
    /// [`<crate::WatchEventClass as FromStr>::from_str`]
    /// (commit `94f8a8b`),
    /// [`<crate::EnvMetadataTagKind as FromStr>::from_str`]
    /// (commit `b556b75`),
    /// [`<crate::FigmentNameTagKind as FromStr>::from_str`]
    /// (commit `64a47e7`),
    /// [`<crate::FigmentSourceKind as FromStr>::from_str`]
    /// (commit `5df265c`), and
    /// [`<crate::ConfigSourceKind as FromStr>::from_str`]
    /// (commit `e0b96d1`) so the same localization story (the operator
    /// sees the offending substring in the rendered diagnostic)
    /// carries to the runtime-client axis kind.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <Self as crate::ClosedAxisLabel>::from_canonical_str(s)
            .ok_or_else(|| ShikumiError::Parse(format!("unknown secret client kind: {s}")))
    }
}

impl serde::Serialize for SecretClientKind {
    /// Serialize the runtime-client axis kind as the canonical
    /// operator-facing label [`Self::as_str`] returns — the same
    /// scalar the [`fmt::Display`] impl writes. Routes through
    /// [`serde::Serializer::collect_str`] so the serialized
    /// representation is exactly `format!("{self}")` with no
    /// intermediate allocation.
    ///
    /// Closes the canonical (`Serialize`, `Deserialize`) serde
    /// idiom-peer of the (`Display`, [`std::str::FromStr`]) stdlib
    /// pair on the runtime-client axis kind primitive. A kind emitted
    /// into a YAML attestation manifest field, a JSON observability
    /// payload, or any consumer struct holding a [`SecretClientKind`]
    /// field under `#[derive(Serialize, Deserialize)]` round-trips
    /// through the canonical label without a consumer-side rename
    /// helper.
    ///
    /// **Round-trip law** — for every `k: SecretClientKind`,
    /// `serde_yaml::from_str::<SecretClientKind>(&serde_yaml::to_string(&k)?)? == k`
    /// and the same on `serde_json`. Pinned by
    /// [`tests::secret_client_kind_serde_yaml_round_trips_over_every_variant`]
    /// and
    /// [`tests::secret_client_kind_serde_json_round_trips_over_every_variant`].
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for SecretClientKind {
    /// Deserialize the runtime-client axis kind from the canonical
    /// operator-facing label [`Self::as_str`] returns via
    /// [`serde::Deserializer::deserialize_str`] with a visitor whose
    /// `visit_str` lowers to [`<Self as FromStr>::from_str`] and
    /// routes any [`ShikumiError`] through
    /// [`serde::de::Error::custom`].
    ///
    /// **Case insensitivity inherits from [`FromStr`]** — the
    /// [`crate::ClosedAxisLabel::from_canonical_str`] trait default
    /// uses [`str::eq_ignore_ascii_case`] over [`Self::ALL`], so
    /// uppercase or mixed-case scalars (e.g. `MEM`, `Aws-Secrets-Manager`)
    /// parse pointwise. Pinned by
    /// [`tests::secret_client_kind_serde_yaml_is_case_insensitive`].
    ///
    /// **Unknown-kind rejection carries the offending label verbatim**
    /// — a manifest field carrying an unrecognized kind surfaces at
    /// the serde error site with the offending substring verbatim in
    /// the rendered message, lifted through [`ShikumiError::Parse`]'s
    /// `Display` impl. Pinned by
    /// [`tests::secret_client_kind_serde_yaml_unknown_kind_error_carries_label_verbatim`].
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretClientKindVisitor;

        impl serde::de::Visitor<'_> for SecretClientKindVisitor {
            type Value = SecretClientKind;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a canonical SecretClientKind label \
                     (`mem`, `command`, `akeyless`, `aws-secrets-manager`, \
                     `op-connect`, `vault`, `gcp-secret-manager`; case-insensitive)",
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<SecretClientKind, E> {
                v.parse::<SecretClientKind>().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(SecretClientKindVisitor)
    }
}

/// Metadata attached to a secret value.
///
/// Not all backends populate every field — `None` means the backend
/// didn't surface it, not that it's absent in the store.
#[derive(Debug, Clone, Default)]
pub struct SecretMetadata {
    /// Opaque version identifier (Vault ver number, GCP version name,
    /// AWS VersionId, etc.). Callers shouldn't parse this.
    pub version: Option<String>,
    /// When the secret was last written (RFC 3339 string to stay
    /// dep-free for now).
    pub updated_at: Option<String>,
    /// Backend-specific tags (AWS Tags, Akeyless tags, Vault custom
    /// metadata, 1Password field names).
    pub tags: HashMap<String, String>,
}

/// A secret value plus its metadata.
#[derive(Debug, Clone)]
pub struct Secret {
    pub value: String,
    pub metadata: SecretMetadata,
}

/// Unified client trait — the abstraction consumers code against.
///
/// Object-safe (`&self` methods, no generics on the trait). All methods
/// are `async` and the trait uses `async_trait` for object safety in
/// Rust's current state.
///
/// Default impls return [`SecretError::Unsupported`] for operations
/// the backend doesn't advertise in [`Self::capabilities`]. Impls
/// override only the operations they support.
#[async_trait]
pub trait SecretClient: Send + Sync {
    /// Human-readable backend name for diagnostics and logging.
    fn backend_name(&self) -> &'static str;

    /// Which operations this backend supports.
    fn capabilities(&self) -> Capabilities;

    /// Typed closed-axis classification of this client's runtime backend
    /// — [`Some`] for the seven shikumi-shipped impls (whose
    /// [`Self::backend_name`] strings are pinned pointwise on
    /// [`SecretClientKind::as_str`]), [`None`] for external implementors
    /// whose [`Self::backend_name`] doesn't match any canonical label
    /// on the [`SecretClientKind`] axis.
    ///
    /// Default impl derives the typed kind from [`Self::backend_name`]
    /// via [`SecretClientKind::from_canonical_str`] (the trait-default
    /// case-insensitive linear-scan parse over [`SecretClientKind::ALL`]),
    /// so every shikumi-shipped impl projects automatically without
    /// touching the impl body: [`MemClient`]'s `"mem"` resolves to
    /// [`Some(SecretClientKind::Mem)`], `AkeylessClient`'s `"akeyless"`
    /// resolves to [`Some(SecretClientKind::Akeyless)`], and so on for
    /// all seven. External implementors with custom backend-name strings
    /// outside the closed axis receive [`None`] from the default — the
    /// trait does not claim to classify implementors it doesn't ship.
    ///
    /// Consumers reading the typed projection (per-client telemetry
    /// dispatching off [`SecretClientKind`], structured-diagnostic
    /// legends naming the failing client by typed primitive across
    /// thread boundaries, attestation manifests recording the client
    /// histogram of refusals, CLI flag values listing the filterable
    /// client set, cross-thread observable forms that need a `'static`
    /// classification surviving the borrow on the live [`SecretClient`])
    /// route through this projection instead of re-deriving the
    /// classification by string-comparing [`Self::backend_name`] at every
    /// observation site. The closed-enum return value composes further
    /// (it's `Copy + Eq + Hash + 'static`), where the raw
    /// `&'static str` does not.
    ///
    /// Pairs with [`Self::backend_name`] under the structural law
    /// `self.client_kind().map(SecretClientKind::as_str) == Some(self.backend_name())`
    /// for every shikumi-shipped impl — pinned by
    /// `secret_client_kind_default_client_kind_recovers_backend_name_pointwise`
    /// in the per-impl test surface for every always-available impl
    /// ([`MemClient`], [`CommandClient`]) and per-feature for the
    /// gated impls. External impls satisfy
    /// `self.client_kind().is_none()` until they opt into the typed
    /// axis by overriding this method directly.
    fn client_kind(&self) -> Option<SecretClientKind> {
        <SecretClientKind as crate::ClosedAxisLabel>::from_canonical_str(self.backend_name())
    }

    /// Fetch the current secret value.
    async fn get(&self, name: &str) -> Result<String, SecretError>;

    /// Fetch the current secret value + metadata.
    ///
    /// Default: calls `get()` and returns empty metadata. Override for
    /// backends that surface version / tag / timestamp info.
    async fn get_with_metadata(&self, name: &str) -> Result<Secret, SecretError> {
        let value = self.get(name).await?;
        Ok(Secret {
            value,
            metadata: SecretMetadata::default(),
        })
    }

    /// List secret names, optionally filtered by prefix.
    async fn list(&self, _prefix: Option<&str>) -> Result<Vec<String>, SecretError> {
        Err(SecretError::unsupported(
            self.backend_name(),
            SecretOperation::List,
        ))
    }

    /// Create or update a secret.
    async fn put(&self, _name: &str, _value: &str) -> Result<(), SecretError> {
        Err(SecretError::unsupported(
            self.backend_name(),
            SecretOperation::Put,
        ))
    }

    /// Delete a secret.
    async fn delete(&self, _name: &str) -> Result<(), SecretError> {
        Err(SecretError::unsupported(
            self.backend_name(),
            SecretOperation::Delete,
        ))
    }

    /// Trigger backend-side rotation (re-derives the value; details are
    /// backend-specific).
    async fn rotate(&self, _name: &str) -> Result<(), SecretError> {
        Err(SecretError::unsupported(
            self.backend_name(),
            SecretOperation::Rotate,
        ))
    }

    /// Fetch a specific historical version of the secret.
    async fn get_version(&self, _name: &str, _version: &str) -> Result<String, SecretError> {
        Err(SecretError::unsupported(
            self.backend_name(),
            SecretOperation::GetVersion,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────
// MemClient — in-memory backend for testing + dev defaults
// ─────────────────────────────────────────────────────────────────────

/// Thread-safe in-memory `SecretClient`. Useful for tests and for
/// seeding dev secrets without hitting a real vault.
///
/// Backed by a `RwLock<HashMap>` so reads don't contend. Version
/// history is kept per-name: each write appends; `rotate` also
/// appends a new generated value. Versions are numbered starting at 1.
pub struct MemClient {
    store: RwLock<HashMap<String, Vec<String>>>,
}

impl MemClient {
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }

    /// Seed the client with an initial set of secrets. Convenient for
    /// test fixtures and dev defaults. Each seed value becomes version 1.
    #[must_use]
    pub fn with_seed<I, K, V>(iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let client = Self::new();
        for (k, v) in iter {
            client
                .store
                .write()
                .expect("MemClient lock poisoned")
                .insert(k.into(), vec![v.into()]);
        }
        client
    }
}

impl Default for MemClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretClient for MemClient {
    fn backend_name(&self) -> &'static str {
        "mem"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::full()
    }

    async fn get(&self, name: &str) -> Result<String, SecretError> {
        let store = self.store.read().expect("MemClient lock poisoned");
        store
            .get(name)
            .and_then(|versions| versions.last().cloned())
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })
    }

    async fn get_with_metadata(&self, name: &str) -> Result<Secret, SecretError> {
        let store = self.store.read().expect("MemClient lock poisoned");
        let versions = store.get(name).ok_or_else(|| SecretError::NotFound {
            name: name.to_owned(),
        })?;
        let value = versions
            .last()
            .cloned()
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })?;
        let metadata = SecretMetadata {
            version: Some(versions.len().to_string()),
            updated_at: None,
            tags: HashMap::new(),
        };
        Ok(Secret { value, metadata })
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, SecretError> {
        let store = self.store.read().expect("MemClient lock poisoned");
        let mut names: Vec<String> = store
            .keys()
            .filter(|k| prefix.is_none_or(|p| k.starts_with(p)))
            .cloned()
            .collect();
        names.sort();
        Ok(names)
    }

    async fn put(&self, name: &str, value: &str) -> Result<(), SecretError> {
        self.store
            .write()
            .expect("MemClient lock poisoned")
            .entry(name.to_owned())
            .or_default()
            .push(value.to_owned());
        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<(), SecretError> {
        let removed = self
            .store
            .write()
            .expect("MemClient lock poisoned")
            .remove(name);
        if removed.is_some() {
            Ok(())
        } else {
            Err(SecretError::NotFound {
                name: name.to_owned(),
            })
        }
    }

    async fn rotate(&self, name: &str) -> Result<(), SecretError> {
        // Rotation semantics for an in-memory client: append a
        // deterministic-ish new value derived from the current version
        // count. Real vaults delegate rotation to a producer; this is
        // a test/dev scaffold so callers can exercise the code path.
        let mut store = self.store.write().expect("MemClient lock poisoned");
        let versions = store.get_mut(name).ok_or_else(|| SecretError::NotFound {
            name: name.to_owned(),
        })?;
        let next = format!("rotated-v{}-{name}", versions.len() + 1);
        versions.push(next);
        Ok(())
    }

    async fn get_version(&self, name: &str, version: &str) -> Result<String, SecretError> {
        let n: usize = version.parse().map_err(|_| {
            SecretError::Backend(format!("mem version must be an integer, got {version:?}"))
        })?;
        if n == 0 {
            return Err(SecretError::Backend(
                "mem versions are 1-indexed; 0 is invalid".into(),
            ));
        }
        let store = self.store.read().expect("MemClient lock poisoned");
        let versions = store.get(name).ok_or_else(|| SecretError::NotFound {
            name: name.to_owned(),
        })?;
        versions.get(n - 1).cloned().ok_or_else(|| {
            SecretError::Backend(format!(
                "mem has {} versions for {name}, version {n} out of range",
                versions.len()
            ))
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
// CommandClient — CLI-shelling backend for "anything else"
// ─────────────────────────────────────────────────────────────────────

/// `SecretClient` backed by shell commands. Each name is looked up by
/// running a per-key template command via [`crate::secret::resolve_command`].
///
/// Two configurations:
///
/// - `with_get_template`: a single template string with `{name}` placeholder
///   substituted in per `get()` call. Example: `"op read 'op://vault/{name}/field'"`.
/// - `with_name_map`: an explicit `HashMap<name, command>` for when each
///   secret has a unique CLI invocation.
///
/// Read-only — `list`/`put`/`delete` return `Unsupported`. Consumers
/// needing write access compose this with [`MemClient`] for
/// test-double scenarios or switch to a native backend.
pub struct CommandClient {
    template: Option<String>,
    name_map: HashMap<String, String>,
}

impl CommandClient {
    /// Build with a single template: `get(name)` runs the template
    /// with `{name}` replaced.
    #[must_use]
    pub fn with_get_template(template: impl Into<String>) -> Self {
        Self {
            template: Some(template.into()),
            name_map: HashMap::new(),
        }
    }

    /// Build with an explicit name-to-command mapping.
    #[must_use]
    pub fn with_name_map<I, K, V>(iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            template: None,
            name_map: iter
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }
}

#[async_trait]
impl SecretClient for CommandClient {
    fn backend_name(&self) -> &'static str {
        "command"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::read_only()
    }

    async fn get(&self, name: &str) -> Result<String, SecretError> {
        let cmd: String = if let Some(explicit) = self.name_map.get(name) {
            explicit.clone()
        } else if let Some(template) = &self.template {
            template.replace("{name}", name)
        } else {
            return Err(SecretError::NotFound {
                name: name.to_owned(),
            });
        };

        crate::secret::resolve_command(&cmd).map_err(SecretError::from)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Native backend impls (feature-gated)
// ─────────────────────────────────────────────────────────────────────

/// Native Akeyless `SecretClient` — HTTP via the `akeyless-api` SDK.
///
/// Feature-gated on `akeyless-native`. Only `get` is implemented at
/// present; `list`/`put`/`delete`/`rotate` will land as follow-ups that
/// wire the corresponding Akeyless API endpoints (list-items,
/// create-secret, delete-item, rotate-secret).
#[cfg(feature = "akeyless-native")]
pub struct AkeylessClient {
    auth: crate::secret::AkeylessAuth,
}

#[cfg(feature = "akeyless-native")]
impl AkeylessClient {
    #[must_use]
    pub fn new(auth: crate::secret::AkeylessAuth) -> Self {
        Self { auth }
    }

    /// Construct from `AKEYLESS_TOKEN` + `AKEYLESS_GATEWAY_URL` env vars.
    ///
    /// # Errors
    ///
    /// Propagates [`crate::secret::AkeylessAuth::from_env`] errors.
    pub fn from_env() -> Result<Self, SecretError> {
        let auth = crate::secret::AkeylessAuth::from_env()?;
        Ok(Self::new(auth))
    }
}

#[cfg(feature = "akeyless-native")]
#[async_trait]
impl SecretClient for AkeylessClient {
    fn backend_name(&self) -> &'static str {
        "akeyless"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::full()
    }

    async fn get(&self, name: &str) -> Result<String, SecretError> {
        crate::secret::resolve_akeyless_native(&self.auth, name)
            .await
            .map_err(SecretError::from)
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, SecretError> {
        let cfg = self.auth.configuration();
        let request = akeyless_api::models::ListItems {
            token: Some(self.auth.token.clone()),
            path: prefix.map(str::to_owned),
            auto_pagination: Some("enabled".into()),
            ..Default::default()
        };
        let response = akeyless_api::apis::v2_api::list_items(&cfg, request)
            .await
            .map_err(|e| SecretError::Backend(format!("akeyless list-items: {e}")))?;

        let mut names: Vec<String> = response
            .items
            .unwrap_or_default()
            .into_iter()
            .filter_map(|item| item.item_name)
            .collect();
        names.sort();
        Ok(names)
    }

    async fn put(&self, name: &str, value: &str) -> Result<(), SecretError> {
        let cfg = self.auth.configuration();
        // Try update first; fall through to create on ItemNotFound.
        let update = akeyless_api::models::UpdateSecretVal {
            token: Some(self.auth.token.clone()),
            name: name.to_owned(),
            value: value.to_owned(),
            ..Default::default()
        };
        let update_result = akeyless_api::apis::v2_api::update_secret_val(&cfg, update).await;
        match update_result {
            Ok(_) => Ok(()),
            Err(err) => {
                let msg = format!("{err}");
                if msg.contains("ItemNotExist")
                    || msg.contains("not exist")
                    || msg.contains("not found")
                {
                    let create = akeyless_api::models::CreateSecret {
                        token: Some(self.auth.token.clone()),
                        name: name.to_owned(),
                        value: value.to_owned(),
                        ..Default::default()
                    };
                    akeyless_api::apis::v2_api::create_secret(&cfg, create)
                        .await
                        .map_err(|e| {
                            SecretError::Backend(format!("akeyless create-secret({name}): {e}"))
                        })?;
                    Ok(())
                } else {
                    Err(SecretError::Backend(format!(
                        "akeyless update-secret-val({name}): {msg}"
                    )))
                }
            }
        }
    }

    async fn delete(&self, name: &str) -> Result<(), SecretError> {
        let cfg = self.auth.configuration();
        let request = akeyless_api::models::DeleteItem {
            token: Some(self.auth.token.clone()),
            name: name.to_owned(),
            delete_immediately: Some(true),
            ..Default::default()
        };
        akeyless_api::apis::v2_api::delete_item(&cfg, request)
            .await
            .map_err(|e| SecretError::Backend(format!("akeyless delete-item({name}): {e}")))?;
        Ok(())
    }

    async fn rotate(&self, name: &str) -> Result<(), SecretError> {
        let cfg = self.auth.configuration();
        let request = akeyless_api::models::RotateSecret {
            token: Some(self.auth.token.clone()),
            name: name.to_owned(),
            ..Default::default()
        };
        akeyless_api::apis::v2_api::rotate_secret(&cfg, request)
            .await
            .map_err(|e| SecretError::Backend(format!("akeyless rotate-secret({name}): {e}")))?;
        Ok(())
    }

    async fn get_version(&self, name: &str, version: &str) -> Result<String, SecretError> {
        let cfg = self.auth.configuration();
        let version_num: i32 = version.parse().map_err(|_| {
            SecretError::Backend(format!(
                "akeyless version must be an integer, got {version:?}"
            ))
        })?;
        let request = akeyless_api::models::GetSecretValue {
            names: vec![name.to_owned()],
            token: Some(self.auth.token.clone()),
            version: Some(version_num),
            ..Default::default()
        };
        let response = akeyless_api::apis::v2_api::get_secret_value(&cfg, request)
            .await
            .map_err(|e| {
                SecretError::Backend(format!(
                    "akeyless get-secret-value({name}, v={version}): {e}"
                ))
            })?;
        let obj = response.as_object().ok_or_else(|| {
            SecretError::Backend(format!(
                "akeyless response for {name} v{version} was not an object"
            ))
        })?;
        obj.get(name)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| {
                SecretError::Backend(format!(
                    "akeyless response missing value for {name} v{version}"
                ))
            })
    }
}

/// Native AWS Secrets Manager `SecretClient`.
///
/// Feature-gated on `aws-native`. Only `get` is implemented at present;
/// `list`/`put`/`delete`/`rotate`/versions will land as follow-ups that
/// wire the corresponding SDK operations (`ListSecrets`, `CreateSecret`,
/// `DeleteSecret`, `RotateSecret`, `GetSecretValue` with version id).
#[cfg(feature = "aws-native")]
pub struct AwsClient {
    client: aws_sdk_secretsmanager::Client,
}

#[cfg(feature = "aws-native")]
impl AwsClient {
    #[must_use]
    pub fn new(client: aws_sdk_secretsmanager::Client) -> Self {
        Self { client }
    }

    /// Construct with a client built from the default AWS credential
    /// chain. Reads region + creds from env vars, profile files, or
    /// IMDSv2 (EC2) / IRSA (EKS).
    pub async fn from_env() -> Self {
        let client = crate::secret::aws_secretsmanager_client().await;
        Self::new(client)
    }
}

#[cfg(feature = "aws-native")]
#[async_trait]
impl SecretClient for AwsClient {
    fn backend_name(&self) -> &'static str {
        "aws-secrets-manager"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::full()
    }

    async fn get(&self, name: &str) -> Result<String, SecretError> {
        crate::secret::resolve_aws_secret_native(&self.client, name)
            .await
            .map_err(SecretError::from)
    }

    async fn get_with_metadata(&self, name: &str) -> Result<Secret, SecretError> {
        let response = self
            .client
            .get_secret_value()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("aws get-secret-value({name}): {e}")))?;

        let value = response.secret_string().map(str::to_owned).ok_or_else(|| {
            SecretError::Backend(format!(
                "aws secret {name} has no SecretString (binary-only)"
            ))
        })?;

        let mut metadata = SecretMetadata::default();
        if let Some(version) = response.version_id() {
            metadata.version = Some(version.to_owned());
        }
        if let Some(created) = response.created_date() {
            // AWS DateTime → epoch seconds → display. Keeping a
            // chrono-free representation since shikumi doesn't pull
            // chrono as a dep.
            metadata.updated_at = Some(format!("{}", created.secs()));
        }
        if !response.version_stages().is_empty() {
            metadata
                .tags
                .insert("stages".into(), response.version_stages().join(","));
        }
        Ok(Secret { value, metadata })
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, SecretError> {
        let mut names = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_secrets();
            if let Some(t) = &next_token {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| SecretError::Backend(format!("aws list-secrets: {e}")))?;
            for entry in resp.secret_list() {
                if let Some(n) = entry.name() {
                    if prefix.is_none_or(|p| n.starts_with(p)) {
                        names.push(n.to_owned());
                    }
                }
            }
            next_token = resp.next_token().map(str::to_owned);
            if next_token.is_none() {
                break;
            }
        }
        names.sort();
        Ok(names)
    }

    async fn put(&self, name: &str, value: &str) -> Result<(), SecretError> {
        // Try update first; if the secret doesn't exist, create it.
        let update_result = self
            .client
            .put_secret_value()
            .secret_id(name)
            .secret_string(value)
            .send()
            .await;
        match update_result {
            Ok(_) => Ok(()),
            Err(err) => {
                // ResourceNotFoundException → fall through to create.
                let err_str = format!("{err}");
                if err_str.contains("ResourceNotFoundException") || err_str.contains("not found") {
                    self.client
                        .create_secret()
                        .name(name)
                        .secret_string(value)
                        .send()
                        .await
                        .map_err(|e| {
                            SecretError::Backend(format!("aws create-secret({name}): {e}"))
                        })?;
                    Ok(())
                } else {
                    Err(SecretError::Backend(format!(
                        "aws put-secret-value({name}): {err_str}"
                    )))
                }
            }
        }
    }

    async fn delete(&self, name: &str) -> Result<(), SecretError> {
        // ForceDeleteWithoutRecovery=true bypasses the 7-30 day
        // recovery window. Callers that need soft-delete compose their
        // own SDK call.
        self.client
            .delete_secret()
            .secret_id(name)
            .force_delete_without_recovery(true)
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("aws delete-secret({name}): {e}")))?;
        Ok(())
    }

    async fn rotate(&self, name: &str) -> Result<(), SecretError> {
        self.client
            .rotate_secret()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("aws rotate-secret({name}): {e}")))?;
        Ok(())
    }

    async fn get_version(&self, name: &str, version: &str) -> Result<String, SecretError> {
        let response = self
            .client
            .get_secret_value()
            .secret_id(name)
            .version_id(version)
            .send()
            .await
            .map_err(|e| {
                SecretError::Backend(format!("aws get-secret-value({name}, v={version}): {e}"))
            })?;
        response.secret_string().map(str::to_owned).ok_or_else(|| {
            SecretError::Backend(format!("aws secret {name} v{version} has no SecretString"))
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
// OpConnectClient — 1Password Connect via thin reqwest HTTP
// ─────────────────────────────────────────────────────────────────────

/// Native 1Password Connect `SecretClient`.
///
/// Feature-gated on `op-native`. Talks to a 1Password Connect server
/// (self-hosted sync service) over HTTP with a Bearer token. Secrets
/// are modeled as Connect Items; `name` is the item *title*, resolved
/// to a UUID per-call.
///
/// The Connect API is small — 8 endpoints for vault + item CRUD — so
/// this is a hand-written thin client rather than a generated SDK.
/// Rotation and versioning are not supported: 1Password doesn't expose
/// programmatic rotation and item-history retrieval isn't in the
/// Connect API surface.
#[cfg(feature = "op-native")]
pub struct OpConnectClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
    vault_id: String,
}

#[cfg(feature = "op-native")]
#[derive(Debug, Clone)]
pub struct OpConnectConfig {
    /// e.g. `https://connect.example.com` (no trailing slash).
    pub base_url: String,
    /// Bearer token from 1Password Connect server (not a vault API key).
    pub token: String,
    /// Vault UUID. Connect items are scoped to a vault.
    pub vault_id: String,
}

#[cfg(feature = "op-native")]
impl OpConnectClient {
    /// Construct from an explicit config.
    #[must_use]
    pub fn new(config: OpConnectConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: config.base_url.trim_end_matches('/').to_owned(),
            token: config.token,
            vault_id: config.vault_id,
        }
    }

    /// Construct from env: `OP_CONNECT_HOST`, `OP_CONNECT_TOKEN`,
    /// `OP_CONNECT_VAULT`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Unauthorized`] if any required variable is missing.
    pub fn from_env() -> Result<Self, SecretError> {
        let read = |var: &str| {
            std::env::var(var).map_err(|_| SecretError::Unauthorized {
                message: format!("{var} not set"),
            })
        };
        Ok(Self::new(OpConnectConfig {
            base_url: read("OP_CONNECT_HOST")?,
            token: read("OP_CONNECT_TOKEN")?,
            vault_id: read("OP_CONNECT_VAULT")?,
        }))
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// Resolve a human-readable item title to a Connect item UUID.
    async fn resolve_item_id(&self, name: &str) -> Result<String, SecretError> {
        let url = format!(
            "{}/v1/vaults/{}/items?filter=title+eq+%22{}%22",
            self.base_url,
            self.vault_id,
            urlencode(name)
        );
        let response = self
            .http
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("op list items: {e}")))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
        {
            return Err(SecretError::Unauthorized {
                message: format!("op list items: {}", response.status()),
            });
        }
        if !response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "op list items: HTTP {}",
                response.status()
            )));
        }

        let items: Vec<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| SecretError::Backend(format!("op list items parse: {e}")))?;

        items
            .into_iter()
            .find_map(|item| item.get("id").and_then(|v| v.as_str()).map(str::to_owned))
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })
    }

    /// Fetch an item by UUID and return its first `password` / `concealed`
    /// field value.
    async fn fetch_item_value(&self, item_id: &str, name: &str) -> Result<String, SecretError> {
        let url = format!(
            "{}/v1/vaults/{}/items/{}",
            self.base_url, self.vault_id, item_id
        );
        let response = self
            .http
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("op get item({name}): {e}")))?;

        if !response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "op get item({name}): HTTP {}",
                response.status()
            )));
        }

        let item: serde_json::Value = response
            .json()
            .await
            .map_err(|e| SecretError::Backend(format!("op get item({name}) parse: {e}")))?;

        let fields = item
            .get("fields")
            .and_then(|v| v.as_array())
            .ok_or_else(|| SecretError::Backend(format!("op item {name} has no fields array")))?;
        fields
            .iter()
            .find_map(|f| {
                let purpose = f.get("purpose").and_then(|v| v.as_str()).unwrap_or("");
                let kind = f.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if purpose == "PASSWORD" || kind == "CONCEALED" {
                    f.get("value").and_then(|v| v.as_str()).map(str::to_owned)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                SecretError::Backend(format!(
                    "op item {name} has no PASSWORD/CONCEALED field with a value"
                ))
            })
    }
}

#[cfg(feature = "op-native")]
#[async_trait]
impl SecretClient for OpConnectClient {
    fn backend_name(&self) -> &'static str {
        "op-connect"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            get: true,
            list: true,
            put: true,
            delete: true,
            rotate: false,
            versions: false,
        }
    }

    async fn get(&self, name: &str) -> Result<String, SecretError> {
        let id = self.resolve_item_id(name).await?;
        self.fetch_item_value(&id, name).await
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, SecretError> {
        let url = format!("{}/v1/vaults/{}/items", self.base_url, self.vault_id);
        let response = self
            .http
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("op list items: {e}")))?;
        if !response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "op list items: HTTP {}",
                response.status()
            )));
        }
        let items: Vec<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| SecretError::Backend(format!("op list items parse: {e}")))?;

        let mut names: Vec<String> = items
            .into_iter()
            .filter_map(|item| {
                item.get("title")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            })
            .filter(|n| prefix.is_none_or(|p| n.starts_with(p)))
            .collect();
        names.sort();
        Ok(names)
    }

    async fn put(&self, name: &str, value: &str) -> Result<(), SecretError> {
        // Create-or-update: look up by title. If missing, POST to
        // create; else PUT to replace the item body.
        let existing = self.resolve_item_id(name).await;
        let body = serde_json::json!({
            "vault": { "id": self.vault_id },
            "title": name,
            "category": "API_CREDENTIAL",
            "fields": [{
                "id": "credential",
                "label": "credential",
                "type": "CONCEALED",
                "purpose": "PASSWORD",
                "value": value,
            }]
        });
        let response = match existing {
            Ok(id) => {
                let url = format!("{}/v1/vaults/{}/items/{}", self.base_url, self.vault_id, id);
                self.http
                    .put(&url)
                    .header("Authorization", self.auth_header())
                    .json(&body)
                    .send()
                    .await
            }
            Err(SecretError::NotFound { .. }) => {
                let url = format!("{}/v1/vaults/{}/items", self.base_url, self.vault_id);
                self.http
                    .post(&url)
                    .header("Authorization", self.auth_header())
                    .json(&body)
                    .send()
                    .await
            }
            Err(e) => return Err(e),
        }
        .map_err(|e| SecretError::Backend(format!("op put item({name}): {e}")))?;

        if !response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "op put item({name}): HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<(), SecretError> {
        let id = self.resolve_item_id(name).await?;
        let url = format!("{}/v1/vaults/{}/items/{}", self.base_url, self.vault_id, id);
        let response = self
            .http
            .delete(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("op delete item({name}): {e}")))?;
        if !response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "op delete item({name}): HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}

#[cfg(feature = "op-native")]
fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────
// VaultClient — `HashiCorp` Vault KV v2 via thin reqwest HTTP
// ─────────────────────────────────────────────────────────────────────

/// Native `HashiCorp` Vault `SecretClient` — KV v2 engine.
///
/// Feature-gated on `vault-native`. Only KV v2 semantics are covered
/// here: a `mount` (e.g. `"secret"`) + a path. `name` maps to the item
/// path under that mount; the value lookup reads `data.data.value`
/// (single-field convention) unless a nested-object schema is used,
/// in which case the full JSON string is returned.
///
/// Rotation is ⚠️ backend-specific: Vault doesn't rotate KV secrets —
/// rotation is a property of dynamic-secret engines (database, aws,
/// pki). `rotate` here returns `Unsupported`; callers that want
/// dynamic-secret rotation should call the engine-specific API.
#[cfg(feature = "vault-native")]
pub struct VaultClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
    mount: String,
    namespace: Option<String>,
}

#[cfg(feature = "vault-native")]
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Vault URL, e.g. `https://vault.example.com:8200` (no trailing slash).
    pub base_url: String,
    /// Vault auth token (X-Vault-Token header).
    pub token: String,
    /// KV v2 mount path, e.g. `"secret"` or `"kv"`.
    pub mount: String,
    /// Optional Vault Enterprise namespace (X-Vault-Namespace header).
    pub namespace: Option<String>,
}

#[cfg(feature = "vault-native")]
impl VaultClient {
    #[must_use]
    pub fn new(config: VaultConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: config.base_url.trim_end_matches('/').to_owned(),
            token: config.token,
            mount: config.mount.trim_matches('/').to_owned(),
            namespace: config.namespace,
        }
    }

    /// Construct from env: `VAULT_ADDR`, `VAULT_TOKEN`,
    /// `VAULT_KV_MOUNT` (default `"secret"`), `VAULT_NAMESPACE` (optional).
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Unauthorized`] if `VAULT_ADDR` or
    /// `VAULT_TOKEN` is missing.
    pub fn from_env() -> Result<Self, SecretError> {
        let base_url = std::env::var("VAULT_ADDR").map_err(|_| SecretError::Unauthorized {
            message: "VAULT_ADDR not set".into(),
        })?;
        let token = std::env::var("VAULT_TOKEN").map_err(|_| SecretError::Unauthorized {
            message: "VAULT_TOKEN not set".into(),
        })?;
        let mount = std::env::var("VAULT_KV_MOUNT").unwrap_or_else(|_| "secret".into());
        let namespace = std::env::var("VAULT_NAMESPACE").ok();
        Ok(Self::new(VaultConfig {
            base_url,
            token,
            mount,
            namespace,
        }))
    }

    fn apply_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut req = req.header("X-Vault-Token", &self.token);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        req
    }

    fn data_url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}/data/{}",
            self.base_url,
            self.mount,
            path.trim_start_matches('/')
        )
    }

    fn metadata_url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}/metadata/{}",
            self.base_url,
            self.mount,
            path.trim_start_matches('/')
        )
    }

    /// Parse a KV v2 data response: extract `data.data` as the secret body.
    /// If the body has a single `value` field, return that; otherwise
    /// return the whole object serialized as JSON.
    fn extract_value(body: &serde_json::Value, name: &str) -> Result<String, SecretError> {
        let data = body
            .get("data")
            .and_then(|v| v.get("data"))
            .ok_or_else(|| {
                SecretError::Backend(format!("vault response for {name} missing data.data"))
            })?;
        if let Some(obj) = data.as_object() {
            if obj.len() == 1 {
                if let Some(v) = obj.values().next().and_then(|v| v.as_str()) {
                    return Ok(v.to_owned());
                }
            }
        }
        Ok(data.to_string())
    }
}

#[cfg(feature = "vault-native")]
#[async_trait]
impl SecretClient for VaultClient {
    fn backend_name(&self) -> &'static str {
        "vault"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            get: true,
            list: true,
            put: true,
            delete: true,
            rotate: false,
            versions: true,
        }
    }

    async fn get(&self, name: &str) -> Result<String, SecretError> {
        let response = self
            .apply_headers(self.http.get(self.data_url(name)))
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("vault get({name}): {e}")))?;

        match response.status() {
            reqwest::StatusCode::NOT_FOUND => Err(SecretError::NotFound {
                name: name.to_owned(),
            }),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                Err(SecretError::Unauthorized {
                    message: format!("vault get({name}): {}", response.status()),
                })
            }
            status if !status.is_success() => Err(SecretError::Backend(format!(
                "vault get({name}): HTTP {status}"
            ))),
            _ => {
                let body: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| SecretError::Backend(format!("vault get({name}) parse: {e}")))?;
                Self::extract_value(&body, name)
            }
        }
    }

    async fn get_with_metadata(&self, name: &str) -> Result<Secret, SecretError> {
        let response = self
            .apply_headers(self.http.get(self.data_url(name)))
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("vault get({name}): {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError::NotFound {
                name: name.to_owned(),
            });
        }
        if !response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "vault get({name}): HTTP {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| SecretError::Backend(format!("vault get({name}) parse: {e}")))?;
        let value = Self::extract_value(&body, name)?;
        let mut metadata = SecretMetadata::default();
        if let Some(v) = body
            .get("data")
            .and_then(|v| v.get("metadata"))
            .and_then(|m| m.get("version"))
        {
            metadata.version = Some(v.to_string());
        }
        if let Some(t) = body
            .get("data")
            .and_then(|v| v.get("metadata"))
            .and_then(|m| m.get("created_time"))
            .and_then(|v| v.as_str())
        {
            metadata.updated_at = Some(t.to_owned());
        }
        Ok(Secret { value, metadata })
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, SecretError> {
        let path = prefix.unwrap_or("").trim_start_matches('/');
        let url = self.metadata_url(path);
        let response = self
            .apply_headers(
                self.http
                    .request(reqwest::Method::from_bytes(b"LIST").unwrap(), &url),
            )
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("vault list: {e}")))?;

        match response.status() {
            reqwest::StatusCode::NOT_FOUND => Ok(Vec::new()),
            s if !s.is_success() => Err(SecretError::Backend(format!("vault list: HTTP {s}"))),
            _ => {
                let body: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| SecretError::Backend(format!("vault list parse: {e}")))?;
                let keys = body
                    .get("data")
                    .and_then(|v| v.get("keys"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut names: Vec<String> = keys
                    .into_iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .map(|k| {
                        if path.is_empty() {
                            k
                        } else {
                            format!("{}/{}", path.trim_end_matches('/'), k)
                        }
                    })
                    .collect();
                names.sort();
                Ok(names)
            }
        }
    }

    async fn put(&self, name: &str, value: &str) -> Result<(), SecretError> {
        let body = serde_json::json!({ "data": { "value": value } });
        let response = self
            .apply_headers(self.http.post(self.data_url(name)))
            .json(&body)
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("vault put({name}): {e}")))?;
        if !response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "vault put({name}): HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<(), SecretError> {
        // DELETE metadata also removes all versions. For soft-delete
        // (versioned tombstone), callers can target /v1/{mount}/delete/{path}.
        let response = self
            .apply_headers(self.http.delete(self.metadata_url(name)))
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("vault delete({name}): {e}")))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError::NotFound {
                name: name.to_owned(),
            });
        }
        if !response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "vault delete({name}): HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn get_version(&self, name: &str, version: &str) -> Result<String, SecretError> {
        let url = format!("{}?version={}", self.data_url(name), version);
        let response = self
            .apply_headers(self.http.get(&url))
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("vault get({name}, v={version}): {e}")))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError::NotFound {
                name: name.to_owned(),
            });
        }
        if !response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "vault get({name}, v={version}): HTTP {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| SecretError::Backend(format!("vault get parse: {e}")))?;
        Self::extract_value(&body, name)
    }
}

// ─────────────────────────────────────────────────────────────────────
// GcpSecretClient — GCP Secret Manager via thin reqwest HTTP
// ─────────────────────────────────────────────────────────────────────

/// Native GCP Secret Manager `SecretClient`.
///
/// Feature-gated on `gcp-native`. Talks to the Secret Manager REST API
/// v1 with a caller-provided OAuth2 Bearer token. shikumi deliberately
/// does *not* implement ADC / Workload Identity / service-account
/// flows — getting an access token from `gcloud auth print-access-token`
/// or `yup-oauth2` is the caller's responsibility, which keeps the
/// dep tree small (no OpenSSL, no gRPC). Tokens expire after 1 hour;
/// callers should refresh and call [`Self::set_token`] on expiry.
///
/// Secrets are identified by short name (e.g. `"db-password"`). The
/// full resource name is constructed as
/// `projects/{project}/secrets/{name}`.
///
/// Versioning uses GCP's numeric version IDs. `"latest"` is also
/// accepted by `get_version`.
///
/// # Limitations
///
/// - Rotation: GCP Secret Manager doesn't have an API-level rotate
///   action (rotation is a property of the referenced secret version);
///   returns [`SecretError::Unsupported`].
#[cfg(feature = "gcp-native")]
pub struct GcpSecretClient {
    http: reqwest::Client,
    project: String,
    base_url: String,
    token: std::sync::RwLock<String>,
}

#[cfg(feature = "gcp-native")]
#[derive(Debug, Clone)]
pub struct GcpSecretConfig {
    /// GCP project ID (not number). e.g. `"my-project-12345"`.
    pub project: String,
    /// OAuth2 access token with `cloud-platform` scope. Short-lived
    /// (≤1h); caller refreshes via [`GcpSecretClient::set_token`].
    pub token: String,
    /// Override for tests / private API endpoints. Production default
    /// is `https://secretmanager.googleapis.com`.
    pub base_url: Option<String>,
}

#[cfg(feature = "gcp-native")]
impl GcpSecretClient {
    #[must_use]
    pub fn new(config: GcpSecretConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            project: config.project,
            base_url: config
                .base_url
                .unwrap_or_else(|| "https://secretmanager.googleapis.com".into()),
            token: std::sync::RwLock::new(config.token),
        }
    }

    /// Construct from env: `GCP_PROJECT`, `GCLOUD_ACCESS_TOKEN`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Unauthorized`] if either var is unset.
    pub fn from_env() -> Result<Self, SecretError> {
        let project = std::env::var("GCP_PROJECT").map_err(|_| SecretError::Unauthorized {
            message: "GCP_PROJECT not set".into(),
        })?;
        let token =
            std::env::var("GCLOUD_ACCESS_TOKEN").map_err(|_| SecretError::Unauthorized {
                message: "GCLOUD_ACCESS_TOKEN not set (run `gcloud auth print-access-token`)"
                    .into(),
            })?;
        Ok(Self::new(GcpSecretConfig {
            project,
            token,
            base_url: None,
        }))
    }

    /// Rotate the OAuth2 token (GCP access tokens expire in ~1 hour).
    pub fn set_token(&self, token: impl Into<String>) {
        *self
            .token
            .write()
            .expect("GcpSecretClient token lock poisoned") = token.into();
    }

    fn auth_header(&self) -> String {
        let guard = self
            .token
            .read()
            .expect("GcpSecretClient token lock poisoned");
        format!("Bearer {}", *guard)
    }

    fn secret_url(&self, name: &str) -> String {
        format!(
            "{}/v1/projects/{}/secrets/{}",
            self.base_url, self.project, name
        )
    }

    fn access_url(&self, name: &str, version: &str) -> String {
        format!(
            "{}/v1/projects/{}/secrets/{}/versions/{}:access",
            self.base_url, self.project, name, version
        )
    }

    /// Decode the base64-encoded `payload.data` from a Secret Manager
    /// access response. GCP returns payloads as base64 regardless of
    /// whether they're text or binary; callers that expect text still
    /// receive a UTF-8 string here (and get a Parse error if the bytes
    /// aren't valid UTF-8).
    fn decode_payload(body: &serde_json::Value, name: &str) -> Result<String, SecretError> {
        let data_b64 = body
            .get("payload")
            .and_then(|p| p.get("data"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| {
                SecretError::Backend(format!("gcp {name}: response missing payload.data"))
            })?;
        let bytes = base64_decode(data_b64)
            .map_err(|e| SecretError::Backend(format!("gcp {name}: base64 decode: {e}")))?;
        String::from_utf8(bytes)
            .map_err(|e| SecretError::Backend(format!("gcp {name}: non-UTF8 payload: {e}")))
    }
}

#[cfg(feature = "gcp-native")]
#[async_trait]
impl SecretClient for GcpSecretClient {
    fn backend_name(&self) -> &'static str {
        "gcp-secret-manager"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            get: true,
            list: true,
            put: true,
            delete: true,
            rotate: false,
            versions: true,
        }
    }

    async fn get(&self, name: &str) -> Result<String, SecretError> {
        let response = self
            .http
            .get(self.access_url(name, "latest"))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("gcp get({name}): {e}")))?;

        match response.status() {
            reqwest::StatusCode::NOT_FOUND => Err(SecretError::NotFound {
                name: name.to_owned(),
            }),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                Err(SecretError::Unauthorized {
                    message: format!("gcp get({name}): {}", response.status()),
                })
            }
            s if !s.is_success() => Err(SecretError::Backend(format!("gcp get({name}): HTTP {s}"))),
            _ => {
                let body: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| SecretError::Backend(format!("gcp get({name}) parse: {e}")))?;
                Self::decode_payload(&body, name)
            }
        }
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, SecretError> {
        let mut names = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/v1/projects/{}/secrets?pageSize=500",
                self.base_url, self.project
            );
            if let Some(tok) = &page_token {
                url.push_str(&format!("&pageToken={tok}"));
            }
            let response = self
                .http
                .get(&url)
                .header("Authorization", self.auth_header())
                .send()
                .await
                .map_err(|e| SecretError::Backend(format!("gcp list-secrets: {e}")))?;

            if !response.status().is_success() {
                return Err(SecretError::Backend(format!(
                    "gcp list-secrets: HTTP {}",
                    response.status()
                )));
            }
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| SecretError::Backend(format!("gcp list-secrets parse: {e}")))?;

            if let Some(secrets) = body.get("secrets").and_then(|v| v.as_array()) {
                for secret in secrets {
                    if let Some(resource_name) = secret.get("name").and_then(|v| v.as_str()) {
                        // Strip the projects/*/secrets/ prefix to get the short name.
                        if let Some(short) =
                            resource_name.rsplit_once('/').map(|(_, n)| n.to_owned())
                        {
                            if prefix.is_none_or(|p| short.starts_with(p)) {
                                names.push(short);
                            }
                        }
                    }
                }
            }
            page_token = body
                .get("nextPageToken")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            if page_token.is_none() || page_token.as_deref() == Some("") {
                break;
            }
        }
        names.sort();
        Ok(names)
    }

    async fn put(&self, name: &str, value: &str) -> Result<(), SecretError> {
        // Two-step: ensure the secret exists, then add a new version.
        // GCP secrets are container + version; payloads attach to
        // versions, not the secret. If the secret doesn't exist we
        // create it with the automatic replication policy.
        let container_url = self.secret_url(name);
        let get_response = self
            .http
            .get(&container_url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("gcp get-secret({name}): {e}")))?;

        if get_response.status() == reqwest::StatusCode::NOT_FOUND {
            let create_url = format!(
                "{}/v1/projects/{}/secrets?secretId={}",
                self.base_url, self.project, name
            );
            let create_body = serde_json::json!({
                "replication": { "automatic": {} }
            });
            let create_response = self
                .http
                .post(&create_url)
                .header("Authorization", self.auth_header())
                .json(&create_body)
                .send()
                .await
                .map_err(|e| SecretError::Backend(format!("gcp create-secret({name}): {e}")))?;
            if !create_response.status().is_success() {
                return Err(SecretError::Backend(format!(
                    "gcp create-secret({name}): HTTP {}",
                    create_response.status()
                )));
            }
        } else if !get_response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "gcp get-secret({name}): HTTP {}",
                get_response.status()
            )));
        }

        // Add a version with the new payload.
        let add_url = format!("{container_url}:addVersion");
        let payload_b64 = base64_encode(value.as_bytes());
        let add_body = serde_json::json!({
            "payload": { "data": payload_b64 }
        });
        let add_response = self
            .http
            .post(&add_url)
            .header("Authorization", self.auth_header())
            .json(&add_body)
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("gcp add-version({name}): {e}")))?;
        if !add_response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "gcp add-version({name}): HTTP {}",
                add_response.status()
            )));
        }
        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<(), SecretError> {
        let response = self
            .http
            .delete(self.secret_url(name))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("gcp delete-secret({name}): {e}")))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError::NotFound {
                name: name.to_owned(),
            });
        }
        if !response.status().is_success() {
            return Err(SecretError::Backend(format!(
                "gcp delete-secret({name}): HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn get_version(&self, name: &str, version: &str) -> Result<String, SecretError> {
        let response = self
            .http
            .get(self.access_url(name, version))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("gcp get({name}, v={version}): {e}")))?;
        match response.status() {
            reqwest::StatusCode::NOT_FOUND => Err(SecretError::NotFound {
                name: name.to_owned(),
            }),
            s if !s.is_success() => Err(SecretError::Backend(format!(
                "gcp get({name}, v={version}): HTTP {s}"
            ))),
            _ => {
                let body: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| SecretError::Backend(format!("gcp get parse: {e}")))?;
                Self::decode_payload(&body, name)
            }
        }
    }
}

#[cfg(feature = "gcp-native")]
fn base64_encode(bytes: &[u8]) -> String {
    // RFC 4648 section 4 (standard) base64 — GCP Secret Manager uses
    // standard base64 (padded) for the payload.data field.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPHABET[(n & 0x3F) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = u32::from(rem[0]) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

#[cfg(feature = "gcp-native")]
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    // Strict standard base64: A-Z, a-z, 0-9, +, /, =. Whitespace is
    // tolerated (GCP sometimes line-wraps large payloads).
    let mut buf = Vec::with_capacity(s.len() * 3 / 4);
    let mut accum: u32 = 0;
    let mut bits: u32 = 0;
    let mut pad = 0usize;
    for c in s.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = match c {
            'A'..='Z' => (c as u32) - ('A' as u32),
            'a'..='z' => (c as u32) - ('a' as u32) + 26,
            '0'..='9' => (c as u32) - ('0' as u32) + 52,
            '+' => 62,
            '/' => 63,
            '=' => {
                pad += 1;
                continue;
            }
            _ => return Err(format!("invalid base64 char: {c:?}")),
        };
        if pad > 0 {
            return Err("data after padding".into());
        }
        accum = (accum << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((accum >> bits) & 0xFF).unwrap_or_default();
            buf.push(byte);
            accum &= (1 << bits) - 1;
        }
    }
    if bits != 0 && accum != 0 {
        return Err(format!("trailing bits: {bits}"));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mem_client_get_missing_returns_not_found() {
        let client = MemClient::new();
        match client.get("nonexistent").await {
            Err(SecretError::NotFound { name }) => assert_eq!(name, "nonexistent"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mem_client_put_get_roundtrip() {
        let client = MemClient::new();
        client.put("key", "value").await.unwrap();
        assert_eq!(client.get("key").await.unwrap(), "value");
    }

    #[tokio::test]
    async fn mem_client_put_overwrites() {
        let client = MemClient::new();
        client.put("key", "v1").await.unwrap();
        client.put("key", "v2").await.unwrap();
        assert_eq!(client.get("key").await.unwrap(), "v2");
    }

    #[tokio::test]
    async fn mem_client_list_all() {
        let client = MemClient::with_seed([("a", "1"), ("b", "2"), ("c", "3")]);
        let names = client.list(None).await.unwrap();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn mem_client_list_with_prefix() {
        let client = MemClient::with_seed([("prod/jwt", "1"), ("prod/api", "2"), ("dev/jwt", "3")]);
        let mut names = client.list(Some("prod/")).await.unwrap();
        names.sort();
        assert_eq!(names, vec!["prod/api", "prod/jwt"]);
    }

    #[tokio::test]
    async fn mem_client_delete_removes() {
        let client = MemClient::with_seed([("gone", "soon")]);
        client.delete("gone").await.unwrap();
        assert!(matches!(
            client.get("gone").await,
            Err(SecretError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn mem_client_delete_missing_errors() {
        let client = MemClient::new();
        assert!(matches!(
            client.delete("nope").await,
            Err(SecretError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn mem_client_rotate_missing_key_errors() {
        let client = MemClient::new();
        match client.rotate("anything").await {
            Err(SecretError::NotFound { name }) => assert_eq!(name, "anything"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mem_client_rotate_appends_version() {
        let client = MemClient::with_seed([("key", "v1")]);
        client.rotate("key").await.unwrap();
        let v1 = client.get_version("key", "1").await.unwrap();
        let v2 = client.get_version("key", "2").await.unwrap();
        assert_eq!(v1, "v1");
        assert!(v2.starts_with("rotated-v2-"));
        // get() returns latest (v2)
        assert_eq!(client.get("key").await.unwrap(), v2);
    }

    #[tokio::test]
    async fn mem_client_versions_track_puts() {
        let client = MemClient::new();
        client.put("key", "v1").await.unwrap();
        client.put("key", "v2").await.unwrap();
        client.put("key", "v3").await.unwrap();
        assert_eq!(client.get_version("key", "1").await.unwrap(), "v1");
        assert_eq!(client.get_version("key", "2").await.unwrap(), "v2");
        assert_eq!(client.get_version("key", "3").await.unwrap(), "v3");
        // get_with_metadata exposes the current version number
        let secret = client.get_with_metadata("key").await.unwrap();
        assert_eq!(secret.value, "v3");
        assert_eq!(secret.metadata.version.as_deref(), Some("3"));
    }

    #[tokio::test]
    async fn mem_client_get_version_out_of_range_errors() {
        let client = MemClient::with_seed([("key", "v1")]);
        assert!(matches!(
            client.get_version("key", "99").await,
            Err(SecretError::Backend(_))
        ));
    }

    #[tokio::test]
    async fn mem_client_capabilities_advertised_full() {
        let caps = MemClient::new().capabilities();
        assert!(caps.get && caps.list && caps.put && caps.delete);
        assert!(caps.rotate && caps.versions);
    }

    #[tokio::test]
    async fn mem_client_get_with_metadata_exposes_version() {
        let client = MemClient::with_seed([("key", "value")]);
        let secret = client.get_with_metadata("key").await.unwrap();
        assert_eq!(secret.value, "value");
        // Seeded values start at version 1; updated_at is None (MemClient
        // isn't a real store with timestamps).
        assert_eq!(secret.metadata.version.as_deref(), Some("1"));
        assert!(secret.metadata.tags.is_empty());
    }

    #[tokio::test]
    async fn command_client_template_substitution() {
        let client = CommandClient::with_get_template("echo resolved-{name}");
        let value = client.get("test").await.unwrap();
        assert_eq!(value, "resolved-test");
    }

    #[tokio::test]
    async fn command_client_name_map() {
        let client =
            CommandClient::with_name_map([("jwt", "echo from-map"), ("api", "echo api-value")]);
        assert_eq!(client.get("jwt").await.unwrap(), "from-map");
        assert_eq!(client.get("api").await.unwrap(), "api-value");
    }

    #[tokio::test]
    async fn command_client_missing_key_errors() {
        let client = CommandClient::with_name_map([("only", "echo x")]);
        assert!(matches!(
            client.get("missing").await,
            Err(SecretError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn command_client_write_ops_unsupported() {
        let client = CommandClient::with_get_template("echo {name}");
        assert!(matches!(
            client.put("k", "v").await,
            Err(SecretError::Unsupported {
                operation: "put",
                ..
            })
        ));
        assert!(matches!(
            client.delete("k").await,
            Err(SecretError::Unsupported {
                operation: "delete",
                ..
            })
        ));
        assert!(matches!(
            client.list(None).await,
            Err(SecretError::Unsupported {
                operation: "list",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn command_client_capabilities_read_only() {
        let caps = CommandClient::with_get_template("x").capabilities();
        assert!(caps.get);
        assert!(!caps.put && !caps.delete && !caps.list && !caps.rotate);
    }

    #[tokio::test]
    async fn trait_object_dispatch_works() {
        let client: std::sync::Arc<dyn SecretClient> =
            std::sync::Arc::new(MemClient::with_seed([("key", "value")]));
        assert_eq!(client.get("key").await.unwrap(), "value");
        assert_eq!(client.backend_name(), "mem");
    }

    #[test]
    fn capabilities_read_only_shape() {
        let caps = Capabilities::read_only();
        assert!(caps.get);
        assert!(!caps.list && !caps.put && !caps.delete && !caps.rotate && !caps.versions);
    }

    #[test]
    fn capabilities_full_shape() {
        let caps = Capabilities::full();
        assert!(caps.get && caps.list && caps.put && caps.delete && caps.rotate && caps.versions);
    }

    #[test]
    fn secret_error_not_retryable_by_default() {
        let err = SecretError::NotFound { name: "x".into() };
        assert!(!err.is_retryable());
    }

    #[test]
    fn secret_error_display_shapes() {
        let unauth = SecretError::Unauthorized {
            message: "no token".into(),
        };
        assert!(unauth.to_string().contains("no token"));

        let unsupported = SecretError::Unsupported {
            backend: "sops",
            operation: "rotate",
        };
        assert!(unsupported.to_string().contains("sops"));
        assert!(unsupported.to_string().contains("rotate"));
    }

    // ── SecretOperation — typed axis over the operation universe ───────

    #[test]
    fn secret_operation_all_covers_every_variant() {
        // Pin that ALL enumerates every constructible variant pointwise.
        // The compiler enforces this on the as_str match; the test makes
        // the contract explicit.
        let mut seen: std::collections::HashSet<SecretOperation> = std::collections::HashSet::new();
        for op in SecretOperation::ALL.iter().copied() {
            assert!(seen.insert(op), "duplicate in ALL: {op:?}");
        }
        assert_eq!(seen.len(), 6);
        assert!(seen.contains(&SecretOperation::Get));
        assert!(seen.contains(&SecretOperation::List));
        assert!(seen.contains(&SecretOperation::Put));
        assert!(seen.contains(&SecretOperation::Delete));
        assert!(seen.contains(&SecretOperation::Rotate));
        assert!(seen.contains(&SecretOperation::GetVersion));
    }

    #[test]
    fn secret_operation_all_has_no_duplicates() {
        // The constant is a set. Same discipline as
        // `config_source_kind_all_has_no_duplicates`,
        // `secret_backend_kind_all_has_no_duplicates`, etc.
        let mut sorted: Vec<&'static str> =
            SecretOperation::ALL.iter().map(|o| o.as_str()).collect();
        sorted.sort_unstable();
        let original_len = sorted.len();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            original_len,
            "SecretOperation::ALL must not list any variant twice",
        );
    }

    #[test]
    fn secret_operation_is_static_copy_hashable() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Static, Copy, Eq, Hash — trait-bounds parity with the sibling
        // closed-axis primitives. Suitable for cross-thread observation
        // and HashMap keys.
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        fn assert_copy<T: Copy>() {}
        fn assert_eq_hash<T: Eq + std::hash::Hash>() {}
        assert_send_sync::<SecretOperation>();
        assert_copy::<SecretOperation>();
        assert_eq_hash::<SecretOperation>();

        // The hash of a Copy value is stable across clones.
        let op = SecretOperation::GetVersion;
        let mut h1 = DefaultHasher::new();
        op.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        op.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn secret_operation_as_str_yields_canonical_snake_case_names() {
        // Concrete-position pin on the canonical labels. A future
        // rename (e.g. "versions" for GetVersion to match the
        // Capabilities field name) fails here before drifting through
        // the round-trip law or the SecretError::Unsupported message.
        assert_eq!(SecretOperation::Get.as_str(), "get");
        assert_eq!(SecretOperation::List.as_str(), "list");
        assert_eq!(SecretOperation::Put.as_str(), "put");
        assert_eq!(SecretOperation::Delete.as_str(), "delete");
        assert_eq!(SecretOperation::Rotate.as_str(), "rotate");
        assert_eq!(SecretOperation::GetVersion.as_str(), "get_version");
    }

    #[test]
    fn capabilities_supports_matches_field_pointwise() {
        // The (operation → field) projection agrees with direct field
        // reads on a `caps` with every bit flipped to true. Pins the
        // structural alignment between [`SecretOperation`] variants
        // and the matching [`Capabilities`] fields — including the
        // `GetVersion` ↔ `versions` naming asymmetry the typed primitive
        // reconciles.
        let caps = Capabilities {
            get: true,
            list: true,
            put: true,
            delete: true,
            rotate: true,
            versions: true,
        };
        assert_eq!(caps.supports(SecretOperation::Get), caps.get);
        assert_eq!(caps.supports(SecretOperation::List), caps.list);
        assert_eq!(caps.supports(SecretOperation::Put), caps.put);
        assert_eq!(caps.supports(SecretOperation::Delete), caps.delete);
        assert_eq!(caps.supports(SecretOperation::Rotate), caps.rotate);
        assert_eq!(caps.supports(SecretOperation::GetVersion), caps.versions);

        // And on a caps with every bit flipped to false (the not-all-true
        // case, so the alignment doesn't pass trivially).
        let none = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        for op in SecretOperation::ALL.iter().copied() {
            assert!(!none.supports(op), "no-cap caps must reject {op:?}");
        }

        // Selective: turn on exactly one field and confirm only the
        // matching operation reports supported. Pins the projection is
        // a bijection between the six fields and the six variants.
        let mut probe = none;
        probe.put = true;
        assert!(probe.supports(SecretOperation::Put));
        for op in SecretOperation::ALL.iter().copied() {
            assert_eq!(
                probe.supports(op),
                op == SecretOperation::Put,
                "after flipping only `put`, supports({op:?}) must be (op == Put)",
            );
        }
    }

    #[test]
    fn secret_operation_is_supported_by_dual_agrees_with_capabilities_supports() {
        // The (Capabilities, SecretOperation) projection is symmetric:
        // both sides delegate to the same arm. Pinned over every
        // (caps, op) sample point.
        for caps in [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: true,
                list: false,
                put: true,
                delete: false,
                rotate: true,
                versions: false,
            },
        ] {
            for op in SecretOperation::ALL.iter().copied() {
                assert_eq!(
                    caps.supports(op),
                    op.is_supported_by(caps),
                    "supports/is_supported_by must agree on {op:?} / {caps:?}",
                );
            }
        }
    }

    #[test]
    fn capabilities_read_only_supports_only_get() {
        let caps = Capabilities::read_only();
        for op in SecretOperation::ALL.iter().copied() {
            assert_eq!(
                caps.supports(op),
                op == SecretOperation::Get,
                "read_only must support exactly Get; got mismatch on {op:?}",
            );
        }
    }

    #[test]
    fn capabilities_full_supports_every_operation() {
        let caps = Capabilities::full();
        for op in SecretOperation::ALL.iter().copied() {
            assert!(caps.supports(op), "full caps must support {op:?}");
        }
    }

    #[test]
    fn secret_error_unsupported_uses_canonical_str_pointwise() {
        // The typed constructor produces the same `operation` string
        // every default trait impl previously hard-coded.
        for op in SecretOperation::ALL.iter().copied() {
            let err = SecretError::unsupported("test-backend", op);
            match err {
                SecretError::Unsupported { backend, operation } => {
                    assert_eq!(backend, "test-backend");
                    assert_eq!(
                        operation,
                        op.as_str(),
                        "constructor must use op.as_str() pointwise on {op:?}",
                    );
                }
                other => panic!("expected Unsupported, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn secret_client_default_unsupported_arms_use_secret_operation_labels() {
        fn assert_unsupported_with_op(
            result: Result<(), SecretError>,
            backend_expected: &'static str,
            op: SecretOperation,
        ) {
            match result {
                Err(SecretError::Unsupported { backend, operation }) => {
                    assert_eq!(backend, backend_expected);
                    assert_eq!(
                        operation,
                        op.as_str(),
                        "default impl for {op:?} must emit op.as_str() as the operation tag",
                    );
                }
                other => panic!("expected Unsupported({op:?}), got {other:?}"),
            }
        }

        // The five default trait impls each route through
        // `SecretError::unsupported(_, SecretOperation::X)`, so the
        // `operation` string on the raised error is exactly
        // `SecretOperation::X.as_str()`. Pinned via the CommandClient,
        // whose write/list/rotate/get_version methods inherit the
        // default impls without overriding them.
        let client = CommandClient::with_get_template("echo {name}");
        let backend = client.backend_name();

        assert_unsupported_with_op(
            client.list(None).await.map(|_| ()),
            backend,
            SecretOperation::List,
        );
        assert_unsupported_with_op(client.put("k", "v").await, backend, SecretOperation::Put);
        assert_unsupported_with_op(client.delete("k").await, backend, SecretOperation::Delete);
        assert_unsupported_with_op(client.rotate("k").await, backend, SecretOperation::Rotate);
        assert_unsupported_with_op(
            client.get_version("k", "1").await.map(|_| ()),
            backend,
            SecretOperation::GetVersion,
        );
    }

    // ── SecretErrorKind — typed kind axis over the SecretError variant space ──

    /// Construction table: one representative [`SecretError`] for each
    /// expected [`SecretErrorKind`] arm, in the same declaration order
    /// as `SecretErrorKind::ALL`. Reused across the per-kind pin tests.
    fn one_per_secret_error_kind() -> [(SecretError, SecretErrorKind); 5] {
        [
            (
                SecretError::NotFound { name: "x".into() },
                SecretErrorKind::NotFound,
            ),
            (
                SecretError::Unauthorized {
                    message: "no token".into(),
                },
                SecretErrorKind::Unauthorized,
            ),
            (
                SecretError::Unsupported {
                    backend: "sops",
                    operation: "rotate",
                },
                SecretErrorKind::Unsupported,
            ),
            (
                SecretError::Backend("connection refused".into()),
                SecretErrorKind::Backend,
            ),
            (
                SecretError::Shikumi(ShikumiError::NotFound { tried: Vec::new() }),
                SecretErrorKind::Shikumi,
            ),
        ]
    }

    #[test]
    fn secret_error_kind_all_covers_every_variant() {
        // The closed list ALL enumerates exactly the five kinds the
        // construction table produces. Mirrors the
        // `shikumi_error_kind_all_covers_every_constructed_variant`
        // pin on the [`ShikumiErrorKind`] axis.
        let mut seen: std::collections::HashSet<SecretErrorKind> = std::collections::HashSet::new();
        for kind in SecretErrorKind::ALL.iter().copied() {
            assert!(seen.insert(kind), "duplicate in ALL: {kind:?}");
        }
        assert_eq!(seen.len(), 5);
        for (_, expected) in one_per_secret_error_kind() {
            assert!(
                seen.contains(&expected),
                "construction-table kind {expected:?} missing from SecretErrorKind::ALL",
            );
        }
    }

    #[test]
    fn secret_error_kind_all_has_no_duplicates() {
        // The constant is a set. Same discipline as the sibling
        // closed-axis primitives.
        let mut sorted: Vec<&'static str> =
            SecretErrorKind::ALL.iter().map(|k| k.as_str()).collect();
        sorted.sort_unstable();
        let original_len = sorted.len();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            original_len,
            "SecretErrorKind::ALL must not list any variant twice",
        );
    }

    #[test]
    fn secret_error_kind_is_static_copy_hashable() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Static, Copy, Eq, Hash — trait-bounds parity with the sibling
        // closed-axis primitives. Suitable for cross-thread observation
        // and HashMap keys.
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        fn assert_copy<T: Copy>() {}
        fn assert_eq_hash<T: Eq + std::hash::Hash>() {}
        assert_send_sync::<SecretErrorKind>();
        assert_copy::<SecretErrorKind>();
        assert_eq_hash::<SecretErrorKind>();

        let kind = SecretErrorKind::Backend;
        let mut h1 = DefaultHasher::new();
        kind.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        kind.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn secret_error_kind_as_str_yields_canonical_lowercase_names() {
        // Concrete-position pin on the canonical labels. A future
        // rename (e.g. switching `"backend"` to `"transport"`,
        // capitalizing `"NotFound"`, dropping the `"not-"` prefix on
        // [`SecretErrorKind::NotFound`]) fails here before drifting
        // through the trait-uniform round-trip law.
        assert_eq!(SecretErrorKind::NotFound.as_str(), "not-found");
        assert_eq!(SecretErrorKind::Unauthorized.as_str(), "unauthorized");
        assert_eq!(SecretErrorKind::Unsupported.as_str(), "unsupported");
        assert_eq!(SecretErrorKind::Backend.as_str(), "backend");
        assert_eq!(SecretErrorKind::Shikumi.as_str(), "shikumi");
    }

    #[test]
    fn secret_error_kind_pins_every_variant_pointwise() {
        // The (SecretError → SecretErrorKind) projection assigns the
        // expected kind to every construction-table entry. Pins the
        // forward map at the type level — a future variant addition
        // forces a new arm in the exhaustive `SecretError::kind` match,
        // which forces a new construction-table row, which forces an
        // ALL entry through `secret_error_kind_all_covers_every_variant`.
        for (err, expected_kind) in one_per_secret_error_kind() {
            assert_eq!(
                err.kind(),
                expected_kind,
                "SecretError::kind on {err:?} must yield {expected_kind:?}",
            );
        }
    }

    #[test]
    fn secret_error_kind_image_lies_in_secret_error_kind_all() {
        // Cover law: every kind read from a construction-table entry
        // lies in [`SecretErrorKind::ALL`]. The projection cannot
        // escape the closed five-way partition.
        for (err, _) in one_per_secret_error_kind() {
            assert!(
                SecretErrorKind::ALL.contains(&err.kind()),
                "SecretError::kind({err:?}) must lie in SecretErrorKind::ALL",
            );
        }
    }

    #[test]
    fn secret_error_kind_pins_unsupported_payload_independence() {
        // The kind projection is payload-free on the [`Self::Unsupported`]
        // arm: any (backend, operation) pair produces
        // [`SecretErrorKind::Unsupported`]. Witnesses the data-free
        // discipline pointwise on the surface that carries the most
        // structured payload.
        for op in SecretOperation::ALL.iter().copied() {
            let err = SecretError::unsupported("any-backend", op);
            assert_eq!(
                err.kind(),
                SecretErrorKind::Unsupported,
                "unsupported({op:?}) must classify as SecretErrorKind::Unsupported",
            );
        }
    }

    #[test]
    fn secret_error_as_shikumi_agrees_with_kind_pointwise() {
        // The (`as_shikumi().is_some()` ↔ `kind() == Shikumi`)
        // structural law holds for every construction-table entry.
        // Dual to the `Self::Shikumi` arm of `SecretError::kind`.
        for (err, expected_kind) in one_per_secret_error_kind() {
            assert_eq!(
                err.as_shikumi().is_some(),
                expected_kind == SecretErrorKind::Shikumi,
                "as_shikumi().is_some() must match (kind == Shikumi) on {err:?}",
            );
        }
    }

    #[test]
    fn secret_error_as_shikumi_recovers_inner_pointwise() {
        // On the [`Self::Shikumi`] arm, `as_shikumi()` recovers a
        // reference to the wrapped [`ShikumiError`] whose own
        // [`ShikumiError::kind`] refines the cross-kind partition on
        // the wrapped-shikumi sub-axis. Probe over every shikumi-side
        // kind to witness the structural composition.
        for shikumi_kind in crate::ShikumiErrorKind::ALL.iter().copied() {
            // Reuse the simplest constructible ShikumiError per kind —
            // NotFound is data-light and constructible without figment.
            // The wrapped-shikumi kind refines through the inner
            // ShikumiError, not through SecretErrorKind itself.
            let inner = match shikumi_kind {
                crate::ShikumiErrorKind::NotFound => ShikumiError::NotFound { tried: Vec::new() },
                _ => continue,
            };
            let err = SecretError::Shikumi(inner);
            let recovered = err.as_shikumi().expect("Self::Shikumi must yield Some");
            assert_eq!(
                recovered.kind(),
                shikumi_kind,
                "as_shikumi must preserve inner ShikumiError::kind ({shikumi_kind:?})",
            );
            assert_eq!(err.kind(), SecretErrorKind::Shikumi);
        }
    }

    // ── SecretErrorKind — Ord / Display / FromStr / serde ───────────
    //
    // The (Ord, Display, FromStr, serde::{Serialize, Deserialize})
    // quartet idiom-peer of the lift already landed on
    // `ShikumiErrorKind` (commit `911b598`), `SecretClientKind`
    // (commit `24c7b33`), `DiffLineKind` (commit `c403e1a`),
    // `WatchEventClass` (commit `94f8a8b`), `EnvMetadataTagKind`
    // (commit `b556b75`), `SecretRefShape` (commit `8a84bb6`),
    // `SecretBackendKind` (commit `9b1da86`), `FigmentNameTagKind`
    // (commit `64a47e7`), `FigmentSourceKind` (commit `5df265c`), and
    // `ConfigSourceKind` (commit `e0b96d1`), now lifted onto the
    // secret-client error-variant axis kind primitive.

    #[test]
    fn secret_error_kind_ord_matches_all_declaration_order() {
        // The derived Ord on SecretErrorKind is declaration-order lex
        // over ALL: `NotFound < Unauthorized < Unsupported < Backend <
        // Shikumi`. A BTreeMap keyed on the secret-client error-
        // variant axis kind (per-kind retry-policy buckets, per-kind
        // failure-rate histograms, attestation manifests recording
        // the captured-failure mix histogram across backends,
        // structured-diagnostic legends bucketing per-kind counters in
        // declaration order) emits rows in declaration order
        // deterministically without a hand-rolled comparator at the
        // renderer.
        //
        // Two-leg pin: (1) ALL is a strictly-increasing chain under
        // Ord, (2) cmp/partial_cmp agree with the array-index lex
        // over ALL on every pair (and reflexivity holds).
        use std::cmp::Ordering;
        for window in SecretErrorKind::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "SecretErrorKind::ALL must be strictly increasing under Ord, \
                 but {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
        for (i, &a) in SecretErrorKind::ALL.iter().enumerate() {
            for (j, &b) in SecretErrorKind::ALL.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    a.cmp(&b),
                    expected,
                    "SecretErrorKind::cmp must match ALL-index lex for ({a:?}, {b:?})",
                );
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "SecretErrorKind::partial_cmp must agree with cmp for ({a:?}, {b:?})",
                );
                if i == j {
                    assert_eq!(a.cmp(&b), Ordering::Equal, "Ord must be reflexive on {a:?}",);
                }
            }
        }
    }

    #[test]
    fn secret_error_kind_btreemap_emits_in_declaration_order() {
        // The compounding payoff of the Ord derive at a typed
        // consumer site: a BTreeMap<SecretErrorKind, _> emits keys in
        // declaration order on `iter()` / `into_iter()` regardless of
        // insertion order, matching `SecretErrorKind::ALL`.
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<SecretErrorKind, u32> = BTreeMap::new();
        counts.insert(SecretErrorKind::Shikumi, 5);
        counts.insert(SecretErrorKind::NotFound, 1);
        counts.insert(SecretErrorKind::Backend, 4);
        counts.insert(SecretErrorKind::Unauthorized, 2);
        counts.insert(SecretErrorKind::Unsupported, 3);
        let observed: Vec<SecretErrorKind> = counts.keys().copied().collect();
        assert_eq!(
            observed,
            SecretErrorKind::ALL.to_vec(),
            "BTreeMap<SecretErrorKind, _> must emit keys in ALL declaration order",
        );
    }

    #[test]
    fn secret_error_kind_display_matches_as_str() {
        // Display writes the canonical label as_str returns, byte-
        // for-byte. The two surfaces stay aligned by construction —
        // a future rename of either must update the other in lockstep.
        for k in SecretErrorKind::ALL.iter().copied() {
            assert_eq!(
                format!("{k}"),
                k.as_str(),
                "Display must agree with as_str for {k:?}",
            );
        }
    }

    #[test]
    fn secret_error_kind_from_str_round_trips_over_every_variant() {
        // Display → FromStr identity round-trip over every variant.
        // FromStr lowers through ClosedAxisLabel::from_canonical_str,
        // so any future override of that trait method is held to this
        // law at the inherent FromStr surface as well.
        for k in SecretErrorKind::ALL {
            let rendered = k.to_string();
            let parsed: SecretErrorKind = rendered
                .parse()
                .expect("FromStr must round-trip Display output");
            assert_eq!(parsed, *k, "FromStr must round-trip {k:?}");
        }
    }

    #[test]
    fn secret_error_kind_from_str_is_case_insensitive() {
        // FromStr lowers through ClosedAxisLabel::from_canonical_str
        // which uses eq_ignore_ascii_case over ALL — uppercase and
        // mixed-case scalars an operator might type into an env var
        // or CLI flag parse pointwise to the same variant.
        assert_eq!(
            "NOT-FOUND".parse::<SecretErrorKind>().unwrap(),
            SecretErrorKind::NotFound,
        );
        assert_eq!(
            "Unauthorized".parse::<SecretErrorKind>().unwrap(),
            SecretErrorKind::Unauthorized,
        );
        assert_eq!(
            "uNsUpPoRtEd".parse::<SecretErrorKind>().unwrap(),
            SecretErrorKind::Unsupported,
        );
        assert_eq!(
            "BACKEND".parse::<SecretErrorKind>().unwrap(),
            SecretErrorKind::Backend,
        );
        assert_eq!(
            "Shikumi".parse::<SecretErrorKind>().unwrap(),
            SecretErrorKind::Shikumi,
        );
    }

    #[test]
    fn secret_error_kind_from_str_unknown_kind_error_carries_label_verbatim() {
        // Unrecognized labels reject through ShikumiError::Parse with
        // the offending substring embedded verbatim in the rendered
        // message — same verbatim-rejection discipline as the prior
        // sibling lifts.
        for bad in &["timeout", "rate-limit", "transport", "", "  backend"] {
            let err = bad
                .parse::<SecretErrorKind>()
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn secret_error_kind_serde_yaml_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_yaml. Closes the (Serialize,
        // Deserialize) idiom-peer of the (Display, FromStr) stdlib
        // pair on the secret-client error-variant axis kind primitive.
        for k in SecretErrorKind::ALL {
            let yaml = serde_yaml::to_string(k).expect("Serialize must succeed");
            let parsed: SecretErrorKind =
                serde_yaml::from_str(&yaml).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_yaml round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn secret_error_kind_serde_json_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_json.
        for k in SecretErrorKind::ALL {
            let json = serde_json::to_string(k).expect("Serialize must succeed");
            let parsed: SecretErrorKind =
                serde_json::from_str(&json).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_json round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn secret_error_kind_serde_yaml_is_case_insensitive() {
        // Deserialize lowers through FromStr which lowers through
        // ClosedAxisLabel::from_canonical_str (eq_ignore_ascii_case),
        // so uppercase or mixed-case scalars parse pointwise.
        let cases: &[(&str, SecretErrorKind)] = &[
            ("Not-Found", SecretErrorKind::NotFound),
            ("UNAUTHORIZED", SecretErrorKind::Unauthorized),
            ("Unsupported", SecretErrorKind::Unsupported),
            ("BaCkEnD", SecretErrorKind::Backend),
            ("SHIKUMI", SecretErrorKind::Shikumi),
        ];
        for (input, expected) in cases {
            let parsed: SecretErrorKind =
                serde_yaml::from_str(input).expect("case-insensitive Deserialize must succeed");
            assert_eq!(
                parsed, *expected,
                "serde_yaml must parse case-insensitively for input {input:?}",
            );
        }
    }

    #[test]
    fn secret_error_kind_serde_yaml_unknown_kind_error_carries_label_verbatim() {
        // An unrecognized secret-client error-variant axis kind label
        // surfaces at the serde error site with the offending substring
        // verbatim in the rendered message, lifted through
        // ShikumiError::Parse's Display impl.
        for bad in &["timeout", "rate-limit", "transport", "denied"] {
            let err = serde_yaml::from_str::<SecretErrorKind>(bad)
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered serde error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn secret_error_kind_serde_yaml_emission_is_bare_scalar() {
        // Concrete-position pin on the YAML emission shape: a
        // SecretErrorKind serializes as a bare kebab-case scalar, not
        // as a quoted string or a tagged enum.
        let pairs: &[(SecretErrorKind, &str)] = &[
            (SecretErrorKind::NotFound, "not-found\n"),
            (SecretErrorKind::Unauthorized, "unauthorized\n"),
            (SecretErrorKind::Unsupported, "unsupported\n"),
            (SecretErrorKind::Backend, "backend\n"),
            (SecretErrorKind::Shikumi, "shikumi\n"),
        ];
        for (k, expected) in pairs {
            let yaml = serde_yaml::to_string(k).unwrap();
            assert_eq!(yaml, *expected, "YAML emission mismatch for {k:?}");
        }
    }

    #[cfg(feature = "op-native")]
    #[test]
    fn op_urlencode_handles_spaces_and_reserved_chars() {
        assert_eq!(urlencode("simple"), "simple");
        assert_eq!(urlencode("with space"), "with%20space");
        assert_eq!(urlencode("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
        // Unreserved chars stay as-is.
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[cfg(feature = "op-native")]
    #[test]
    fn op_connect_client_constructs_from_config() {
        let client = OpConnectClient::new(OpConnectConfig {
            base_url: "https://connect.example.com/".into(),
            token: "bearer-tok".into(),
            vault_id: "VAULT_UUID".into(),
        });
        assert_eq!(client.backend_name(), "op-connect");
        let caps = client.capabilities();
        assert!(caps.get && caps.list && caps.put && caps.delete);
        assert!(!caps.rotate && !caps.versions);
        // Trailing slash trimmed.
        assert_eq!(client.base_url, "https://connect.example.com");
    }

    #[cfg(feature = "vault-native")]
    #[test]
    fn vault_client_constructs_from_config() {
        let client = VaultClient::new(VaultConfig {
            base_url: "https://vault.example.com:8200/".into(),
            token: "vault-tok".into(),
            mount: "/secret/".into(),
            namespace: Some("admin/team-a".into()),
        });
        assert_eq!(client.backend_name(), "vault");
        let caps = client.capabilities();
        assert!(caps.get && caps.list && caps.put && caps.delete && caps.versions);
        assert!(!caps.rotate);
        assert_eq!(client.base_url, "https://vault.example.com:8200");
        assert_eq!(client.mount, "secret");
    }

    #[cfg(feature = "vault-native")]
    #[test]
    fn vault_url_construction() {
        let client = VaultClient::new(VaultConfig {
            base_url: "https://vault.example.com:8200".into(),
            token: "t".into(),
            mount: "secret".into(),
            namespace: None,
        });
        assert_eq!(
            client.data_url("foo/bar"),
            "https://vault.example.com:8200/v1/secret/data/foo/bar"
        );
        assert_eq!(
            client.metadata_url("foo/bar"),
            "https://vault.example.com:8200/v1/secret/metadata/foo/bar"
        );
        // Leading slash on path is tolerated.
        assert_eq!(
            client.data_url("/foo"),
            "https://vault.example.com:8200/v1/secret/data/foo"
        );
    }

    #[cfg(feature = "vault-native")]
    #[test]
    fn vault_extract_value_single_field() {
        let body = serde_json::json!({
            "data": { "data": { "value": "hello" } }
        });
        assert_eq!(VaultClient::extract_value(&body, "x").unwrap(), "hello");
    }

    #[cfg(feature = "vault-native")]
    #[test]
    fn vault_extract_value_multi_field_returns_json_string() {
        let body = serde_json::json!({
            "data": { "data": { "username": "u", "password": "p" } }
        });
        let v = VaultClient::extract_value(&body, "x").unwrap();
        // JSON object — contains both keys, order indeterminate.
        assert!(v.contains("\"username\":\"u\""));
        assert!(v.contains("\"password\":\"p\""));
    }

    #[cfg(feature = "vault-native")]
    #[test]
    fn vault_extract_value_missing_errors() {
        let body = serde_json::json!({ "data": {} });
        assert!(matches!(
            VaultClient::extract_value(&body, "x"),
            Err(SecretError::Backend(_))
        ));
    }

    #[cfg(feature = "gcp-native")]
    #[test]
    fn gcp_base64_roundtrip() {
        // Empty
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), b"");
        // Single byte → 2 chars + ==
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        // Two bytes → 3 chars + =
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        // Three bytes → 4 chars
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        // Longer
        assert_eq!(base64_encode(b"hello world"), "aGVsbG8gd29ybGQ=");
        assert_eq!(base64_decode("aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
        // Binary-ish bytes (GCP payloads are sometimes non-UTF8)
        let bin: Vec<u8> = (0..=255).collect();
        assert_eq!(base64_decode(&base64_encode(&bin)).unwrap(), bin);
    }

    #[cfg(feature = "gcp-native")]
    #[test]
    fn gcp_base64_tolerates_whitespace() {
        // GCP occasionally line-wraps payloads; our decoder must be
        // lenient about whitespace to match the server's output.
        let wrapped = "aGVs\nbG8g\nd29y\nbGQ=";
        assert_eq!(base64_decode(wrapped).unwrap(), b"hello world");
    }

    #[cfg(feature = "gcp-native")]
    #[test]
    fn gcp_base64_rejects_invalid_chars() {
        assert!(base64_decode("not*valid").is_err());
        assert!(base64_decode("Zg==extra").is_err()); // data after padding
    }

    #[cfg(feature = "gcp-native")]
    #[test]
    fn gcp_client_constructs_from_config() {
        let client = GcpSecretClient::new(GcpSecretConfig {
            project: "my-project".into(),
            token: "ya29.abc123".into(),
            base_url: None,
        });
        assert_eq!(client.backend_name(), "gcp-secret-manager");
        let caps = client.capabilities();
        assert!(caps.get && caps.list && caps.put && caps.delete && caps.versions);
        assert!(!caps.rotate);
        assert_eq!(client.project, "my-project");
        assert!(client.base_url.starts_with("https://"));
    }

    #[cfg(feature = "gcp-native")]
    #[test]
    fn gcp_url_construction() {
        let client = GcpSecretClient::new(GcpSecretConfig {
            project: "p".into(),
            token: "t".into(),
            base_url: Some("https://test.googleapis.com".into()),
        });
        assert_eq!(
            client.secret_url("db-password"),
            "https://test.googleapis.com/v1/projects/p/secrets/db-password"
        );
        assert_eq!(
            client.access_url("db-password", "latest"),
            "https://test.googleapis.com/v1/projects/p/secrets/db-password/versions/latest:access"
        );
        assert_eq!(
            client.access_url("db-password", "7"),
            "https://test.googleapis.com/v1/projects/p/secrets/db-password/versions/7:access"
        );
    }

    #[cfg(feature = "gcp-native")]
    #[test]
    fn gcp_token_rotation() {
        let client = GcpSecretClient::new(GcpSecretConfig {
            project: "p".into(),
            token: "old".into(),
            base_url: None,
        });
        assert_eq!(client.auth_header(), "Bearer old");
        client.set_token("new");
        assert_eq!(client.auth_header(), "Bearer new");
    }

    #[cfg(feature = "gcp-native")]
    #[test]
    fn gcp_decode_payload_happy_path() {
        let body = serde_json::json!({
            "name": "projects/p/secrets/s/versions/1",
            "payload": { "data": "aGVsbG8=" }
        });
        assert_eq!(
            GcpSecretClient::decode_payload(&body, "s").unwrap(),
            "hello"
        );
    }

    #[cfg(feature = "gcp-native")]
    #[test]
    fn gcp_decode_payload_missing_data_errors() {
        let body = serde_json::json!({ "name": "x", "payload": {} });
        assert!(matches!(
            GcpSecretClient::decode_payload(&body, "x"),
            Err(SecretError::Backend(_))
        ));
    }

    // ── SecretClientKind — typed axis over the SecretClient impl universe ──

    #[test]
    fn secret_client_kind_all_covers_every_variant() {
        // Pin that ALL enumerates every constructible variant pointwise.
        // The compiler enforces this on the as_str match; the test makes
        // the contract explicit. Same discipline as
        // `secret_operation_all_covers_every_variant`,
        // `secret_error_kind_all_covers_every_variant`.
        let mut seen: std::collections::HashSet<SecretClientKind> =
            std::collections::HashSet::new();
        for kind in SecretClientKind::ALL.iter().copied() {
            assert!(seen.insert(kind), "duplicate in ALL: {kind:?}");
        }
        assert_eq!(seen.len(), 7);
        assert!(seen.contains(&SecretClientKind::Mem));
        assert!(seen.contains(&SecretClientKind::Command));
        assert!(seen.contains(&SecretClientKind::Akeyless));
        assert!(seen.contains(&SecretClientKind::AwsSecretsManager));
        assert!(seen.contains(&SecretClientKind::OpConnect));
        assert!(seen.contains(&SecretClientKind::Vault));
        assert!(seen.contains(&SecretClientKind::GcpSecretManager));
    }

    #[test]
    fn secret_client_kind_all_has_no_duplicates() {
        // The constant is a set. Same discipline as
        // `secret_error_kind_all_has_no_duplicates`,
        // `secret_operation_all_has_no_duplicates`.
        let mut sorted: Vec<&'static str> =
            SecretClientKind::ALL.iter().map(|k| k.as_str()).collect();
        sorted.sort_unstable();
        let original_len = sorted.len();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            original_len,
            "SecretClientKind::ALL must not list any variant twice",
        );
    }

    #[test]
    fn secret_client_kind_is_static_copy_hashable() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Static, Copy, Eq, Hash — trait-bounds parity with the sibling
        // closed-axis primitives. Suitable for cross-thread observation
        // and HashMap keys.
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        fn assert_copy<T: Copy>() {}
        fn assert_eq_hash<T: Eq + std::hash::Hash>() {}
        assert_send_sync::<SecretClientKind>();
        assert_copy::<SecretClientKind>();
        assert_eq_hash::<SecretClientKind>();

        // The hash of a Copy value is stable across clones.
        let k = SecretClientKind::AwsSecretsManager;
        let mut h1 = DefaultHasher::new();
        k.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        k.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn secret_client_kind_as_str_yields_canonical_names() {
        // Concrete-position pin on the canonical labels. A future rename
        // (e.g. shortening `"aws-secrets-manager"` to `"aws"`, expanding
        // `"mem"` to `"in-memory"`, dropping the `-secrets-manager`
        // suffix) fails here before drifting through the round-trip law
        // or the per-impl `backend_name()` pins below.
        assert_eq!(SecretClientKind::Mem.as_str(), "mem");
        assert_eq!(SecretClientKind::Command.as_str(), "command");
        assert_eq!(SecretClientKind::Akeyless.as_str(), "akeyless");
        assert_eq!(
            SecretClientKind::AwsSecretsManager.as_str(),
            "aws-secrets-manager",
        );
        assert_eq!(SecretClientKind::OpConnect.as_str(), "op-connect");
        assert_eq!(SecretClientKind::Vault.as_str(), "vault");
        assert_eq!(
            SecretClientKind::GcpSecretManager.as_str(),
            "gcp-secret-manager",
        );
    }

    #[test]
    fn secret_client_kind_as_str_pins_mem_client_backend_name() {
        // The lift's structural contract: the canonical label of
        // [`SecretClientKind::Mem`] is byte-identical to
        // [`MemClient::backend_name`]. Pinned per-impl so a future
        // re-label of either side fails at one site.
        let client = MemClient::new();
        assert_eq!(client.backend_name(), SecretClientKind::Mem.as_str());
    }

    #[test]
    fn secret_client_kind_as_str_pins_command_client_backend_name() {
        let client = CommandClient::with_get_template("echo x");
        assert_eq!(client.backend_name(), SecretClientKind::Command.as_str());
    }

    #[test]
    fn secret_client_default_client_kind_recovers_mem_kind() {
        // The trait-default `client_kind` derives from `backend_name`
        // via `SecretClientKind::from_canonical_str`. For a
        // shikumi-shipped impl, the projection must round-trip to
        // [`Some(_)`] on the matching variant — the operative agreement
        // pin between the `backend_name` string axis and the
        // [`SecretClientKind`] typed axis.
        let client = MemClient::new();
        assert_eq!(client.client_kind(), Some(SecretClientKind::Mem));
    }

    #[test]
    fn secret_client_default_client_kind_recovers_command_kind() {
        let client = CommandClient::with_get_template("echo x");
        assert_eq!(client.client_kind(), Some(SecretClientKind::Command));
    }

    #[test]
    fn secret_client_default_client_kind_recovers_backend_name_pointwise() {
        // The structural law:
        //   `self.client_kind().map(SecretClientKind::as_str) == Some(self.backend_name())`
        // for every shikumi-shipped impl. Always-available impls
        // ([`MemClient`], [`CommandClient`]) pinned here; per-feature
        // impls pinned below.
        let mem = MemClient::new();
        assert_eq!(
            mem.client_kind().map(SecretClientKind::as_str),
            Some(mem.backend_name()),
        );

        let cmd = CommandClient::with_get_template("x");
        assert_eq!(
            cmd.client_kind().map(SecretClientKind::as_str),
            Some(cmd.backend_name()),
        );
    }

    #[cfg(feature = "op-native")]
    #[test]
    fn secret_client_kind_recovers_op_connect_backend_name() {
        let client = OpConnectClient::new(OpConnectConfig {
            base_url: "https://connect.example.com/".into(),
            token: "t".into(),
            vault_id: "v".into(),
        });
        assert_eq!(client.client_kind(), Some(SecretClientKind::OpConnect));
        assert_eq!(
            client.client_kind().map(SecretClientKind::as_str),
            Some(client.backend_name()),
        );
    }

    #[cfg(feature = "vault-native")]
    #[test]
    fn secret_client_kind_recovers_vault_backend_name() {
        let client = VaultClient::new(VaultConfig {
            base_url: "https://vault.example.com:8200/".into(),
            token: "t".into(),
            mount: "/secret/".into(),
            namespace: None,
        });
        assert_eq!(client.client_kind(), Some(SecretClientKind::Vault));
        assert_eq!(
            client.client_kind().map(SecretClientKind::as_str),
            Some(client.backend_name()),
        );
    }

    #[test]
    fn secret_client_kind_image_lies_in_secret_client_kind_all() {
        // Every variant of [`SecretClientKind`] appears in
        // [`SecretClientKind::ALL`]. Composes the as_str canonical
        // labels with the trait-default `from_canonical_str` round-trip
        // law (also pinned by
        // `closed_axis_label_round_trips_for_every_implementor` in
        // `cube::tests`).
        for kind in SecretClientKind::ALL.iter().copied() {
            let parsed =
                <SecretClientKind as crate::ClosedAxisLabel>::from_canonical_str(kind.as_str());
            assert_eq!(parsed, Some(kind), "round-trip failed for {kind:?}");
        }
    }

    // ── SecretClientKind — Ord / Display / FromStr / serde ──────────
    //
    // The (Ord, Display, FromStr, serde::{Serialize, Deserialize})
    // quartet idiom-peer of the lift already landed on
    // `SecretBackendKind` (commit `9b1da86`), `SecretRefShape`
    // (commit `8a84bb6`), `DiffLineKind` (commit `c403e1a`),
    // `WatchEventClass` (commit `94f8a8b`), `EnvMetadataTagKind`
    // (commit `b556b75`), `FigmentNameTagKind` (commit `64a47e7`),
    // `FigmentSourceKind` (commit `5df265c`), and `ConfigSourceKind`
    // (commit `e0b96d1`), now lifted onto the runtime-client axis
    // kind primitive.

    #[test]
    fn secret_client_kind_ord_matches_all_declaration_order() {
        // The derived Ord on SecretClientKind is declaration-order
        // lex over ALL: `Mem < Command < Akeyless <
        // AwsSecretsManager < OpConnect < Vault < GcpSecretManager`.
        // A BTreeMap keyed on the runtime-client axis kind (per-
        // client request-rate histograms, per-client latency
        // dashboards, attestation manifests recording the client-mix
        // histogram of resolved secrets, structured-diagnostic
        // legends bucketing per-client counters in declaration order)
        // emits rows in that order deterministically without a hand-
        // rolled comparator at the renderer.
        //
        // Two-leg pin: (1) ALL is a strictly-increasing chain under
        // Ord, (2) cmp/partial_cmp agree with the array-index lex
        // over ALL on every pair (and reflexivity holds). Idiom-peer
        // of the same pin on SecretBackendKind (commit `9b1da86`),
        // SecretRefShape (commit `8a84bb6`), and DiffLineKind
        // (commit `c403e1a`).
        use std::cmp::Ordering;
        for window in SecretClientKind::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "SecretClientKind::ALL must be strictly increasing under Ord, \
                 but {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
        for (i, &a) in SecretClientKind::ALL.iter().enumerate() {
            for (j, &b) in SecretClientKind::ALL.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    a.cmp(&b),
                    expected,
                    "SecretClientKind::cmp must match ALL-index lex for ({a:?}, {b:?})",
                );
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "SecretClientKind::partial_cmp must agree with cmp for ({a:?}, {b:?})",
                );
                if i == j {
                    assert_eq!(a.cmp(&b), Ordering::Equal, "Ord must be reflexive on {a:?}",);
                }
            }
        }
    }

    #[test]
    fn secret_client_kind_btreemap_emits_in_declaration_order() {
        // The compounding payoff of the Ord derive at a typed
        // consumer site: a BTreeMap<SecretClientKind, _> emits keys
        // in declaration order on `iter()` / `into_iter()` regardless
        // of insertion order, matching `SecretClientKind::ALL`.
        // Idiom-peer of the same pin on SecretBackendKind
        // (commit `9b1da86`), SecretRefShape (commit `8a84bb6`), and
        // DiffLineKind (commit `c403e1a`).
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<SecretClientKind, u32> = BTreeMap::new();
        counts.insert(SecretClientKind::GcpSecretManager, 7);
        counts.insert(SecretClientKind::Mem, 1);
        counts.insert(SecretClientKind::Vault, 5);
        counts.insert(SecretClientKind::OpConnect, 4);
        counts.insert(SecretClientKind::AwsSecretsManager, 3);
        counts.insert(SecretClientKind::Command, 2);
        counts.insert(SecretClientKind::Akeyless, 6);
        let observed: Vec<SecretClientKind> = counts.keys().copied().collect();
        assert_eq!(
            observed,
            SecretClientKind::ALL.to_vec(),
            "BTreeMap<SecretClientKind, _> must emit keys in ALL declaration order",
        );
    }

    #[test]
    fn secret_client_kind_display_matches_as_str() {
        // Display writes the canonical label as_str returns, byte-
        // for-byte. The two surfaces stay aligned by construction —
        // a future rename of either must update the other in
        // lockstep. Idiom-peer of the same pin on SecretBackendKind
        // (commit `9b1da86`), DiffLineKind (commit `c403e1a`), and
        // WatchEventClass (commit `94f8a8b`).
        for k in SecretClientKind::ALL.iter().copied() {
            assert_eq!(
                format!("{k}"),
                k.as_str(),
                "Display must agree with as_str for {k:?}",
            );
        }
    }

    #[test]
    fn secret_client_kind_from_str_round_trips_over_every_variant() {
        // Display → FromStr identity round-trip over every variant.
        // FromStr lowers through ClosedAxisLabel::from_canonical_str,
        // so any future override of that trait method is held to this
        // law at the inherent FromStr surface as well.
        for k in SecretClientKind::ALL {
            let rendered = k.to_string();
            let parsed: SecretClientKind = rendered
                .parse()
                .expect("FromStr must round-trip Display output");
            assert_eq!(parsed, *k, "FromStr must round-trip {k:?}");
        }
    }

    #[test]
    fn secret_client_kind_from_str_is_case_insensitive() {
        // FromStr lowers through ClosedAxisLabel::from_canonical_str
        // which uses eq_ignore_ascii_case over ALL — uppercase and
        // mixed-case scalars an operator might type into an env var
        // or CLI flag parse pointwise to the same variant.
        assert_eq!(
            "MEM".parse::<SecretClientKind>().unwrap(),
            SecretClientKind::Mem,
        );
        assert_eq!(
            "Command".parse::<SecretClientKind>().unwrap(),
            SecretClientKind::Command,
        );
        assert_eq!(
            "Aws-Secrets-Manager".parse::<SecretClientKind>().unwrap(),
            SecretClientKind::AwsSecretsManager,
        );
        assert_eq!(
            "oP-cOnNeCt".parse::<SecretClientKind>().unwrap(),
            SecretClientKind::OpConnect,
        );
        assert_eq!(
            "GCP-SECRET-MANAGER".parse::<SecretClientKind>().unwrap(),
            SecretClientKind::GcpSecretManager,
        );
    }

    #[test]
    fn secret_client_kind_from_str_unknown_kind_error_carries_label_verbatim() {
        // Unrecognized labels reject through ShikumiError::Parse with
        // the offending substring embedded verbatim in the rendered
        // message — same verbatim-rejection discipline as
        // SecretBackendKind's FromStr surface (commit `9b1da86`),
        // SecretRefShape's FromStr surface (commit `8a84bb6`),
        // DiffLineKind's FromStr surface (commit `c403e1a`),
        // WatchEventClass's FromStr surface (commit `94f8a8b`),
        // EnvMetadataTagKind's FromStr surface (commit `b556b75`),
        // FigmentNameTagKind's FromStr surface (commit `64a47e7`),
        // FigmentSourceKind's FromStr surface (commit `5df265c`), and
        // ConfigSourceKind's FromStr surface (commit `e0b96d1`).
        for bad in &["aws", "gcp", "kubernetes", "keychain", "", "  mem"] {
            let err = bad
                .parse::<SecretClientKind>()
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn secret_client_kind_serde_yaml_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_yaml. Closes the (Serialize,
        // Deserialize) idiom-peer of the (Display, FromStr) stdlib
        // pair on the runtime-client axis kind primitive. A consumer
        // struct holding a SecretClientKind field under
        // #[derive(Serialize, Deserialize)] (e.g. an attestation
        // manifest recording the client kind of a resolved secret)
        // round-trips without a consumer-side rename helper.
        for k in SecretClientKind::ALL {
            let yaml = serde_yaml::to_string(k).expect("Serialize must succeed");
            let parsed: SecretClientKind =
                serde_yaml::from_str(&yaml).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_yaml round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn secret_client_kind_serde_json_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over every
        // variant through serde_json. The two formats render the
        // canonical scalar identically modulo wire ceremony (YAML's
        // bare scalar vs. JSON's quoted string), so the round-trip
        // law composes pointwise — a future divergence in either
        // Serialize impl surfaces here.
        for k in SecretClientKind::ALL {
            let json = serde_json::to_string(k).expect("Serialize must succeed");
            let parsed: SecretClientKind =
                serde_json::from_str(&json).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *k, "serde_json round-trip must preserve {k:?}");
        }
    }

    #[test]
    fn secret_client_kind_serde_yaml_is_case_insensitive() {
        // Deserialize lowers through FromStr which lowers through
        // ClosedAxisLabel::from_canonical_str (eq_ignore_ascii_case),
        // so uppercase or mixed-case scalars parse pointwise. A
        // manifest field authored by an operator typing the canonical
        // name with different casing parses without a consumer-side
        // case-fold helper.
        let cases: &[(&str, SecretClientKind)] = &[
            ("Mem", SecretClientKind::Mem),
            ("COMMAND", SecretClientKind::Command),
            ("Aws-Secrets-Manager", SecretClientKind::AwsSecretsManager),
            ("oP-cOnNeCt", SecretClientKind::OpConnect),
            ("GCP-SECRET-MANAGER", SecretClientKind::GcpSecretManager),
        ];
        for (input, expected) in cases {
            let parsed: SecretClientKind =
                serde_yaml::from_str(input).expect("case-insensitive Deserialize must succeed");
            assert_eq!(
                parsed, *expected,
                "serde_yaml must parse case-insensitively for input {input:?}",
            );
        }
    }

    #[test]
    fn secret_client_kind_serde_yaml_unknown_kind_error_carries_label_verbatim() {
        // An unrecognized runtime-client axis kind label surfaces at
        // the serde error site with the offending substring verbatim
        // in the rendered message, lifted through
        // ShikumiError::Parse's Display impl. Same verbatim-rejection
        // discipline as SecretBackendKind's serde surface
        // (commit `9b1da86`), DiffLineKind's serde surface
        // (commit `c403e1a`), WatchEventClass's serde surface
        // (commit `94f8a8b`), and ConfigSourceKind's serde surface
        // (commit `e0b96d1`).
        for bad in &["aws", "gcp", "kubernetes", "keychain"] {
            let err = serde_yaml::from_str::<SecretClientKind>(bad)
                .expect_err("non-canonical label must reject");
            let rendered = err.to_string();
            assert!(
                rendered.contains(bad),
                "rendered serde error must contain the offending label verbatim: \
                 input={bad:?}, rendered={rendered:?}",
            );
        }
    }

    #[test]
    fn secret_client_kind_serde_yaml_emission_is_bare_scalar() {
        // Concrete-position pin on the YAML emission shape: a
        // SecretClientKind serializes as a bare kebab-case scalar,
        // not as a quoted string or a tagged enum. Captures that an
        // attestation manifest authoring tool can emit the kind as a
        // bare YAML scalar pointwise matching the operator-facing
        // label across all seven variants.
        let pairs: &[(SecretClientKind, &str)] = &[
            (SecretClientKind::Mem, "mem\n"),
            (SecretClientKind::Command, "command\n"),
            (SecretClientKind::Akeyless, "akeyless\n"),
            (SecretClientKind::AwsSecretsManager, "aws-secrets-manager\n"),
            (SecretClientKind::OpConnect, "op-connect\n"),
            (SecretClientKind::Vault, "vault\n"),
            (SecretClientKind::GcpSecretManager, "gcp-secret-manager\n"),
        ];
        for (k, expected) in pairs {
            let yaml = serde_yaml::to_string(k).unwrap();
            assert_eq!(yaml, *expected, "YAML emission mismatch for {k:?}");
        }
    }
}
