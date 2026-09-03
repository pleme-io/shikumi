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
    ///
    /// Payload-inspecting sibling of the tag-side quintet
    /// [`Self::is_not_found`] / [`Self::is_unauthorized`] /
    /// [`Self::is_unsupported`] / [`Self::is_backend`] /
    /// [`Self::is_shikumi`] — this predicate consults the
    /// [`Self::Backend`] arm's message-string content, while the five
    /// tag-side siblings project the closed-partition variant tag
    /// through [`Self::kind`] without touching the payload. Observers
    /// wanting the full retryability decision compose
    /// `err.is_backend() && err.is_retryable()` instead of re-deriving
    /// the kind-axis half by open-coded `matches!`.
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
    ///
    /// Strict superset of the tag-side quintet [`Self::is_not_found`] /
    /// [`Self::is_unauthorized`] / [`Self::is_unsupported`] /
    /// [`Self::is_backend`] / [`Self::is_shikumi`]: each `is_X()` is
    /// `self.kind() == SecretErrorKind::X`. The five predicates remain
    /// as convenience accessors; new code that needs to distinguish
    /// more than one kind should prefer this one accessor over a chain
    /// of predicates.
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

    /// Returns `true` if this is a `NotFound` error. Convenience over
    /// [`Self::kind`]; equivalent to
    /// `self.kind() == SecretErrorKind::NotFound`.
    ///
    /// Tag-side sibling predicate over the closed five-way
    /// [`SecretError`] variant space. Peer of [`Self::is_unauthorized`]
    /// / [`Self::is_unsupported`] / [`Self::is_backend`] /
    /// [`Self::is_shikumi`] — the full tag-side quintet mirroring the
    /// kind-side quintet on [`SecretErrorKind::is_not_found`] et al.
    /// Pointwise-agreement bridge with the kind-side predicate is
    /// pinned by
    /// [`tests::secret_error_predicates_agree_pointwise_with_secret_error_kind_predicates`];
    /// the closed-quintet partition on the tag-side (exactly one of
    /// the five predicates holds on every constructed error) is
    /// pinned by
    /// [`tests::secret_error_predicates_are_a_closed_quintet_partition`].
    ///
    /// Direct methodological analogue of [`ShikumiError::is_not_found`]
    /// on the [`ShikumiError`] tag-side septet — same routing shape
    /// (`matches!(self.kind(), SecretErrorKind::NotFound)`), same
    /// closed-partition contract at one altitude lower, same
    /// pointwise-agreement bridge to the kind-side sibling.
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self.kind(), SecretErrorKind::NotFound)
    }

    /// Returns `true` if this is an `Unauthorized` error. Convenience
    /// over [`Self::kind`]; equivalent to
    /// `self.kind() == SecretErrorKind::Unauthorized`. Tag-side
    /// sibling predicate; see [`Self::is_not_found`] for the full
    /// contract.
    #[must_use]
    pub const fn is_unauthorized(&self) -> bool {
        matches!(self.kind(), SecretErrorKind::Unauthorized)
    }

    /// Returns `true` if this is an `Unsupported` error. Convenience
    /// over [`Self::kind`]; equivalent to
    /// `self.kind() == SecretErrorKind::Unsupported`. Tag-side
    /// sibling predicate; see [`Self::is_not_found`] for the full
    /// contract.
    ///
    /// Payload-independence — the answer is the same for every
    /// `Unsupported { backend, operation }` — is what the
    /// pointwise-agreement bridge locks in: the kind-side predicate
    /// cannot see the `backend`/`operation` string pair, and a future
    /// edit that changed this arm to inspect them would diverge from
    /// the kind-side and fail
    /// [`tests::secret_error_predicates_agree_pointwise_with_secret_error_kind_predicates`].
    #[must_use]
    pub const fn is_unsupported(&self) -> bool {
        matches!(self.kind(), SecretErrorKind::Unsupported)
    }

    /// Returns `true` if this is a `Backend` error. Convenience over
    /// [`Self::kind`]; equivalent to
    /// `self.kind() == SecretErrorKind::Backend`. Tag-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    ///
    /// Coincides on the kind axis with the payload-inspecting
    /// [`Self::is_retryable`] predicate's domain — that predicate
    /// returns `true` only on a subset of [`Self::Backend`] payloads
    /// (whose message hints at a transient failure via `timeout` or
    /// `5` substrings). Observers wanting the full retryability
    /// decision compose `err.is_backend() && err.is_retryable()`
    /// (equivalent to `err.is_retryable()` alone since `is_retryable`
    /// only fires on `Self::Backend`, but explicit about the two-part
    /// contract) instead of re-deriving the kind-axis half by
    /// open-coded `matches!`.
    #[must_use]
    pub const fn is_backend(&self) -> bool {
        matches!(self.kind(), SecretErrorKind::Backend)
    }

    /// Returns `true` if this is a `Shikumi` pass-through error.
    /// Convenience over [`Self::kind`]; equivalent to
    /// `self.kind() == SecretErrorKind::Shikumi`. Tag-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    ///
    /// Structural sibling of [`Self::as_shikumi`]:
    /// `err.is_shikumi() == err.as_shikumi().is_some()` for every
    /// [`SecretError`], pinned by the pre-existing
    /// [`tests::secret_error_as_shikumi_agrees_with_kind_pointwise`]
    /// through the [`Self::kind`] projection; this predicate lets the
    /// same observation surface phrase the check without spelling the
    /// closed-equality on the kind axis at its own site. Observers
    /// wanting to refine the kind partition further on the
    /// wrapped-shikumi sub-axis compose
    /// `err.as_shikumi().map(ShikumiError::kind)` after gating on
    /// `err.is_shikumi()` — the tag-side sibling here replaces the
    /// prior `err.kind() == SecretErrorKind::Shikumi` phrasing.
    #[must_use]
    pub const fn is_shikumi(&self) -> bool {
        matches!(self.kind(), SecretErrorKind::Shikumi)
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

    /// Returns `true` for [`Self::NotFound`]; equivalent to
    /// `self == SecretErrorKind::NotFound`.
    ///
    /// Kind-side sibling predicate over the closed five-way
    /// [`SecretErrorKind`] partition. Consumers holding only the kind
    /// (a `HashMap`/`HashSet` key, a `BTreeMap` bucket, a per-kind
    /// retry-policy dispatch, a cross-thread failure-class tag captured
    /// on a per-request observability record after the borrowed
    /// [`SecretError`] payload has been dropped) classify without
    /// materializing a synthetic [`SecretError`] first — the tag-side
    /// data-carrying enum holds owned `String` / `ShikumiError`
    /// payloads a kind-only observer cannot cheaply reconstruct.
    ///
    /// Peer to [`crate::ConfigSourceKind::is_defaults`] /
    /// [`crate::ConfigSourceKind::is_env`] /
    /// [`crate::ConfigSourceKind::is_file`] on the shikumi-side
    /// layer-kind axis, [`crate::FigmentSourceKind::is_file`] /
    /// [`crate::FigmentSourceKind::is_code`] /
    /// [`crate::FigmentSourceKind::is_custom`] on the figment-side
    /// source axis, and [`crate::SecretBackendKind::is_literal`] /
    /// [`crate::SecretBackendKind::is_op`] / … on the payload-carrying
    /// secret-backend axis: same kind-side sibling-predicate
    /// discipline applied to the secret-client error-variant axis, the
    /// last kind-enum primitive in the crate carrying zero per-variant
    /// sibling predicates before this landing.
    ///
    /// The five sibling predicates form a closed disjoint partition
    /// of [`Self::ALL`] — every variant satisfies exactly one, none
    /// satisfies two, none satisfies zero — pinned by
    /// [`tests::secret_error_kind_predicates_are_a_closed_quintet_partition`].
    /// The kind-alone equality-agreement law
    /// (`k.is_X() == (k == Self::X)` for every variant) is pinned by
    /// [`tests::secret_error_kind_predicates_agree_with_equality_pointwise`].
    #[must_use]
    pub const fn is_not_found(self) -> bool {
        matches!(self, Self::NotFound)
    }

    /// Returns `true` for [`Self::Unauthorized`]; equivalent to
    /// `self == SecretErrorKind::Unauthorized`. Kind-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    #[must_use]
    pub const fn is_unauthorized(self) -> bool {
        matches!(self, Self::Unauthorized)
    }

    /// Returns `true` for [`Self::Unsupported`]; equivalent to
    /// `self == SecretErrorKind::Unsupported`. Kind-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    #[must_use]
    pub const fn is_unsupported(self) -> bool {
        matches!(self, Self::Unsupported)
    }

    /// Returns `true` for [`Self::Backend`]; equivalent to
    /// `self == SecretErrorKind::Backend`. Kind-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    ///
    /// Coincides with the domain [`SecretError::is_retryable`] targets
    /// today — that tag-side predicate returns `true` only for
    /// [`SecretError::Backend`] payloads whose message hints at a
    /// transient failure (timeout / 5xx substring). The kind-side
    /// predicate does not consult the payload; observers wanting the
    /// full retryability decision compose
    /// `err.kind().is_backend() && err.is_retryable()` instead of
    /// re-deriving the kind-axis half by open-coded `matches!`.
    #[must_use]
    pub const fn is_backend(self) -> bool {
        matches!(self, Self::Backend)
    }

    /// Returns `true` for [`Self::Shikumi`]; equivalent to
    /// `self == SecretErrorKind::Shikumi`. Kind-side sibling
    /// predicate; see [`Self::is_not_found`] for the full contract.
    ///
    /// Structural sibling of [`SecretError::as_shikumi`]:
    /// `err.kind().is_shikumi() == err.as_shikumi().is_some()` for
    /// every [`SecretError`], already pinned by the pre-existing
    /// [`tests::secret_error_as_shikumi_agrees_with_kind_pointwise`]
    /// under the kind-equality form; this predicate lets the same
    /// observation surface phrase the check without spelling the
    /// closed-equality on the kind axis at its own site.
    #[must_use]
    pub const fn is_shikumi(self) -> bool {
        matches!(self, Self::Shikumi)
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

// The canonical (Display, FromStr, Serialize, Deserialize) string-surface
// quartet on the secret-client error-variant axis kind closed-enum, lifted
// to one macro after the eleven hand-rolled idiom-peers preceding this
// commit (WatchEventClass at `94f8a8b`, ShikumiErrorKind at `4b53792`,
// DiffLineKind at `74ee853`, ConfigSourceKind at `ae24a13`,
// FormatProvenance at `212d6fb`, FigmentNameTagKind at `25bab65`,
// FigmentSourceKind at `8a0277d`, EnvMetadataTagKind at `58557d3`,
// SecretBackendKind at `360487a`, SecretRefShape at `bb249c0`,
// SecretClientKind at `fd9cc2b`). See `closed_axis_label_string_surface!`
// in `crate::macros` for the contract; behavior is byte-identical to the
// hand-rolled impls the macro replaces — the verbatim-label `Parse` error
// body, the case-insensitive `from_canonical_str` lowering, the
// `collect_str`-based serde emission, and the visitor's `expecting`
// message all match the prior surface pointwise. Pinned by
// `tests::secret_error_kind_display_matches_as_str`,
// `tests::secret_error_kind_from_str_*`, and
// `tests::secret_error_kind_serde_yaml_*` / `…_serde_json_*`.
closed_axis_label_string_surface! {
    type = SecretErrorKind,
    parse_error = "unknown secret error kind",
    expecting = "a canonical SecretErrorKind label \
                 (`not-found`, `unauthorized`, `unsupported`, \
                 `backend`, `shikumi`; case-insensitive)",
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
/// `Ord` / `PartialOrd` are declaration-order lex over [`Self::ALL`]
/// (`Get < List < Put < Delete < Rotate < GetVersion`): a
/// `BTreeMap<SecretOperation, T>` keyed on the operation axis
/// (per-operation request-rate histograms, per-operation latency
/// dashboards, attestation manifests recording the operation-mix
/// histogram of refused calls, structured-diagnostic legends
/// bucketing per-operation counters in declaration order) emits rows
/// in that order deterministically without a hand-rolled comparator
/// at the renderer. Idiom-peer of the same derive on
/// [`crate::SecretBackendKind`] (commit `9b1da86`),
/// [`crate::SecretRefShape`] (commit `8a84bb6`),
/// [`crate::DiffLineKind`] (commit `c403e1a`),
/// [`crate::WatchEventClass`] (commit `94f8a8b`),
/// [`crate::EnvMetadataTagKind`] (commit `b556b75`),
/// [`crate::FigmentNameTagKind`] (commit `64a47e7`),
/// [`crate::FigmentSourceKind`] (commit `5df265c`),
/// [`crate::ConfigSourceKind`] (commit `e0b96d1`),
/// [`SecretClientKind`] (commit `24c7b33`),
/// [`crate::ShikumiErrorKind`] (commit `911b598`), and
/// [`SecretErrorKind`] (commit `38b9964`) lifted onto the operation
/// axis closed-enum.
///
/// [`SecretBackendKind`]: crate::secret::SecretBackendKind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

    /// The three MUTATING [`SecretOperation`] variants that *change the
    /// underlying store's state* — [`Self::Put`], [`Self::Delete`],
    /// [`Self::Rotate`] — in the relative declaration order they appear
    /// in [`Self::ALL`].
    ///
    /// **The write-half slice of the operation axis at the primitive's
    /// own altitude.** The compound-polarity meta-partition of
    /// [`Self::ALL`] materialized as a static slice, one altitude down
    /// from the shipped [`Self::is_mutating`] predicate: every variant in
    /// this slice satisfies `op.is_mutating()`, and no variant outside it
    /// does. Paired with [`Self::NON_MUTATING`], the two disjoint slices
    /// partition [`Self::ALL`] pointwise — the same read-vs-write
    /// meta-partition the shipped `is_mutating` / `is_non_mutating`
    /// predicates name at the boolean altitude, lifted onto the slice
    /// altitude so consumers enumerate one pole in one iterator instead
    /// of filtering [`Self::ALL`] through the polarity predicate.
    ///
    /// Consumers that iterate ONLY the write half (an RBAC gate walking
    /// "which mutating operations does this backend actually support?",
    /// an attestation manifest emitting the mutating-operation histogram
    /// of a resolved client, a `/healthz/capabilities` dashboard row
    /// bucketing each backend by "N of 3 mutating ops advertised", a CLI
    /// `--mutating-only` filter over a captured refusal log) walk this
    /// slice directly rather than iterating [`Self::ALL`] and dispatching
    /// through [`Self::is_mutating`] on every step. Idiom-peer of the
    /// shipped [`Capabilities::supported_mutating_op_count`] one altitude
    /// up: both project the write-half meta-partition at their own
    /// altitude without re-deriving through the sibling polarity
    /// predicate.
    ///
    /// Written as an explicit three-variant slice literal (in the
    /// declaration order [`Self::Put`], [`Self::Delete`], [`Self::Rotate`]
    /// mirroring their appearance in [`Self::ALL`]) rather than derived
    /// by filtering [`Self::ALL`] through [`Self::is_mutating`] — so a
    /// hypothetical seventh mutating operation must be added HERE in
    /// lockstep with `is_mutating`, and the two independent declarations
    /// keep the pin catching any drift between them before either can
    /// silently disagree. Uses the same static-slice discipline as
    /// [`Self::ALL`].
    ///
    /// The two agreement laws (`MUTATING.iter().all(|op|
    /// op.is_mutating())` and `MUTATING.iter().all(|op|
    /// !op.is_non_mutating())`) are pinned by
    /// [`tests::secret_operation_mutating_slice_agrees_with_is_mutating_predicate`].
    /// The pair partitions [`Self::ALL`] via
    /// [`tests::secret_operation_mutating_and_non_mutating_slices_partition_all`].
    /// The declaration-order preservation pin is
    /// [`tests::secret_operation_mutating_and_non_mutating_slices_preserve_all_order`].
    /// No duplicates: [`tests::secret_operation_mutating_slice_has_no_duplicates`].
    pub const MUTATING: &'static [Self] = &[Self::Put, Self::Delete, Self::Rotate];

    /// The three NON-MUTATING [`SecretOperation`] variants that *do not
    /// change the underlying store's state* — [`Self::Get`], [`Self::List`],
    /// [`Self::GetVersion`] — in the relative declaration order they
    /// appear in [`Self::ALL`].
    ///
    /// **The read-half slice of the operation axis at the primitive's
    /// own altitude.** Complement pole of [`Self::MUTATING`] on the
    /// read-vs-write meta-partition; the pair partitions [`Self::ALL`]
    /// into two disjoint three-element slices whose union is
    /// [`Self::ALL`] pointwise. Mirrors the shipped
    /// [`Self::is_non_mutating`] predicate one altitude down: every
    /// variant in this slice satisfies `op.is_non_mutating()`, and no
    /// variant outside it does.
    ///
    /// Consumers iterating ONLY the read half (a captured-refusal log's
    /// read-path filter, an attestation manifest recording the read-path
    /// support histogram, a `/healthz/capabilities` dashboard row
    /// bucketing each backend by "N of 3 read ops advertised") walk this
    /// slice directly rather than filtering [`Self::ALL`] through
    /// [`Self::is_non_mutating`] on every step. Idiom-peer of the shipped
    /// [`Capabilities::supported_non_mutating_op_count`] one altitude up.
    ///
    /// See [`Self::MUTATING`] for the full contract, the discipline
    /// behind the explicit three-variant slice literal (rather than a
    /// filter through [`Self::is_non_mutating`]), and the load-bearing
    /// agreement and partition pins.
    pub const NON_MUTATING: &'static [Self] = &[Self::Get, Self::List, Self::GetVersion];

    /// The single [`Self::Get`] pole of the six-way identity meta-
    /// partition on the [`SecretClient`] operation axis at the
    /// static-slice altitude — the singleton slice `&[Self::Get]`
    /// mirroring the shipped boolean predicate [`Self::is_get`] one
    /// altitude down: every variant in this slice satisfies
    /// `op.is_get()`, and no variant outside it does.
    ///
    /// Paired with the five siblings ([`Self::ONLY_LIST`],
    /// [`Self::ONLY_PUT`], [`Self::ONLY_DELETE`], [`Self::ONLY_ROTATE`],
    /// [`Self::ONLY_GET_VERSION`]), the six disjoint singleton slices
    /// partition [`Self::ALL`] at the static-slice altitude the same
    /// way the shipped boolean predicates
    /// ([`Self::is_get`] / [`Self::is_list`] / [`Self::is_put`] /
    /// [`Self::is_delete`] / [`Self::is_rotate`] /
    /// [`Self::is_get_version`]) meta-partition it at the boolean
    /// altitude. All six constants sit in the same `impl SecretOperation`
    /// block as [`Self::ALL`] / [`Self::MUTATING`] / [`Self::NON_MUTATING`]
    /// and follow the same `pub const &'static [Self]` static-slice
    /// discipline.
    ///
    /// Written as explicit one-variant slice literals in the SAME
    /// relative declaration order the six identity poles occupy in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through the six identity predicates at const-fn altitude — so
    /// the two declaration surfaces (the slice literals and the
    /// boolean predicates) remain independent load-bearing witnesses
    /// of the same identity meta-partition, and a future edit that
    /// shifts a variant across an identity pole on ONE surface but
    /// not the other diverges at test time on the first shape where
    /// they disagree.
    ///
    /// Also the first cell of [`Self::NON_MUTATING`] — the two
    /// witnesses agree here (`ONLY_GET ⊆ NON_MUTATING`) per the
    /// identity-vs-compound cross-check that pins the six identity
    /// singletons against the shipped mutation-polarity meta-partition.
    ///
    /// **Idiom-peer.** Senary landing of the per-half meta-partition
    /// slice-constant discipline, matching altitude-for-altitude the
    /// octonary
    /// [`crate::secret::SecretBackendKind::ONLY_LITERAL`] / … /
    /// `ONLY_GCP_SECRET` (commit `19364e3`), the septenary
    /// [`SecretClientKind::ONLY_MEM`] / … /
    /// `ONLY_GCP_SECRET_MANAGER` (commit `d78ae31`), the quinary
    /// [`crate::cli::TierArg::ONLY_BARE`] / … / `ONLY_ENV`
    /// (commit `f7f5529`), and the quaternary
    /// [`crate::tiered::ConfigTierKind::ONLY_BARE`] / … /
    /// `ONLY_CUSTOM` (commit `ff6492b`) — the per-half meta-partition
    /// slice-constant discipline applied here to the six-way
    /// [`SecretClient`] operation axis (the first landing on the
    /// operation-axis primitive), lifting the six identity poles onto
    /// the slice-constant altitude alongside the shipped compound-
    /// polarity [`Self::MUTATING`] / [`Self::NON_MUTATING`] pair one
    /// altitude up.
    ///
    /// The six agreement laws (`ONLY_GET.iter().all(|o| o.is_get())`
    /// and `ONLY_GET.iter().all(|o| !o.is_list() && !o.is_put() &&
    /// !o.is_delete() && !o.is_rotate() && !o.is_get_version())`,
    /// symmetric on the five siblings) are pinned by
    /// [`tests::secret_operation_identity_slices_agree_with_identity_predicates`].
    /// Partition invariant across all six:
    /// [`tests::secret_operation_identity_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::secret_operation_identity_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::secret_operation_identity_slices_have_no_duplicates`].
    /// Cardinality-agreement with the six boolean poles:
    /// [`tests::secret_operation_identity_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::secret_operation_identity_slices_are_const_addressable`].
    /// Cross-altitude weld with the shipped compound-polarity
    /// [`Self::MUTATING`] / [`Self::NON_MUTATING`] pair:
    /// [`tests::secret_operation_identity_slices_agree_with_compound_polarity_slices`].
    pub const ONLY_GET: &'static [Self] = &[Self::Get];

    /// The [`Self::List`] pole of the six-way identity meta-partition
    /// on the [`SecretClient`] operation axis at the static-slice
    /// altitude — the singleton slice `&[Self::List]` mirroring the
    /// shipped boolean predicate [`Self::is_list`] one altitude down.
    ///
    /// Also the second cell of [`Self::NON_MUTATING`] — the two
    /// witnesses agree here (`ONLY_LIST ⊆ NON_MUTATING`).
    ///
    /// See [`Self::ONLY_GET`] for the full contract, the discipline
    /// behind writing the six identity-partition constants as
    /// explicit slice literals (rather than filters through
    /// [`Self::is_list`]), and the load-bearing agreement,
    /// partition, order-preservation, no-duplicates, cardinality,
    /// and const-addressability pins the six `ONLY_*` singletons
    /// share.
    pub const ONLY_LIST: &'static [Self] = &[Self::List];

    /// The [`Self::Put`] pole of the six-way identity meta-partition
    /// on the [`SecretClient`] operation axis at the static-slice
    /// altitude — the singleton slice `&[Self::Put]` mirroring the
    /// shipped boolean predicate [`Self::is_put`] one altitude down.
    ///
    /// Also the first cell of [`Self::MUTATING`] — the two witnesses
    /// agree here (`ONLY_PUT ⊆ MUTATING`).
    ///
    /// See [`Self::ONLY_GET`] for the full contract and the load-
    /// bearing pins the six `ONLY_*` singletons share.
    pub const ONLY_PUT: &'static [Self] = &[Self::Put];

    /// The [`Self::Delete`] pole of the six-way identity meta-
    /// partition on the [`SecretClient`] operation axis at the
    /// static-slice altitude — the singleton slice `&[Self::Delete]`
    /// mirroring the shipped boolean predicate [`Self::is_delete`]
    /// one altitude down.
    ///
    /// Also the second cell of [`Self::MUTATING`] — the two witnesses
    /// agree here (`ONLY_DELETE ⊆ MUTATING`).
    ///
    /// See [`Self::ONLY_GET`] for the full contract and the load-
    /// bearing pins the six `ONLY_*` singletons share.
    pub const ONLY_DELETE: &'static [Self] = &[Self::Delete];

    /// The [`Self::Rotate`] pole of the six-way identity meta-
    /// partition on the [`SecretClient`] operation axis at the
    /// static-slice altitude — the singleton slice `&[Self::Rotate]`
    /// mirroring the shipped boolean predicate [`Self::is_rotate`]
    /// one altitude down.
    ///
    /// Also the third cell of [`Self::MUTATING`] — the two witnesses
    /// agree here (`ONLY_ROTATE ⊆ MUTATING`).
    ///
    /// See [`Self::ONLY_GET`] for the full contract and the load-
    /// bearing pins the six `ONLY_*` singletons share.
    pub const ONLY_ROTATE: &'static [Self] = &[Self::Rotate];

    /// The [`Self::GetVersion`] pole of the six-way identity meta-
    /// partition on the [`SecretClient`] operation axis at the
    /// static-slice altitude — the singleton slice `&[Self::GetVersion]`
    /// mirroring the shipped boolean predicate [`Self::is_get_version`]
    /// one altitude down.
    ///
    /// Also the third cell of [`Self::NON_MUTATING`] — the two
    /// witnesses agree here (`ONLY_GET_VERSION ⊆ NON_MUTATING`).
    ///
    /// See [`Self::ONLY_GET`] for the full contract and the load-
    /// bearing pins the six `ONLY_*` singletons share.
    pub const ONLY_GET_VERSION: &'static [Self] = &[Self::GetVersion];

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

    /// Returns `true` for [`Self::Get`]; equivalent to
    /// `self == SecretOperation::Get`.
    ///
    /// Per-variant sibling predicate over the closed six-way
    /// [`SecretOperation`] partition. Consumers carrying the operation
    /// tag alone (per-operation request-rate histograms bucketing on
    /// the read path, dispatch-side "am I about to call `.get()` on
    /// this client?" gating, attestation manifests recording the
    /// refused-operation mix, structured-diagnostic legends bucketing
    /// per-operation counters) classify without spelling
    /// `op == SecretOperation::Get` at their own site, and the
    /// sextet-partition + equality-agreement pins catch the two
    /// failure modes of `matches!`-based predicates (silent widen to
    /// a second arm, silent robbery of an arm) before drift reaches
    /// any dispatch site.
    ///
    /// Peer to [`SecretErrorKind::is_not_found`] /
    /// [`SecretErrorKind::is_unauthorized`] / … on the secret-client
    /// error-variant kind axis (commit `6b67a81`),
    /// [`crate::SecretBackendKind::is_literal`] /
    /// [`crate::SecretBackendKind::is_command`] / … on the
    /// payload-carrying secret-backend kind axis (commit `9dc6d1f`),
    /// [`crate::ConfigSourceKind::is_defaults`] /
    /// [`crate::ConfigSourceKind::is_env`] /
    /// [`crate::ConfigSourceKind::is_file`] on the shikumi-side
    /// layer-kind axis, and [`crate::Format::is_yaml`] /
    /// [`crate::Format::is_toml`] / … on the top-level config-file
    /// format axis: same sibling-predicate discipline applied to the
    /// secret-client operation axis, the last surface-carrying
    /// closed-enum primitive in the crate holding zero per-variant
    /// sibling predicates before this landing.
    ///
    /// The six sibling predicates form a closed disjoint partition
    /// of [`Self::ALL`] — every variant satisfies exactly one, none
    /// satisfies two, none satisfies zero — pinned by
    /// [`tests::secret_operation_predicates_are_a_closed_sextet_partition`].
    /// The equality-agreement law (`op.is_X() == (op == Self::X)` for
    /// every variant) is pinned by
    /// [`tests::secret_operation_predicates_agree_with_equality_pointwise`].
    #[must_use]
    pub const fn is_get(self) -> bool {
        matches!(self, Self::Get)
    }

    /// Returns `true` for [`Self::List`]; equivalent to
    /// `self == SecretOperation::List`. Per-variant sibling
    /// predicate; see [`Self::is_get`] for the full contract.
    #[must_use]
    pub const fn is_list(self) -> bool {
        matches!(self, Self::List)
    }

    /// Returns `true` for [`Self::Put`]; equivalent to
    /// `self == SecretOperation::Put`. Per-variant sibling predicate;
    /// see [`Self::is_get`] for the full contract.
    #[must_use]
    pub const fn is_put(self) -> bool {
        matches!(self, Self::Put)
    }

    /// Returns `true` for [`Self::Delete`]; equivalent to
    /// `self == SecretOperation::Delete`. Per-variant sibling
    /// predicate; see [`Self::is_get`] for the full contract.
    #[must_use]
    pub const fn is_delete(self) -> bool {
        matches!(self, Self::Delete)
    }

    /// Returns `true` for [`Self::Rotate`]; equivalent to
    /// `self == SecretOperation::Rotate`. Per-variant sibling
    /// predicate; see [`Self::is_get`] for the full contract.
    #[must_use]
    pub const fn is_rotate(self) -> bool {
        matches!(self, Self::Rotate)
    }

    /// Returns `true` for [`Self::GetVersion`]; equivalent to
    /// `self == SecretOperation::GetVersion`. Per-variant sibling
    /// predicate; see [`Self::is_get`] for the full contract.
    ///
    /// Names the operation whose (Capabilities-side `versions` plural
    /// × trait-side `get_version` singular) surface-disagreement the
    /// [`SecretOperation`] primitive reconciles — consumers can now
    /// classify the historical-version read path by named predicate
    /// (`op.is_get_version()`) without spelling either surface's
    /// magic string, or the closed-equality
    /// `op == SecretOperation::GetVersion`, at their own site.
    #[must_use]
    pub const fn is_get_version(self) -> bool {
        matches!(self, Self::GetVersion)
    }

    /// Returns `true` for the *mutating* pole of the [`SecretOperation`]
    /// axis — the three operations that *change the underlying store's
    /// state*: [`Self::Put`] (create-or-update a value),
    /// [`Self::Delete`] (destroy a value), [`Self::Rotate`] (trigger
    /// backend-side generation of a new value under an existing key) —
    /// `false` on the three non-mutating operations ([`Self::Get`],
    /// [`Self::List`], [`Self::GetVersion`]).
    ///
    /// **The write-half compound-polarity pole at the operation
    /// altitude.** The six per-variant singleton predicates
    /// ([`Self::is_get`] / [`Self::is_list`] / [`Self::is_put`] /
    /// [`Self::is_delete`] / [`Self::is_rotate`] / [`Self::is_get_version`])
    /// already resolve the closed sextet partition of [`Self::ALL`] at the
    /// primitive's altitude; the compound-polarity pair
    /// ([`Self::is_mutating`] + [`Self::is_non_mutating`]) lifts the
    /// *read-vs-write* meta-partition onto the same altitude so a
    /// consumer reasoning about *whether the call changes the store*
    /// (an RBAC gate on a daemon startup — "the resolved role has
    /// read-only permission, so any [`Self::is_mutating`] dispatch must
    /// refuse before touching the backend"; an audit-log filter routing
    /// mutating dispatches into a separately-retained higher-severity
    /// stream; an attestation manifest recording the read-vs-write
    /// operation histogram of a recorded session; a structured-tracing
    /// span attribute bucketing dispatches on the compound-polarity
    /// pole; a CLI `--mutating-only` / `--read-only` filter over a
    /// captured refusal log) names the *positive* form of the query at
    /// the call site instead of the three-arm disjunction
    /// `op.is_put() || op.is_delete() || op.is_rotate()` and reads the
    /// pole through ONE welded predicate.
    ///
    /// Written as `match *self { Self::Put | Self::Delete | Self::Rotate
    /// => true, Self::Get | Self::List | Self::GetVersion => false }` so
    /// a hypothetical seventh operation (a `Metadata` read the
    /// [`SecretOperation`] doc calls out explicitly, a `Renew` on a
    /// lease-tracking backend that would sit on the mutating pole
    /// alongside [`Self::Rotate`], a `Watch` streaming updates that
    /// would sit on the non-mutating pole alongside [`Self::List`],
    /// etc.) must be classified on this axis at `cargo build` — an
    /// exhaustive `match` naming both arms fails the build until the
    /// new variant is placed on one polarity or the other, rather than
    /// silently defaulting past a bare `false` literal on the compound
    /// pole and drifting through every consumer site that reasons about
    /// the read/write partition. Idiom-peer of the same explicit-arms
    /// discipline on the peer compound-polarity siblings
    /// [`crate::WatchEventClass::is_file_mutation`],
    /// [`crate::discovery::Format::is_feature_gated`],
    /// [`crate::secret::SecretBackendKind::is_cloud_secret_manager`],
    /// [`Self::is_cloud_secret_manager`][SecretClientKind::is_cloud_secret_manager],
    /// [`crate::source::ConfigSourceKind::is_overlay`], and
    /// [`crate::tiered::ConfigTierKind::is_computed`].
    ///
    /// **Cross-surface: agreement with [`Capabilities::full`].** Every
    /// mutating operation is advertised by the full-capability set —
    /// `Capabilities::full()` sets `put`, `delete`, and `rotate` to
    /// `true`, so `op.is_mutating() ⇒ op.is_supported_by(Capabilities::full())`
    /// — pinned by
    /// [`tests::secret_operation_is_mutating_ops_supported_by_full_capabilities`].
    /// The dual [`Capabilities::read_only`] set does *not* symmetrically
    /// pin `!op.is_mutating() ⇒ op.is_supported_by(caps)`: the shipped
    /// `read_only()` set enables only `get`, so it refuses both mutating
    /// operations *and* the two non-mutating operations [`Self::List`]
    /// and [`Self::GetVersion`] — the historically get-only shape of
    /// `read_only()` is a stronger constraint than *just* non-mutating,
    /// which is why the compound-polarity name here is `is_mutating` /
    /// `is_non_mutating` rather than `is_write` / `is_read_only` (the
    /// latter would falsely suggest agreement with the get-only
    /// [`Capabilities::read_only`] shape).
    ///
    /// The compound ↔ complement law (`op.is_mutating() ==
    /// !op.is_non_mutating()`) is pinned by
    /// [`tests::secret_operation_is_mutating_is_complement_of_is_non_mutating`].
    /// The compound ↔ three-arm disjunction law (`op.is_mutating() ==
    /// op.is_put() || op.is_delete() || op.is_rotate()`) is pinned by
    /// [`tests::secret_operation_is_mutating_agrees_with_disjunction_of_mutating_siblings`].
    /// The compound-polarity binary partition is pinned by
    /// [`tests::secret_operation_is_mutating_and_is_non_mutating_are_a_closed_binary_partition`].
    /// The compile-time weld is pinned by
    /// [`tests::secret_operation_is_mutating_is_const_callable`].
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        match self {
            Self::Put | Self::Delete | Self::Rotate => true,
            Self::Get | Self::List | Self::GetVersion => false,
        }
    }

    /// Returns `true` for the *non-mutating* pole of the
    /// [`SecretOperation`] axis — the three operations that *do not
    /// change the underlying store's state*: [`Self::Get`] (read a
    /// current value), [`Self::List`] (enumerate keys), [`Self::GetVersion`]
    /// (read a historical value) — `false` on the three mutating
    /// operations ([`Self::Put`], [`Self::Delete`], [`Self::Rotate`]).
    ///
    /// Complement pole of [`Self::is_mutating`] on the read-vs-write
    /// meta-partition; equivalent to `!self.is_mutating()`. Named
    /// separately (rather than left as a negation) so consumers reading
    /// the non-mutating half of the axis no longer negate
    /// [`Self::is_mutating`] — a shape whose polarity a future tertiary
    /// class (e.g. a `Watch` streaming subscription that arguably neither
    /// reads a *current* value nor mutates the store) would silently
    /// flip: `!is_mutating` would then include the tertiary alongside the
    /// three shipped non-mutating cells, whereas the direct predicate
    /// stays true only for the three declared non-mutating cells and
    /// forces the tertiary to declare its own polarity. Peer of the same
    /// closed-binary-pair discipline the neighbouring compound-polarity
    /// axes carry — [`crate::WatchEventClass::is_file_mutation`] /
    /// [`crate::WatchEventClass::is_ignored`] on the reload-relevance
    /// axis, [`crate::discovery::Format::is_feature_gated`] /
    /// [`crate::discovery::Format::is_always_available`] on the file-
    /// format axis, [`crate::tiered::ConfigTierKind::is_computed`] /
    /// [`crate::tiered::ConfigTierKind::is_custom`] on the tier axis.
    ///
    /// See [`Self::is_mutating`] for the full compound-polarity
    /// contract, the cross-surface `Capabilities::full` agreement law,
    /// and the load-bearing test suite.
    #[must_use]
    pub const fn is_non_mutating(self) -> bool {
        match self {
            Self::Get | Self::List | Self::GetVersion => true,
            Self::Put | Self::Delete | Self::Rotate => false,
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

// The canonical (Display, FromStr, Serialize, Deserialize) string-surface
// quartet on the operation axis closed-enum, lifted to one macro after the
// twelve hand-rolled idiom-peers preceding this commit (WatchEventClass at
// `94f8a8b`, ShikumiErrorKind at `4b53792`, DiffLineKind at `74ee853`,
// ConfigSourceKind at `ae24a13`, FormatProvenance at `212d6fb`,
// FigmentNameTagKind at `25bab65`, FigmentSourceKind at `8a0277d`,
// EnvMetadataTagKind at `58557d3`, SecretBackendKind at `360487a`,
// SecretRefShape at `bb249c0`, SecretClientKind at `fd9cc2b`, and
// SecretErrorKind at `930ee5a`). See `closed_axis_label_string_surface!`
// in `crate::macros` for the contract; behavior is byte-identical to the
// hand-rolled impls the macro replaces — the verbatim-label `Parse` error
// body, the case-insensitive `from_canonical_str` lowering, the
// `collect_str`-based serde emission, and the visitor's `expecting`
// message all match the prior surface pointwise. Pinned by
// `tests::secret_operation_display_matches_as_str`,
// `tests::secret_operation_from_str_*`,
// `tests::secret_operation_serde_yaml_*`, and
// `tests::secret_operation_serde_json_*`.
closed_axis_label_string_surface! {
    type = SecretOperation,
    parse_error = "unknown secret operation",
    expecting = "a canonical SecretOperation label \
                 (`get`, `list`, `put`, `delete`, `rotate`, \
                 `get_version`; case-insensitive)",
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

    /// Returns `true` iff this capability set advertises AT LEAST ONE
    /// of the three mutating [`SecretOperation`] variants
    /// ([`SecretOperation::Put`], [`SecretOperation::Delete`],
    /// [`SecretOperation::Rotate`]) — i.e. `self.put || self.delete ||
    /// self.rotate`.
    ///
    /// **The mutation-capable pole of the compound-polarity axis
    /// [`SecretOperation::is_mutating`] names one altitude down**, lifted
    /// onto the [`Capabilities`] altitude. The
    /// [`SecretOperation::is_mutating`] / [`SecretOperation::is_non_mutating`]
    /// pair (commit `ca7131b`) already partitions
    /// [`SecretOperation::ALL`] into the write-half ([`SecretOperation::Put`]
    /// / [`SecretOperation::Delete`] / [`SecretOperation::Rotate`]) and
    /// read-half ([`SecretOperation::Get`] / [`SecretOperation::List`] /
    /// [`SecretOperation::GetVersion`]) at the operation altitude; this
    /// method lifts the *mutation-capable* pole onto the capability-set
    /// altitude so a consumer holding a [`Capabilities`] value alone (a
    /// daemon startup gate: "the resolved backend advertises no mutating
    /// operation, so this daemon can only be deployed in read-only mode";
    /// an RBAC dispatch table: "reject a deployment whose declared role
    /// requires mutation against a `Capabilities` set that advertises
    /// none"; an attestation manifest recording the count of resolved
    /// backends grouped by whether the operator retained ANY write access;
    /// a `/healthz/capabilities` dashboard bucketing runtime clients by
    /// their write-capability pole) names the *positive* form of the
    /// query at the call site instead of the three-arm disjunction
    /// `caps.put || caps.delete || caps.rotate` and reads the pole
    /// through ONE welded predicate — the same relief the
    /// [`SecretOperation::is_mutating`] pole provided one altitude down
    /// on the operation-tag surface.
    ///
    /// **Cross-altitude weld with [`SecretOperation::is_mutating`].** The
    /// two poles agree structurally: `caps.supports_any_mutating_op()`
    /// holds iff there EXISTS a [`SecretOperation`] variant satisfying
    /// both `op.is_mutating()` and `caps.supports(op)` — i.e.,
    /// `caps.supports_any_mutating_op() == SecretOperation::ALL.iter()
    /// .any(|op| op.is_mutating() && caps.supports(*op))`. This law is
    /// what makes the compound predicate on this altitude coherent with
    /// the mutating-pole meta-partition on the operation altitude — a
    /// future edit that flipped the polarity on either side without
    /// flipping the other diverges here at compile-time-of-suite, before
    /// drifting through any RBAC gate that reasons about the two
    /// altitudes as one pole. Pinned by
    /// [`tests::capabilities_supports_any_mutating_op_agrees_with_operation_is_mutating`].
    ///
    /// **Cross-surface anchors on the shipped constructors.**
    /// [`Capabilities::full`] advertises every mutating operation
    /// (`put`, `delete`, `rotate` all `true`), so
    /// `Capabilities::full().supports_any_mutating_op()` is `true` —
    /// pinned by
    /// [`tests::capabilities_full_supports_any_mutating_op`].
    /// [`Capabilities::read_only`] advertises none of them (all three
    /// mutating flags are `false`), so
    /// `Capabilities::read_only().supports_any_mutating_op()` is
    /// `false` — pinned by
    /// [`tests::capabilities_read_only_supports_no_mutating_op`]. The
    /// two shipped constructors sit on opposite poles of this
    /// compound-polarity axis by construction.
    ///
    /// Written as an explicit `self.put || self.delete || self.rotate`
    /// disjunction over exactly the three mutating fields (rather than
    /// iterating [`SecretOperation::ALL`] and dispatching through
    /// [`Self::supports`] on every arm), so the compile-time weld to the
    /// three specific field identifiers stays load-bearing: a future
    /// [`Capabilities`] field rename (`put` → `create`, `rotate` →
    /// `renew`) fails at `cargo build` here before drifting through any
    /// consumer that reasons about the mutation-capable pole, and a
    /// hypothetical seventh mutating operation landing on
    /// [`SecretOperation`] (a `Renew` on a lease-tracking backend, a
    /// `Metadata` write) surfaces at the cross-altitude agreement pin
    /// above rather than silently changing this predicate's answer.
    /// Idiom-peer of the explicit-disjunction discipline
    /// [`SecretOperation::is_mutating`] carries on its `Self::Put |
    /// Self::Delete | Self::Rotate` arm one altitude down.
    ///
    /// The compound ↔ complement law
    /// (`caps.supports_any_mutating_op() ==
    /// !caps.supports_no_mutating_op()`) is pinned by
    /// [`tests::capabilities_supports_any_mutating_op_is_complement_of_supports_no_mutating_op`].
    /// The compile-time weld is pinned by
    /// [`tests::capabilities_supports_any_mutating_op_is_const_callable`].
    #[must_use]
    pub const fn supports_any_mutating_op(self) -> bool {
        self.put || self.delete || self.rotate
    }

    /// Returns `true` iff this capability set advertises NONE of the
    /// three mutating [`SecretOperation`] variants
    /// ([`SecretOperation::Put`], [`SecretOperation::Delete`],
    /// [`SecretOperation::Rotate`]) — i.e. `!self.put && !self.delete
    /// && !self.rotate`.
    ///
    /// Complement pole of [`Self::supports_any_mutating_op`] on the
    /// mutation-capability meta-partition at the [`Capabilities`]
    /// altitude; equivalent to `!self.supports_any_mutating_op()`.
    /// Named separately (rather than left as a negation) so consumers
    /// reading the mutation-incapable half of the axis no longer negate
    /// [`Self::supports_any_mutating_op`] — a shape whose polarity a
    /// future fourth mutating [`SecretOperation`] variant (a `Renew` on
    /// a lease-tracking backend, a `Metadata` write) with its own
    /// [`Capabilities`] field would silently include in the negation
    /// without extending this predicate. The direct predicate, written
    /// as `!self.put && !self.delete && !self.rotate` over exactly the
    /// three currently-mutating fields, forces the maintainer landing
    /// the new [`Capabilities`] field to update this arm in lockstep
    /// with the new field — or the cross-altitude weld with
    /// [`SecretOperation::is_non_mutating`] one altitude down diverges
    /// at test time.
    ///
    /// See [`Self::supports_any_mutating_op`] for the full compound-
    /// polarity contract, the cross-altitude weld with
    /// [`SecretOperation::is_mutating`] / [`SecretOperation::is_non_mutating`],
    /// the cross-surface anchors on [`Self::full`] / [`Self::read_only`],
    /// and the load-bearing test suite.
    ///
    /// Named `supports_no_mutating_op` (rather than `is_read_only` or
    /// `is_immutable`) to match the compound-polarity naming discipline
    /// established by [`SecretOperation::is_mutating`] /
    /// [`SecretOperation::is_non_mutating`] one altitude down — the
    /// `read_only` name would falsely suggest agreement with the
    /// get-only shape of [`Self::read_only`] (which also refuses the
    /// non-mutating [`SecretOperation::List`] and
    /// [`SecretOperation::GetVersion`] operations, so the get-only
    /// constructor is a *stronger* constraint than mere mutation
    /// incapability). The same naming asymmetry is documented in
    /// [`SecretOperation::is_mutating`]'s doc.
    #[must_use]
    pub const fn supports_no_mutating_op(self) -> bool {
        !self.put && !self.delete && !self.rotate
    }

    /// Returns `true` iff this capability set advertises AT LEAST ONE
    /// of the three non-mutating [`SecretOperation`] variants
    /// ([`SecretOperation::Get`], [`SecretOperation::List`],
    /// [`SecretOperation::GetVersion`]) — i.e. `self.get || self.list
    /// || self.versions`.
    ///
    /// **The read-capable pole of the compound-polarity axis
    /// [`SecretOperation::is_non_mutating`] names one altitude down**,
    /// lifted onto the [`Capabilities`] altitude — orthogonal READ-half
    /// counterpart of the WRITE-half pair
    /// [`Self::supports_any_mutating_op`] / [`Self::supports_no_mutating_op`]
    /// already shipped on this altitude. Together the two pairs cover
    /// the two poles of the read-vs-write meta-partition
    /// [`SecretOperation::is_mutating`] / [`SecretOperation::is_non_mutating`]
    /// names one altitude down: any [`Capabilities`] value now surfaces
    /// its WRITE-half and READ-half "any / none" answers through four
    /// welded predicates at the primitive's own altitude, without a
    /// consumer holding a bare [`Capabilities`] value ever having to
    /// re-derive the three-arm disjunction inline.
    ///
    /// The [`SecretOperation::is_non_mutating`] pair already partitions
    /// [`SecretOperation::ALL`] into the read-half
    /// ([`SecretOperation::Get`] / [`SecretOperation::List`] /
    /// [`SecretOperation::GetVersion`]) and write-half
    /// ([`SecretOperation::Put`] / [`SecretOperation::Delete`] /
    /// [`SecretOperation::Rotate`]) at the operation altitude; this
    /// method lifts the *read-capable* pole onto the capability-set
    /// altitude so a consumer holding a [`Capabilities`] value alone (a
    /// daemon startup gate: "the resolved backend advertises no
    /// non-mutating operation at all, so this deployment cannot serve
    /// any read-side request — refuse to start"; an RBAC dispatch
    /// table: "reject a deployment whose declared role requires reads
    /// against a `Capabilities` set that advertises none"; an
    /// attestation manifest recording the count of resolved backends
    /// grouped by whether the operator retained ANY read access; a
    /// `/healthz/capabilities` dashboard bucketing runtime clients by
    /// their read-capability pole) names the *positive* form of the
    /// query at the call site instead of the three-arm disjunction
    /// `caps.get || caps.list || caps.versions` and reads the pole
    /// through ONE welded predicate — the same relief
    /// [`Self::supports_any_mutating_op`] provides on the write pole
    /// and the same relief the [`SecretOperation::is_non_mutating`]
    /// pole provides one altitude down on the operation-tag surface.
    ///
    /// **Cross-altitude weld with [`SecretOperation::is_non_mutating`].**
    /// The two poles agree structurally:
    /// `caps.supports_any_non_mutating_op()` holds iff there EXISTS a
    /// [`SecretOperation`] variant satisfying both
    /// `op.is_non_mutating()` and `caps.supports(op)` — i.e.,
    /// `caps.supports_any_non_mutating_op() == SecretOperation::ALL.iter()
    /// .any(|op| op.is_non_mutating() && caps.supports(*op))`. This law
    /// is what makes the compound predicate on this altitude coherent
    /// with the non-mutating-pole meta-partition on the operation
    /// altitude — a future edit that flipped the polarity on either
    /// side without flipping the other diverges here at test time,
    /// before drifting through any RBAC gate that reasons about the
    /// two altitudes as one pole. Pinned by
    /// [`tests::capabilities_supports_any_non_mutating_op_agrees_with_operation_is_non_mutating`].
    ///
    /// **Cross-surface anchors on the shipped constructors.**
    /// [`Capabilities::full`] advertises every non-mutating operation
    /// (`get`, `list`, `versions` all `true`), so
    /// `Capabilities::full().supports_any_non_mutating_op()` is `true`
    /// — pinned by
    /// [`tests::capabilities_full_supports_any_non_mutating_op`].
    /// [`Capabilities::read_only`] advertises `get: true` (with `list`
    /// / `versions` both `false`), so
    /// `Capabilities::read_only().supports_any_non_mutating_op()` is
    /// `true` too — pinned by
    /// [`tests::capabilities_read_only_supports_any_non_mutating_op`].
    /// Both shipped constructors sit on the same read-capable pole of
    /// this compound-polarity axis by construction, mirroring the
    /// (asymmetric) fact that the two shipped constructors sit on
    /// OPPOSITE poles of the write-capable axis
    /// [`Self::supports_any_mutating_op`] (only [`Self::full`] fires
    /// there): shikumi ships no read-incapable constructor, so the
    /// non-mutating-pole predicate only distinguishes hand-rolled
    /// [`Capabilities`] shapes (e.g. a write-only backend), never
    /// either shipped preset.
    ///
    /// Written as an explicit `self.get || self.list || self.versions`
    /// disjunction over exactly the three non-mutating fields (rather
    /// than iterating [`SecretOperation::ALL`] and dispatching through
    /// [`Self::supports`] on every arm), so the compile-time weld to
    /// the three specific field identifiers stays load-bearing: a
    /// future [`Capabilities`] field rename (`get` → `read`, `versions`
    /// → `history`) fails at `cargo build` here before drifting through
    /// any consumer that reasons about the read-capable pole, and a
    /// hypothetical fourth non-mutating operation landing on
    /// [`SecretOperation`] (a `Watch` streaming subscription, a
    /// `Metadata` read) surfaces at the cross-altitude agreement pin
    /// above rather than silently changing this predicate's answer.
    /// Idiom-peer of the explicit-arms discipline
    /// [`SecretOperation::is_non_mutating`] carries on its
    /// `Self::Get | Self::List | Self::GetVersion` arm one altitude
    /// down and of [`Self::supports_any_mutating_op`]'s
    /// `self.put || self.delete || self.rotate` disjunction on the
    /// write pole of this same altitude.
    ///
    /// The compound ↔ complement law
    /// (`caps.supports_any_non_mutating_op() ==
    /// !caps.supports_no_non_mutating_op()`) is pinned by
    /// [`tests::capabilities_supports_any_non_mutating_op_is_complement_of_supports_no_non_mutating_op`].
    /// The compile-time weld is pinned by
    /// [`tests::capabilities_supports_any_non_mutating_op_is_const_callable`].
    #[must_use]
    pub const fn supports_any_non_mutating_op(self) -> bool {
        self.get || self.list || self.versions
    }

    /// Returns `true` iff this capability set advertises NONE of the
    /// three non-mutating [`SecretOperation`] variants
    /// ([`SecretOperation::Get`], [`SecretOperation::List`],
    /// [`SecretOperation::GetVersion`]) — i.e. `!self.get && !self.list
    /// && !self.versions`.
    ///
    /// Complement pole of [`Self::supports_any_non_mutating_op`] on
    /// the read-capability meta-partition at the [`Capabilities`]
    /// altitude; equivalent to `!self.supports_any_non_mutating_op()`.
    /// Named separately (rather than left as a negation) so consumers
    /// reading the read-incapable half of the axis no longer negate
    /// [`Self::supports_any_non_mutating_op`] — a shape whose polarity
    /// a future fourth non-mutating [`SecretOperation`] variant (a
    /// `Watch` streaming subscription that reads without mutating, a
    /// `Metadata` read) with its own [`Capabilities`] field would
    /// silently include in the negation without extending this
    /// predicate. The direct predicate, written as
    /// `!self.get && !self.list && !self.versions` over exactly the
    /// three currently-non-mutating fields, forces the maintainer
    /// landing the new [`Capabilities`] field to update this arm in
    /// lockstep with the new field — or the cross-altitude weld with
    /// [`SecretOperation::is_non_mutating`] one altitude down diverges
    /// at test time.
    ///
    /// See [`Self::supports_any_non_mutating_op`] for the full
    /// compound-polarity contract, the cross-altitude weld with
    /// [`SecretOperation::is_non_mutating`] /
    /// [`SecretOperation::is_mutating`], the cross-surface anchors on
    /// [`Self::full`] / [`Self::read_only`] (both on the read-capable
    /// pole), and the load-bearing test suite.
    ///
    /// Named `supports_no_non_mutating_op` (rather than
    /// `is_write_only` or `has_no_reads`) to match the compound-
    /// polarity naming discipline established by
    /// [`Self::supports_any_mutating_op`] /
    /// [`Self::supports_no_mutating_op`] on the write pole of this same
    /// altitude and by [`SecretOperation::is_mutating`] /
    /// [`SecretOperation::is_non_mutating`] one altitude down — the
    /// `is_write_only` name would falsely imply the shape *also*
    /// advertises every mutating operation (a strictly stronger
    /// constraint than mere read-incapability), whereas
    /// `supports_no_non_mutating_op` names ONLY the read-incapability
    /// pole without saying anything about the mutating half.
    #[must_use]
    pub const fn supports_no_non_mutating_op(self) -> bool {
        !self.get && !self.list && !self.versions
    }

    /// Returns `true` iff this capability set advertises **every** one
    /// of the three mutating [`SecretOperation`] variants
    /// ([`SecretOperation::Put`], [`SecretOperation::Delete`],
    /// [`SecretOperation::Rotate`]) — i.e. `self.put && self.delete
    /// && self.rotate`.
    ///
    /// **The universal (∀) pole of the WRITE-half meta-partition at
    /// the [`Capabilities`] altitude**, orthogonal to the existential
    /// (∃) pole [`Self::supports_any_mutating_op`] /
    /// [`Self::supports_no_mutating_op`] already shipped on this
    /// altitude. Together the two axes form a 2×2 quantifier matrix on
    /// the WRITE-half of the mutating-op meta-partition:
    /// `supports_every_mutating_op` (∀) is strictly stronger than
    /// `supports_any_mutating_op` (∃) — a consumer that requires the
    /// FULL write cycle (put + delete + rotate) rejects any partial
    /// mutation-capable shape (a `put`-only backend, a `delete`-only
    /// backend) that the ∃-pole predicate would accept, while a
    /// consumer that only needs "any write capability" tolerates such
    /// partial shapes. The ∀-pole is what a fleet secret-mirroring
    /// controller or a rotate-scheduled backfill gate reasons about,
    /// where a partial-write backend cannot cover the workload.
    ///
    /// **Cross-altitude weld with [`SecretOperation::is_mutating`].** The
    /// ∀ pole agrees structurally with the universal quantifier over
    /// the mutating half of the operation axis:
    /// `caps.supports_every_mutating_op() == SecretOperation::ALL.iter()
    /// .all(|op| !op.is_mutating() || caps.supports(*op))`. Pinned by
    /// [`tests::capabilities_supports_every_mutating_op_agrees_with_operation_is_mutating`].
    ///
    /// **Cross-quantifier implication weld with [`Self::supports_any_mutating_op`].**
    /// The ∀ pole implies the ∃ pole: `caps.supports_every_mutating_op()
    /// ⇒ caps.supports_any_mutating_op()`. Pinned by
    /// [`tests::capabilities_supports_every_mutating_op_implies_supports_any_mutating_op`].
    ///
    /// **Cross-surface anchors on the shipped constructors.**
    /// [`Capabilities::full`] advertises every mutating operation, so
    /// `Capabilities::full().supports_every_mutating_op()` is `true` —
    /// pinned by [`tests::capabilities_full_supports_every_mutating_op`].
    /// [`Capabilities::read_only`] advertises none of them, so
    /// `Capabilities::read_only().supports_every_mutating_op()` is
    /// `false` — pinned by
    /// [`tests::capabilities_read_only_supports_not_every_mutating_op`].
    ///
    /// Written as an explicit `self.put && self.delete && self.rotate`
    /// conjunction over exactly the three mutating fields (rather than
    /// iterating [`SecretOperation::ALL`] and dispatching through
    /// [`Self::supports`] on every arm), so a future [`Capabilities`]
    /// field rename fails at `cargo build` here before drifting through
    /// any consumer that reasons about the ∀ pole, and a hypothetical
    /// seventh mutating operation landing on [`SecretOperation`]
    /// surfaces at the cross-altitude agreement pin above rather than
    /// silently changing this predicate's answer.
    ///
    /// The compound ↔ complement law
    /// (`caps.supports_every_mutating_op() ==
    /// !caps.supports_not_every_mutating_op()`) is pinned by
    /// [`tests::capabilities_supports_every_mutating_op_is_complement_of_supports_not_every_mutating_op`].
    /// The compile-time weld is pinned by
    /// [`tests::capabilities_supports_every_mutating_op_is_const_callable`].
    #[must_use]
    pub const fn supports_every_mutating_op(self) -> bool {
        self.put && self.delete && self.rotate
    }

    /// Returns `true` iff this capability set is **missing at least
    /// one** of the three mutating [`SecretOperation`] variants
    /// ([`SecretOperation::Put`], [`SecretOperation::Delete`],
    /// [`SecretOperation::Rotate`]) — i.e. `!self.put || !self.delete
    /// || !self.rotate`.
    ///
    /// Complement pole of [`Self::supports_every_mutating_op`] on the
    /// universal (∀) axis at the [`Capabilities`] altitude; equivalent
    /// to `!self.supports_every_mutating_op()`. Named separately
    /// (rather than left as a negation) so consumers reading the
    /// "missing at least one write op" half of the axis no longer
    /// negate [`Self::supports_every_mutating_op`] — a shape whose
    /// polarity a future fourth mutating [`SecretOperation`] variant
    /// with its own [`Capabilities`] field would silently include in
    /// the negation without extending this predicate. The direct
    /// predicate, written as `!self.put || !self.delete || !self.rotate`
    /// over exactly the three currently-mutating fields, forces the
    /// maintainer landing the new [`Capabilities`] field to update this
    /// arm in lockstep with the new field — or the cross-altitude weld
    /// with [`SecretOperation::is_mutating`] one altitude down diverges
    /// at test time.
    ///
    /// See [`Self::supports_every_mutating_op`] for the full
    /// compound-polarity contract, the cross-altitude weld with
    /// [`SecretOperation::is_mutating`], the cross-quantifier
    /// implication (∀ ⇒ ∃), the cross-surface anchors on
    /// [`Self::full`] / [`Self::read_only`], and the load-bearing test
    /// suite.
    #[must_use]
    pub const fn supports_not_every_mutating_op(self) -> bool {
        !self.put || !self.delete || !self.rotate
    }

    /// Returns `true` iff this capability set advertises **every** one
    /// of the three non-mutating [`SecretOperation`] variants
    /// ([`SecretOperation::Get`], [`SecretOperation::List`],
    /// [`SecretOperation::GetVersion`]) — i.e. `self.get && self.list
    /// && self.versions`.
    ///
    /// **The universal (∀) pole of the READ-half meta-partition at
    /// the [`Capabilities`] altitude**, orthogonal to the existential
    /// (∃) pole [`Self::supports_any_non_mutating_op`] /
    /// [`Self::supports_no_non_mutating_op`] already shipped on this
    /// altitude, and the READ-half analogue of the WRITE-half ∀ pair
    /// [`Self::supports_every_mutating_op`] /
    /// [`Self::supports_not_every_mutating_op`]. Together the four
    /// predicates form the (any/no × every/not_every) × (write/read)
    /// closed matrix at the [`Capabilities`] altitude — the last
    /// remaining quantifier cell that had no direct name.
    /// `supports_every_non_mutating_op` (∀) is strictly stronger than
    /// `supports_any_non_mutating_op` (∃) — a consumer that requires
    /// the FULL read cycle (get + list + versions) rejects any partial
    /// read-capable shape (a `get`-only backend such as the shipped
    /// [`Self::read_only`], a `list`-only backend, a `get + versions`
    /// backend with no `list` enumeration) that the ∃-pole predicate
    /// would accept, while a consumer that only needs "any read
    /// capability" tolerates such partial shapes. The ∀-pole is what
    /// a full read-cycle audit backend, a per-secret history
    /// reconstruction gate (needs `get` for current value, `list` for
    /// enumeration, `versions` for history in one call chain), or a
    /// snapshot-exporter pipeline reasons about, where a partial-read
    /// backend cannot cover the workload.
    ///
    /// **Cross-altitude weld with [`SecretOperation::is_non_mutating`].**
    /// The ∀ pole agrees structurally with the universal quantifier
    /// over the non-mutating half of the operation axis:
    /// `caps.supports_every_non_mutating_op() == SecretOperation::ALL
    /// .iter().all(|op| !op.is_non_mutating() || caps.supports(*op))`.
    /// Pinned by
    /// [`tests::capabilities_supports_every_non_mutating_op_agrees_with_operation_is_non_mutating`].
    ///
    /// **Cross-quantifier implication weld with [`Self::supports_any_non_mutating_op`].**
    /// The ∀ pole implies the ∃ pole:
    /// `caps.supports_every_non_mutating_op() ⇒
    /// caps.supports_any_non_mutating_op()`. Pinned by
    /// [`tests::capabilities_supports_every_non_mutating_op_implies_supports_any_non_mutating_op`].
    ///
    /// **Cross-surface anchors on the shipped constructors.**
    /// [`Capabilities::full`] advertises every non-mutating operation,
    /// so `Capabilities::full().supports_every_non_mutating_op()` is
    /// `true` — pinned by
    /// [`tests::capabilities_full_supports_every_non_mutating_op`].
    /// [`Capabilities::read_only`] advertises `get` alone (refusing
    /// `list` and `versions`), so
    /// `Capabilities::read_only().supports_every_non_mutating_op()` is
    /// `false` — pinned by
    /// [`tests::capabilities_read_only_supports_not_every_non_mutating_op`].
    /// Note the (deliberate) asymmetry with the ∃ pair
    /// [`Self::supports_any_non_mutating_op`] / [`Self::supports_no_non_mutating_op`]:
    /// on the ∃ axis BOTH shipped constructors sit on the read-capable
    /// pole (both `full()` and `read_only()` fire ∃), while on the ∀
    /// axis the two constructors sit on OPPOSITE poles — `read_only`
    /// is precisely the partial-read shape that distinguishes the two
    /// quantifiers on this half.
    ///
    /// Written as an explicit `self.get && self.list && self.versions`
    /// conjunction over exactly the three non-mutating fields (rather
    /// than iterating [`SecretOperation::ALL`] and dispatching through
    /// [`Self::supports`] on every arm), so a future [`Capabilities`]
    /// field rename fails at `cargo build` here before drifting through
    /// any consumer that reasons about the ∀ pole, and a hypothetical
    /// fourth non-mutating operation landing on [`SecretOperation`]
    /// (a `Watch` streaming subscription, a `Metadata` read) surfaces
    /// at the cross-altitude agreement pin above rather than silently
    /// changing this predicate's answer.
    ///
    /// The compound ↔ complement law
    /// (`caps.supports_every_non_mutating_op() ==
    /// !caps.supports_not_every_non_mutating_op()`) is pinned by
    /// [`tests::capabilities_supports_every_non_mutating_op_is_complement_of_supports_not_every_non_mutating_op`].
    /// The compile-time weld is pinned by
    /// [`tests::capabilities_supports_every_non_mutating_op_is_const_callable`].
    #[must_use]
    pub const fn supports_every_non_mutating_op(self) -> bool {
        self.get && self.list && self.versions
    }

    /// Returns `true` iff this capability set is **missing at least
    /// one** of the three non-mutating [`SecretOperation`] variants
    /// ([`SecretOperation::Get`], [`SecretOperation::List`],
    /// [`SecretOperation::GetVersion`]) — i.e. `!self.get || !self.list
    /// || !self.versions`.
    ///
    /// Complement pole of [`Self::supports_every_non_mutating_op`] on
    /// the universal (∀) axis at the [`Capabilities`] altitude;
    /// equivalent to `!self.supports_every_non_mutating_op()`. Named
    /// separately (rather than left as a negation) so consumers reading
    /// the "missing at least one read op" half of the axis no longer
    /// negate [`Self::supports_every_non_mutating_op`] — a shape whose
    /// polarity a future fourth non-mutating [`SecretOperation`]
    /// variant with its own [`Capabilities`] field would silently
    /// include in the negation without extending this predicate. The
    /// direct predicate, written as
    /// `!self.get || !self.list || !self.versions` over exactly the
    /// three currently-non-mutating fields, forces the maintainer
    /// landing the new [`Capabilities`] field to update this arm in
    /// lockstep with the new field — or the cross-altitude weld with
    /// [`SecretOperation::is_non_mutating`] one altitude down diverges
    /// at test time.
    ///
    /// See [`Self::supports_every_non_mutating_op`] for the full
    /// compound-polarity contract, the cross-altitude weld with
    /// [`SecretOperation::is_non_mutating`], the cross-quantifier
    /// implication (∀ ⇒ ∃), the cross-surface anchors on
    /// [`Self::full`] / [`Self::read_only`] (on OPPOSITE poles of this
    /// axis, in contrast to the ∃ pair where both constructors sit on
    /// the read-capable pole), and the load-bearing test suite.
    #[must_use]
    pub const fn supports_not_every_non_mutating_op(self) -> bool {
        !self.get || !self.list || !self.versions
    }

    /// Returns `true` iff this capability set advertises AT LEAST ONE
    /// of the six [`SecretOperation`] variants — i.e. `self.get ||
    /// self.list || self.put || self.delete || self.rotate ||
    /// self.versions`.
    ///
    /// **The whole-set existential (∃) pole at the [`Capabilities`]
    /// altitude**, orthogonal to (and welding back together) the
    /// (any/no × every/not_every) × (write/read) closed matrix already
    /// shipped at this altitude. The four partitioned ∃/∀ pairs
    /// ([`Self::supports_any_mutating_op`] / [`Self::supports_no_mutating_op`],
    /// [`Self::supports_any_non_mutating_op`] / [`Self::supports_no_non_mutating_op`],
    /// [`Self::supports_every_mutating_op`] / [`Self::supports_not_every_mutating_op`],
    /// [`Self::supports_every_non_mutating_op`] / [`Self::supports_not_every_non_mutating_op`])
    /// each read ONE half of the mutating-vs-non-mutating meta-partition
    /// [`SecretOperation::is_mutating`] / [`SecretOperation::is_non_mutating`]
    /// names one altitude down; this pair reads the WHOLE
    /// [`SecretOperation::ALL`] universe at once, without a consumer
    /// having to compose the two halves inline through the meta-partition
    /// union law below.
    ///
    /// **Cross-altitude weld with [`SecretOperation`].** The ∃ pole
    /// agrees structurally with the existential quantifier over the
    /// whole operation axis: `caps.supports_any_op() ==
    /// SecretOperation::ALL.iter().any(|op| caps.supports(*op))`. Pinned
    /// by
    /// [`tests::capabilities_supports_any_op_agrees_with_operation_axis_disjunction`].
    ///
    /// **Meta-partition union law.** The whole-set ∃ pole is the union
    /// of the two partitioned ∃ poles across the mutating-vs-non-mutating
    /// meta-partition: `caps.supports_any_op() ==
    /// caps.supports_any_mutating_op() ||
    /// caps.supports_any_non_mutating_op()`, and dually
    /// `caps.supports_no_op() == caps.supports_no_mutating_op() &&
    /// caps.supports_no_non_mutating_op()`. Pinned by
    /// [`tests::capabilities_supports_any_op_agrees_with_meta_partition_union`].
    ///
    /// **Cross-quantifier implication weld with [`Self::supports_every_op`].**
    /// The ∀ pole implies the ∃ pole: `caps.supports_every_op() ⇒
    /// caps.supports_any_op()`. Pinned by
    /// [`tests::capabilities_supports_every_op_implies_supports_any_op`].
    ///
    /// **Cross-surface anchors on the shipped constructors.**
    /// [`Capabilities::full`] advertises every operation, so
    /// `Capabilities::full().supports_any_op()` is `true` — pinned by
    /// [`tests::capabilities_full_supports_any_op`].
    /// [`Capabilities::read_only`] advertises `get` alone, so
    /// `Capabilities::read_only().supports_any_op()` is `true` — pinned
    /// by [`tests::capabilities_read_only_supports_any_op`]. Both shipped
    /// constructors sit on the *capable* pole of this axis by construction;
    /// the ∃-mute pole is only reachable via a hand-built all-`false`
    /// [`Capabilities`] value (a hypothetical "resolved backend
    /// advertises no operation whatsoever" refusal-cache entry, an
    /// attestation manifest recording a torn/incomplete client init).
    ///
    /// Written as an explicit `self.get || self.list || self.put ||
    /// self.delete || self.rotate || self.versions` disjunction over
    /// exactly the six [`Capabilities`] fields (rather than iterating
    /// [`SecretOperation::ALL`] and dispatching through [`Self::supports`]
    /// on every arm, and rather than delegating to `supports_any_mutating_op
    /// () || supports_any_non_mutating_op()`), so the compile-time weld
    /// to the six specific field identifiers stays load-bearing: a
    /// future [`Capabilities`] field rename (`put` → `create`, `rotate`
    /// → `renew`, `versions` → `history`) fails at `cargo build` here
    /// before drifting through any consumer that reasons about the
    /// whole-set ∃ pole, and a hypothetical seventh [`SecretOperation`]
    /// variant with its own [`Capabilities`] field surfaces at the
    /// cross-altitude agreement pin above rather than silently changing
    /// this predicate's answer. Idiom-peer of the explicit-disjunction
    /// discipline on [`Self::supports_any_mutating_op`] /
    /// [`Self::supports_any_non_mutating_op`] at this same altitude.
    ///
    /// The compound ↔ complement law (`caps.supports_any_op() ==
    /// !caps.supports_no_op()`) is pinned by
    /// [`tests::capabilities_supports_any_op_is_complement_of_supports_no_op`].
    /// The compile-time weld is pinned by
    /// [`tests::capabilities_supports_any_op_is_const_callable`].
    #[must_use]
    pub const fn supports_any_op(self) -> bool {
        self.get || self.list || self.put || self.delete || self.rotate || self.versions
    }

    /// Returns `true` iff this capability set advertises NONE of the
    /// six [`SecretOperation`] variants — i.e. `!self.get && !self.list
    /// && !self.put && !self.delete && !self.rotate && !self.versions`.
    ///
    /// Complement pole of [`Self::supports_any_op`] on the whole-set
    /// existential axis at the [`Capabilities`] altitude; equivalent to
    /// `!self.supports_any_op()`. Named separately (rather than left as
    /// a negation) so consumers reading the "advertises no operation
    /// whatsoever" half of the axis no longer negate
    /// [`Self::supports_any_op`] — a shape whose polarity a future
    /// seventh [`SecretOperation`] variant with its own [`Capabilities`]
    /// field would silently include in the negation without extending
    /// this predicate. The direct predicate, written as `!self.get &&
    /// !self.list && !self.put && !self.delete && !self.rotate &&
    /// !self.versions` over exactly the six currently-declared fields,
    /// forces the maintainer landing the new [`Capabilities`] field to
    /// update this arm in lockstep with the new field — or the
    /// cross-altitude weld with the operation axis one altitude down
    /// diverges at test time.
    ///
    /// See [`Self::supports_any_op`] for the full compound-polarity
    /// contract, the cross-altitude weld, the meta-partition union
    /// law, the cross-quantifier implication (∀ ⇒ ∃), the cross-surface
    /// anchors on [`Self::full`] / [`Self::read_only`] (both on the
    /// *capable* pole by construction, so this ∃-mute pole is only
    /// reachable via a hand-built all-`false` [`Capabilities`] value),
    /// and the load-bearing test suite.
    #[must_use]
    pub const fn supports_no_op(self) -> bool {
        !self.get && !self.list && !self.put && !self.delete && !self.rotate && !self.versions
    }

    /// Returns `true` iff this capability set advertises ALL SIX
    /// [`SecretOperation`] variants — i.e. `self.get && self.list &&
    /// self.put && self.delete && self.rotate && self.versions`.
    ///
    /// **The whole-set universal (∀) pole at the [`Capabilities`]
    /// altitude**, orthogonal to (and welding back together) the two
    /// partitioned ∀ pairs [`Self::supports_every_mutating_op`] /
    /// [`Self::supports_not_every_mutating_op`] and
    /// [`Self::supports_every_non_mutating_op`] /
    /// [`Self::supports_not_every_non_mutating_op`] already shipped on
    /// this altitude. The ∀ pole reads the WHOLE
    /// [`SecretOperation::ALL`] universe at once and is the direct
    /// characterisation of the shipped [`Self::full`] constructor —
    /// `caps.supports_every_op() == (caps == Capabilities::full())` by
    /// construction — pinned by
    /// [`tests::capabilities_supports_every_op_agrees_with_full_constructor`].
    ///
    /// **Cross-altitude weld with [`SecretOperation`].** The ∀ pole
    /// agrees structurally with the universal quantifier over the whole
    /// operation axis: `caps.supports_every_op() ==
    /// SecretOperation::ALL.iter().all(|op| caps.supports(*op))`. Pinned
    /// by
    /// [`tests::capabilities_supports_every_op_agrees_with_operation_axis_conjunction`].
    ///
    /// **Meta-partition intersection law.** The whole-set ∀ pole is the
    /// intersection of the two partitioned ∀ poles across the mutating-
    /// vs-non-mutating meta-partition: `caps.supports_every_op() ==
    /// caps.supports_every_mutating_op() &&
    /// caps.supports_every_non_mutating_op()`. Pinned by
    /// [`tests::capabilities_supports_every_op_agrees_with_meta_partition_intersection`].
    ///
    /// **Cross-quantifier implication weld with [`Self::supports_any_op`].**
    /// The ∀ pole implies the ∃ pole on this same whole-set axis:
    /// `caps.supports_every_op() ⇒ caps.supports_any_op()`. Pinned by
    /// [`tests::capabilities_supports_every_op_implies_supports_any_op`].
    ///
    /// Written as an explicit conjunction over exactly the six
    /// [`Capabilities`] fields (rather than iterating
    /// [`SecretOperation::ALL`] or delegating to the meta-partition
    /// intersection), so the compile-time weld to the six specific
    /// field identifiers stays load-bearing under a future field rename
    /// or a hypothetical seventh variant, matching the explicit-arms
    /// discipline of the four partitioned ∃/∀ predicates already at
    /// this altitude.
    ///
    /// The compound ↔ complement law
    /// (`caps.supports_every_op() ==
    /// !caps.supports_not_every_op()`) is pinned by
    /// [`tests::capabilities_supports_every_op_is_complement_of_supports_not_every_op`].
    /// The compile-time weld is pinned by
    /// [`tests::capabilities_supports_every_op_is_const_callable`].
    #[must_use]
    pub const fn supports_every_op(self) -> bool {
        self.get && self.list && self.put && self.delete && self.rotate && self.versions
    }

    /// Returns `true` iff this capability set is **missing at least
    /// one** of the six [`SecretOperation`] variants — i.e. `!self.get
    /// || !self.list || !self.put || !self.delete || !self.rotate ||
    /// !self.versions`.
    ///
    /// Complement pole of [`Self::supports_every_op`] on the whole-set
    /// universal axis at the [`Capabilities`] altitude; equivalent to
    /// `!self.supports_every_op()`. Named separately (rather than left
    /// as a negation) so consumers reading the "missing at least one
    /// op" half of the axis no longer negate [`Self::supports_every_op`]
    /// — a shape whose polarity a future seventh [`SecretOperation`]
    /// variant with its own [`Capabilities`] field would silently include
    /// in the negation without extending this predicate. The direct
    /// predicate is written as `!self.get || !self.list || !self.put ||
    /// !self.delete || !self.rotate || !self.versions` over exactly the
    /// six currently-declared fields.
    ///
    /// See [`Self::supports_every_op`] for the full compound-polarity
    /// contract, the cross-altitude weld, the meta-partition
    /// intersection law, and the cross-quantifier implication (∀ ⇒ ∃).
    #[must_use]
    pub const fn supports_not_every_op(self) -> bool {
        !self.get || !self.list || !self.put || !self.delete || !self.rotate || !self.versions
    }

    /// Returns the number of [`SecretOperation`] variants this capability
    /// set advertises — a `u8` in the range `0..=6`. Written as
    /// `(self.get as u8) + (self.list as u8) + (self.put as u8) +
    /// (self.delete as u8) + (self.rotate as u8) + (self.versions as u8)`
    /// over exactly the six [`Capabilities`] fields (the primitive
    /// `bool as u8` cast is `const`-callable on stable Rust, unlike
    /// `u8::from(bool)`, so the projection stays inside a `const fn`
    /// alongside the twelve compound-polarity predicates at this same
    /// altitude).
    ///
    /// **The cardinality altitude at the [`Capabilities`] altitude**,
    /// orthogonal to (and welding together via arithmetic identities)
    /// the whole `(any/no × every/not_every) × (write/read/whole)`
    /// twelve-predicate compound-polarity matrix already shipped on
    /// this altitude. Where each of the twelve compound predicates
    /// answers ONE binary polarity question about a subset of the
    /// operation universe, this projection resolves the full
    /// cardinality in one shot, and the twelve compound-polarity
    /// predicates re-derive from it by threshold ((`> 0` ⇒ ∃-whole,
    /// `== 0` ⇒ ¬∃-whole, `== 6` ⇒ ∀-whole, `< 6` ⇒ ¬∀-whole) rather
    /// than by an inline six-way disjunction / conjunction over the
    /// same six fields at every call site.
    ///
    /// **Cross-surface anchors on the shipped constructors.**
    /// [`Capabilities::full`] advertises every operation, so
    /// `Capabilities::full().supported_op_count() == 6` — pinned by
    /// [`tests::capabilities_full_supported_op_count_is_six`].
    /// [`Capabilities::read_only`] advertises `get` alone, so
    /// `Capabilities::read_only().supported_op_count() == 1` — pinned
    /// by [`tests::capabilities_read_only_supported_op_count_is_one`].
    /// The hand-built all-`false` shape returns `0` — pinned by
    /// [`tests::capabilities_empty_supported_op_count_is_zero`].
    ///
    /// **Cross-altitude weld with [`SecretOperation`].** The
    /// cardinality agrees structurally with counting supported ops via
    /// the whole operation axis: `caps.supported_op_count() as usize ==
    /// SecretOperation::ALL.iter().filter(|op| caps.supports(**op)).count()`.
    /// Pinned by
    /// [`tests::capabilities_supported_op_count_agrees_with_operation_axis_filter_count`].
    ///
    /// **Cross-quantifier welds with the twelve compound-polarity
    /// predicates.** The cardinality resolves the whole matrix at
    /// once through the four threshold identities:
    /// `caps.supports_any_op() == (caps.supported_op_count() > 0)`,
    /// `caps.supports_no_op() == (caps.supported_op_count() == 0)`,
    /// `caps.supports_every_op() == (caps.supported_op_count() == 6)`,
    /// `caps.supports_not_every_op() == (caps.supported_op_count() < 6)`.
    /// Pinned by
    /// [`tests::capabilities_supported_op_count_thresholds_agree_with_whole_set_compound_polarity_matrix`].
    ///
    /// **Bounds pin.** `caps.supported_op_count()` stays in the closed
    /// range `0..=6` for every reachable [`Capabilities`] shape (the
    /// bound is exactly `SecretOperation::ALL.len()` for the shipped
    /// six-variant operation axis, and rises in lockstep should a
    /// seventh variant with its own [`Capabilities`] field land). Pinned
    /// by
    /// [`tests::capabilities_supported_op_count_stays_within_all_len_bound`].
    ///
    /// Written as an explicit six-term `u8::from` sum over exactly the
    /// six [`Capabilities`] fields (rather than iterating
    /// [`SecretOperation::ALL`] and dispatching through
    /// [`Self::supports`] on every arm, and rather than deriving the
    /// count from `Self::supports_every_op() as u8 * 6 + …` gymnastics),
    /// so the compile-time weld to the six specific field identifiers
    /// stays load-bearing: a future [`Capabilities`] field rename
    /// (`put` → `create`, `rotate` → `renew`, `versions` → `history`)
    /// fails at `cargo build` here before drifting through any consumer
    /// that reads the cardinality directly, and a hypothetical seventh
    /// [`SecretOperation`] variant with its own [`Capabilities`] field
    /// surfaces at the cross-altitude filter-count weld above rather
    /// than silently ceiling this predicate's answer at six. Matches the
    /// explicit-arms discipline of the twelve compound-polarity
    /// predicates already at this altitude.
    ///
    /// The compile-time const weld is pinned by
    /// [`tests::capabilities_supported_op_count_is_const_callable`].
    #[must_use]
    pub const fn supported_op_count(self) -> u8 {
        (self.get as u8)
            + (self.list as u8)
            + (self.put as u8)
            + (self.delete as u8)
            + (self.rotate as u8)
            + (self.versions as u8)
    }

    /// Returns the CARDINALITY of the mutating [`SecretOperation`]
    /// variants ([`SecretOperation::Put`], [`SecretOperation::Delete`],
    /// [`SecretOperation::Rotate`]) advertised by this capability set —
    /// i.e. `(self.put as u8) + (self.delete as u8) + (self.rotate as u8)`,
    /// a `u8` in the closed range `0..=3` (exactly the write-half
    /// meta-partition size for the shipped six-variant operation axis).
    ///
    /// **The WRITE-half slice of the cardinality projection at the
    /// [`Capabilities`] altitude**, one of the two per-half slices
    /// (with [`Self::supported_non_mutating_op_count`] on the read pole)
    /// whose sum is the whole-set count [`Self::supported_op_count`]
    /// via the meta-partition sum law. Orthogonal to (and welding
    /// together via arithmetic threshold identities) the four write-half
    /// compound-polarity predicates already shipped at this altitude:
    /// [`Self::supports_any_mutating_op`], [`Self::supports_no_mutating_op`],
    /// [`Self::supports_every_mutating_op`], [`Self::supports_not_every_mutating_op`].
    ///
    /// **Meta-partition sum law with the whole-set count.**
    /// `caps.supported_op_count() == caps.supported_mutating_op_count()
    /// + caps.supported_non_mutating_op_count()` for every reachable
    /// shape — the load-bearing weld that recovers the whole-set count
    /// from the two per-half slices, and pins any drift on ONE half at
    /// test time before a consumer can observe the disagreement. Pinned
    /// by [`tests::capabilities_supported_op_count_is_sum_of_per_half_op_counts`].
    ///
    /// **Threshold identities with the write-half compound-polarity pairs.**
    /// The write-half ∃/¬∃/∀/¬∀ quartet is recovered from this count
    /// through the four threshold identities:
    /// `caps.supports_any_mutating_op() ==
    ///     (caps.supported_mutating_op_count() > 0)`,
    /// `caps.supports_no_mutating_op() ==
    ///     (caps.supported_mutating_op_count() == 0)`,
    /// `caps.supports_every_mutating_op() ==
    ///     (caps.supported_mutating_op_count() == 3)`,
    /// `caps.supports_not_every_mutating_op() ==
    ///     (caps.supported_mutating_op_count() < 3)`.
    /// Pinned by
    /// [`tests::capabilities_supported_mutating_op_count_thresholds_agree_with_write_half_compound_polarity_matrix`].
    ///
    /// **Cross-altitude weld with the operation axis one altitude down.**
    /// `caps.supported_mutating_op_count() ==
    /// SecretOperation::ALL.iter().filter(|op| op.is_mutating() &&
    /// caps.supports(**op)).count()`. Pinned by
    /// [`tests::capabilities_supported_mutating_op_count_agrees_with_operation_axis_filter_count`].
    ///
    /// **Bounds pin.** `caps.supported_mutating_op_count()` stays in
    /// the closed range `0..=3` for every reachable [`Capabilities`]
    /// shape (the bound is exactly the write-half meta-partition size
    /// for the shipped six-variant operation axis, and rises in
    /// lockstep should a fourth mutating variant with its own
    /// [`Capabilities`] field land). Pinned by
    /// [`tests::capabilities_supported_mutating_op_count_stays_within_write_half_bound`].
    ///
    /// Written as an explicit three-term `bool as u8` sum over exactly
    /// the three currently-mutating [`Capabilities`] fields (`put`,
    /// `delete`, `rotate`) rather than iterating
    /// [`SecretOperation::ALL`] and dispatching through
    /// [`Self::supports`] on every arm — so the compile-time weld to
    /// the three specific write-half field identifiers stays
    /// load-bearing: a future [`Capabilities`] field rename fails at
    /// `cargo build` here before drifting through any consumer that
    /// reads the write-half cardinality, and a hypothetical fourth
    /// mutating [`SecretOperation`] variant with its own
    /// [`Capabilities`] field surfaces at the cross-altitude filter-
    /// count agreement pin (via [`SecretOperation::is_mutating`]) rather
    /// than silently ceiling this predicate's answer at three. Matches
    /// the explicit-arms discipline of [`Self::supports_any_mutating_op`]
    /// and its three siblings at this same altitude, and of
    /// [`Self::supported_op_count`] one meta-partition step wider.
    ///
    /// The compile-time const weld is pinned by
    /// [`tests::capabilities_supported_mutating_op_count_is_const_callable`].
    #[must_use]
    pub const fn supported_mutating_op_count(self) -> u8 {
        (self.put as u8) + (self.delete as u8) + (self.rotate as u8)
    }

    /// Returns the CARDINALITY of the non-mutating [`SecretOperation`]
    /// variants ([`SecretOperation::Get`], [`SecretOperation::List`],
    /// [`SecretOperation::GetVersion`]) advertised by this capability
    /// set — i.e. `(self.get as u8) + (self.list as u8) +
    /// (self.versions as u8)`, a `u8` in the closed range `0..=3`
    /// (exactly the read-half meta-partition size for the shipped
    /// six-variant operation axis).
    ///
    /// **The READ-half slice of the cardinality projection at the
    /// [`Capabilities`] altitude**, one of the two per-half slices
    /// (with [`Self::supported_mutating_op_count`] on the write pole)
    /// whose sum is the whole-set count [`Self::supported_op_count`]
    /// via the meta-partition sum law. Orthogonal to (and welding
    /// together via arithmetic threshold identities) the four read-half
    /// compound-polarity predicates already shipped at this altitude:
    /// [`Self::supports_any_non_mutating_op`], [`Self::supports_no_non_mutating_op`],
    /// [`Self::supports_every_non_mutating_op`], [`Self::supports_not_every_non_mutating_op`].
    ///
    /// **Meta-partition sum law with the whole-set count.**
    /// `caps.supported_op_count() == caps.supported_mutating_op_count()
    /// + caps.supported_non_mutating_op_count()` for every reachable
    /// shape — the load-bearing weld that recovers the whole-set count
    /// from the two per-half slices, and pins any drift on ONE half at
    /// test time before a consumer can observe the disagreement. Pinned
    /// by [`tests::capabilities_supported_op_count_is_sum_of_per_half_op_counts`].
    ///
    /// **Threshold identities with the read-half compound-polarity pairs.**
    /// The read-half ∃/¬∃/∀/¬∀ quartet is recovered from this count
    /// through the four threshold identities:
    /// `caps.supports_any_non_mutating_op() ==
    ///     (caps.supported_non_mutating_op_count() > 0)`,
    /// `caps.supports_no_non_mutating_op() ==
    ///     (caps.supported_non_mutating_op_count() == 0)`,
    /// `caps.supports_every_non_mutating_op() ==
    ///     (caps.supported_non_mutating_op_count() == 3)`,
    /// `caps.supports_not_every_non_mutating_op() ==
    ///     (caps.supported_non_mutating_op_count() < 3)`.
    /// Pinned by
    /// [`tests::capabilities_supported_non_mutating_op_count_thresholds_agree_with_read_half_compound_polarity_matrix`].
    ///
    /// **Cross-altitude weld with the operation axis one altitude down.**
    /// `caps.supported_non_mutating_op_count() ==
    /// SecretOperation::ALL.iter().filter(|op| op.is_non_mutating() &&
    /// caps.supports(**op)).count()`. Pinned by
    /// [`tests::capabilities_supported_non_mutating_op_count_agrees_with_operation_axis_filter_count`].
    ///
    /// **Bounds pin.** `caps.supported_non_mutating_op_count()` stays
    /// in the closed range `0..=3` for every reachable [`Capabilities`]
    /// shape (the bound is exactly the read-half meta-partition size
    /// for the shipped six-variant operation axis, and rises in
    /// lockstep should a fourth non-mutating variant with its own
    /// [`Capabilities`] field land). Pinned by
    /// [`tests::capabilities_supported_non_mutating_op_count_stays_within_read_half_bound`].
    ///
    /// Written as an explicit three-term `bool as u8` sum over exactly
    /// the three currently-non-mutating [`Capabilities`] fields (`get`,
    /// `list`, `versions`) rather than iterating
    /// [`SecretOperation::ALL`] and dispatching through
    /// [`Self::supports`] on every arm — so the compile-time weld to
    /// the three specific read-half field identifiers stays
    /// load-bearing: a future [`Capabilities`] field rename fails at
    /// `cargo build` here before drifting through any consumer that
    /// reads the read-half cardinality, and a hypothetical fourth
    /// non-mutating [`SecretOperation`] variant with its own
    /// [`Capabilities`] field surfaces at the cross-altitude filter-
    /// count agreement pin (via [`SecretOperation::is_non_mutating`])
    /// rather than silently ceiling this predicate's answer at three.
    /// Matches the explicit-arms discipline of
    /// [`Self::supports_any_non_mutating_op`] and its three siblings
    /// at this same altitude, and of [`Self::supported_op_count`] one
    /// meta-partition step wider.
    ///
    /// The compile-time const weld is pinned by
    /// [`tests::capabilities_supported_non_mutating_op_count_is_const_callable`].
    #[must_use]
    pub const fn supported_non_mutating_op_count(self) -> u8 {
        (self.get as u8) + (self.list as u8) + (self.versions as u8)
    }

    /// Returns the CARDINALITY of the [`SecretOperation`] variants NOT
    /// advertised by this capability set — i.e. `(!self.get as u8) +
    /// (!self.list as u8) + (!self.put as u8) + (!self.delete as u8) +
    /// (!self.rotate as u8) + (!self.versions as u8)`, a `u8` in the
    /// closed range `0..=6` (exactly `SecretOperation::ALL.len()` for the
    /// shipped six-variant operation axis).
    ///
    /// **The compound-polarity sibling of [`Self::supported_op_count`]
    /// at the [`Capabilities`] altitude** — the complement projection
    /// that closes the pair via the axis-cardinality sum-complement law
    /// `caps.supported_op_count() + caps.unsupported_op_count() ==
    /// SecretOperation::ALL.len() as u8`. Idiom-peer of the
    /// (any/no × every/not_every) × (write/read/whole) compound-polarity
    /// matrix already shipped at this altitude: each shipped whole-set
    /// polarity predicate has a sibling recovered from this count
    /// through the four inverse threshold identities.
    ///
    /// **Cross-surface anchors on the shipped constructors.**
    /// [`Capabilities::full`] advertises every operation, so
    /// `Capabilities::full().unsupported_op_count() == 0` — pinned by
    /// [`tests::capabilities_full_unsupported_op_count_is_zero`].
    /// [`Capabilities::read_only`] advertises `get` alone, so
    /// `Capabilities::read_only().unsupported_op_count() == 5` — pinned
    /// by [`tests::capabilities_read_only_unsupported_op_count_is_five`].
    /// The hand-built all-`false` shape returns `6` — pinned by
    /// [`tests::capabilities_empty_unsupported_op_count_is_six`].
    ///
    /// **Axis-cardinality sum-complement law with the shipped
    /// projection.** `caps.supported_op_count() +
    /// caps.unsupported_op_count() == SecretOperation::ALL.len() as u8`
    /// for every reachable [`Capabilities`] shape — the load-bearing
    /// weld that recovers the whole-set cardinality bound from the two
    /// polarity slices, and pins any drift on ONE of the two counts at
    /// test time before a consumer can observe the disagreement. Pinned
    /// by
    /// [`tests::capabilities_supported_and_unsupported_op_counts_sum_to_axis_cardinality`].
    ///
    /// **Cross-altitude weld with the operation axis one altitude down.**
    /// `caps.unsupported_op_count() as usize ==
    /// SecretOperation::ALL.iter().filter(|op|
    /// !caps.supports(**op)).count()`. Pinned by
    /// [`tests::capabilities_unsupported_op_count_agrees_with_operation_axis_filter_count`].
    ///
    /// **Inverse threshold identities with the whole-set compound-
    /// polarity quartet.** The whole-set ∃/¬∃/∀/¬∀ matrix is recovered
    /// from this count through the four inverse threshold identities:
    /// `caps.supports_no_op() == (caps.unsupported_op_count() == 6)`,
    /// `caps.supports_every_op() == (caps.unsupported_op_count() == 0)`,
    /// `caps.supports_any_op() == (caps.unsupported_op_count() < 6)`,
    /// `caps.supports_not_every_op() == (caps.unsupported_op_count() > 0)`.
    /// Pinned by
    /// [`tests::capabilities_unsupported_op_count_thresholds_agree_with_whole_set_compound_polarity_matrix`].
    ///
    /// **Bounds pin.** `caps.unsupported_op_count()` stays in the closed
    /// range `0..=6` for every reachable [`Capabilities`] shape (the
    /// bound is exactly `SecretOperation::ALL.len()` for the shipped
    /// six-variant operation axis, and rises in lockstep should a
    /// seventh variant with its own [`Capabilities`] field land). Pinned
    /// by
    /// [`tests::capabilities_unsupported_op_count_stays_within_all_len_bound`].
    ///
    /// Written as an explicit six-term `bool as u8` sum over the negated
    /// [`Capabilities`] fields (rather than deriving from
    /// `SecretOperation::ALL.len() as u8 - self.supported_op_count()`
    /// via the sum-complement law), so the compile-time weld to the six
    /// specific field identifiers stays load-bearing: a future
    /// [`Capabilities`] field rename fails at `cargo build` here before
    /// drifting through any consumer that reads the complement
    /// cardinality, and a hypothetical seventh [`SecretOperation`]
    /// variant with its own [`Capabilities`] field surfaces at the
    /// cross-altitude filter-count weld above rather than silently
    /// ceiling this predicate's answer at six. The two projections stay
    /// independent witnesses of the same underlying six-field state, and
    /// the sum-complement pin catches drift on either single one.
    /// Matches the explicit-arms discipline of [`Self::supported_op_count`]
    /// and its two per-half slices at this same altitude, and of the
    /// twelve compound-polarity predicates before them.
    ///
    /// The compile-time const weld is pinned by
    /// [`tests::capabilities_unsupported_op_count_is_const_callable`].
    #[must_use]
    pub const fn unsupported_op_count(self) -> u8 {
        (!self.get as u8)
            + (!self.list as u8)
            + (!self.put as u8)
            + (!self.delete as u8)
            + (!self.rotate as u8)
            + (!self.versions as u8)
    }

    /// Returns the CARDINALITY of the mutating [`SecretOperation`]
    /// variants ([`SecretOperation::Put`], [`SecretOperation::Delete`],
    /// [`SecretOperation::Rotate`]) NOT advertised by this capability set —
    /// i.e. `(!self.put as u8) + (!self.delete as u8) + (!self.rotate as u8)`,
    /// a `u8` in the closed range `0..=3` (exactly the write-half
    /// meta-partition size for the shipped six-variant operation axis).
    ///
    /// **The WRITE-half slice of the COMPLEMENT projection at the
    /// [`Capabilities`] altitude** — the compound-polarity sibling of
    /// [`Self::supported_mutating_op_count`], closing the write-half pair
    /// via the meta-partition sum-complement law
    /// `caps.supported_mutating_op_count() +
    /// caps.unsupported_mutating_op_count() == 3`. Idiom-peer of the
    /// whole-set complement [`Self::unsupported_op_count`] one meta-partition
    /// step wider: the same explicit-negated-fields discipline restricted
    /// to the three write-half [`Capabilities`] fields (`put`, `delete`,
    /// `rotate`).
    ///
    /// **Cross-surface anchors on the shipped constructors.**
    /// [`Capabilities::full`] advertises every write-half operation, so
    /// `Capabilities::full().unsupported_mutating_op_count() == 0` —
    /// pinned by
    /// [`tests::capabilities_full_unsupported_mutating_op_count_is_zero`].
    /// [`Capabilities::read_only`] advertises `get` alone (no write-half
    /// operation), so `Capabilities::read_only().unsupported_mutating_op_count()
    /// == 3` — pinned by
    /// [`tests::capabilities_read_only_unsupported_mutating_op_count_is_three`].
    /// The hand-built all-`false` shape returns `3` — pinned by
    /// [`tests::capabilities_empty_unsupported_mutating_op_count_is_three`].
    ///
    /// **Write-half sum-complement law with the shipped supported half.**
    /// `caps.supported_mutating_op_count() +
    /// caps.unsupported_mutating_op_count() == 3` for every reachable
    /// shape — the load-bearing weld that recovers the write-half
    /// meta-partition size from the two polarity slices, and pins any
    /// drift on ONE of the two write-half counts at test time before a
    /// consumer can observe the disagreement. Pinned by
    /// [`tests::capabilities_supported_and_unsupported_mutating_op_counts_sum_to_write_half_size`].
    ///
    /// **Cross-altitude weld with the operation axis one altitude down.**
    /// `caps.unsupported_mutating_op_count() as usize ==
    /// SecretOperation::ALL.iter().filter(|op| op.is_mutating() &&
    /// !caps.supports(**op)).count()`. Pinned by
    /// [`tests::capabilities_unsupported_mutating_op_count_agrees_with_operation_axis_filter_count`].
    ///
    /// **Inverse threshold identities with the write-half compound-polarity
    /// quartet.** The write-half ∃/¬∃/∀/¬∀ matrix is recovered from this
    /// count through the four inverse threshold identities:
    /// `caps.supports_no_mutating_op() ==
    ///     (caps.unsupported_mutating_op_count() == 3)`,
    /// `caps.supports_every_mutating_op() ==
    ///     (caps.unsupported_mutating_op_count() == 0)`,
    /// `caps.supports_any_mutating_op() ==
    ///     (caps.unsupported_mutating_op_count() < 3)`,
    /// `caps.supports_not_every_mutating_op() ==
    ///     (caps.unsupported_mutating_op_count() > 0)`.
    /// Pinned by
    /// [`tests::capabilities_unsupported_mutating_op_count_thresholds_agree_with_write_half_compound_polarity_matrix`].
    ///
    /// **Bounds pin.** `caps.unsupported_mutating_op_count()` stays in
    /// the closed range `0..=3` for every reachable [`Capabilities`]
    /// shape (the bound is exactly the write-half meta-partition size
    /// for the shipped six-variant operation axis, and rises in lockstep
    /// should a fourth mutating variant with its own [`Capabilities`]
    /// field land). Pinned by
    /// [`tests::capabilities_unsupported_mutating_op_count_stays_within_write_half_bound`].
    ///
    /// Written as an explicit three-term `bool as u8` sum over exactly
    /// the three currently-mutating [`Capabilities`] fields negated
    /// (`put`, `delete`, `rotate`) rather than deriving from `3 -
    /// self.supported_mutating_op_count()` via the sum-complement law or
    /// iterating [`SecretOperation::ALL`] and dispatching through
    /// [`Self::supports`] on every arm — so the compile-time weld to the
    /// three specific write-half field identifiers stays load-bearing: a
    /// future [`Capabilities`] field rename fails at `cargo build` here
    /// before drifting through any consumer that reads the write-half
    /// complement cardinality, and a hypothetical fourth mutating
    /// [`SecretOperation`] variant with its own [`Capabilities`] field
    /// surfaces at the cross-altitude filter-count agreement pin (via
    /// [`SecretOperation::is_mutating`]) rather than silently ceiling
    /// this predicate's answer at three. The two write-half projections
    /// stay independent witnesses of the same underlying three-field
    /// state, and the sum-complement pin catches drift on either single
    /// one. Matches the explicit-arms discipline of
    /// [`Self::supported_mutating_op_count`] at the same altitude, of the
    /// whole-set complement [`Self::unsupported_op_count`] one
    /// meta-partition step wider, and of the four write-half compound-
    /// polarity predicates already at this altitude.
    ///
    /// The compile-time const weld is pinned by
    /// [`tests::capabilities_unsupported_mutating_op_count_is_const_callable`].
    #[must_use]
    pub const fn unsupported_mutating_op_count(self) -> u8 {
        (!self.put as u8) + (!self.delete as u8) + (!self.rotate as u8)
    }

    /// Returns the CARDINALITY of the non-mutating [`SecretOperation`]
    /// variants ([`SecretOperation::Get`], [`SecretOperation::List`],
    /// [`SecretOperation::GetVersion`]) NOT advertised by this capability
    /// set — i.e. `(!self.get as u8) + (!self.list as u8) +
    /// (!self.versions as u8)`, a `u8` in the closed range `0..=3`
    /// (exactly the read-half meta-partition size for the shipped
    /// six-variant operation axis).
    ///
    /// **The READ-half slice of the COMPLEMENT projection at the
    /// [`Capabilities`] altitude** — the compound-polarity sibling of
    /// [`Self::supported_non_mutating_op_count`], closing the read-half
    /// pair via the meta-partition sum-complement law
    /// `caps.supported_non_mutating_op_count() +
    /// caps.unsupported_non_mutating_op_count() == 3`. Idiom-peer of the
    /// write-half complement [`Self::unsupported_mutating_op_count`] at
    /// the same altitude and of the whole-set complement
    /// [`Self::unsupported_op_count`] one meta-partition step wider: the
    /// same explicit-negated-fields discipline restricted to the three
    /// read-half [`Capabilities`] fields (`get`, `list`, `versions`).
    /// This is the sixth and final projection at the cardinality altitude
    /// — the 2×3 `(supported, unsupported) × (whole, write-half,
    /// read-half)` matrix closes here.
    ///
    /// **Cross-surface anchors on the shipped constructors.**
    /// [`Capabilities::full`] advertises every read-half operation, so
    /// `Capabilities::full().unsupported_non_mutating_op_count() == 0` —
    /// pinned by
    /// [`tests::capabilities_full_unsupported_non_mutating_op_count_is_zero`].
    /// [`Capabilities::read_only`] advertises `get` alone on the read
    /// half (no `list`, no `versions`), so
    /// `Capabilities::read_only().unsupported_non_mutating_op_count() == 2`
    /// — pinned by
    /// [`tests::capabilities_read_only_unsupported_non_mutating_op_count_is_two`].
    /// The hand-built all-`false` shape returns `3` — pinned by
    /// [`tests::capabilities_empty_unsupported_non_mutating_op_count_is_three`].
    ///
    /// **Read-half sum-complement law with the shipped supported half.**
    /// `caps.supported_non_mutating_op_count() +
    /// caps.unsupported_non_mutating_op_count() == 3` for every reachable
    /// shape — the load-bearing weld that recovers the read-half
    /// meta-partition size from the two polarity slices, and pins any
    /// drift on ONE of the two read-half counts at test time before a
    /// consumer can observe the disagreement. Pinned by
    /// [`tests::capabilities_supported_and_unsupported_non_mutating_op_counts_sum_to_read_half_size`].
    ///
    /// **Meta-partition sum law with the whole-set complement.**
    /// `caps.unsupported_op_count() == caps.unsupported_mutating_op_count()
    /// + caps.unsupported_non_mutating_op_count()` for every reachable
    /// shape — the load-bearing weld that recovers the whole-set
    /// complement cardinality from the two per-half complement slices,
    /// mirroring the shipped supported-side meta-partition sum law
    /// `supported_op_count == supported_mutating + supported_non_mutating`.
    /// A future edit that shifts a field from one half to the other on
    /// ONE of the three complement projections (whole / write-half /
    /// read-half) diverges here. Pinned by
    /// [`tests::capabilities_unsupported_op_count_is_sum_of_per_half_unsupported_op_counts`].
    ///
    /// **Cross-altitude weld with the operation axis one altitude down.**
    /// `caps.unsupported_non_mutating_op_count() as usize ==
    /// SecretOperation::ALL.iter().filter(|op| op.is_non_mutating() &&
    /// !caps.supports(**op)).count()`. Pinned by
    /// [`tests::capabilities_unsupported_non_mutating_op_count_agrees_with_operation_axis_filter_count`].
    ///
    /// **Inverse threshold identities with the read-half compound-polarity
    /// quartet.** The read-half ∃/¬∃/∀/¬∀ matrix is recovered from this
    /// count through the four inverse threshold identities:
    /// `caps.supports_no_non_mutating_op() ==
    ///     (caps.unsupported_non_mutating_op_count() == 3)`,
    /// `caps.supports_every_non_mutating_op() ==
    ///     (caps.unsupported_non_mutating_op_count() == 0)`,
    /// `caps.supports_any_non_mutating_op() ==
    ///     (caps.unsupported_non_mutating_op_count() < 3)`,
    /// `caps.supports_not_every_non_mutating_op() ==
    ///     (caps.unsupported_non_mutating_op_count() > 0)`.
    /// Pinned by
    /// [`tests::capabilities_unsupported_non_mutating_op_count_thresholds_agree_with_read_half_compound_polarity_matrix`].
    ///
    /// **Bounds pin.** `caps.unsupported_non_mutating_op_count()` stays
    /// in the closed range `0..=3` for every reachable [`Capabilities`]
    /// shape (the bound is exactly the read-half meta-partition size for
    /// the shipped six-variant operation axis, and rises in lockstep
    /// should a fourth non-mutating variant with its own [`Capabilities`]
    /// field land). Pinned by
    /// [`tests::capabilities_unsupported_non_mutating_op_count_stays_within_read_half_bound`].
    ///
    /// Written as an explicit three-term `bool as u8` sum over exactly
    /// the three currently-non-mutating [`Capabilities`] fields negated
    /// (`get`, `list`, `versions`) rather than deriving from `3 -
    /// self.supported_non_mutating_op_count()` via the sum-complement
    /// law, from `self.unsupported_op_count() -
    /// self.unsupported_mutating_op_count()` via the meta-partition sum
    /// law, or from iterating [`SecretOperation::ALL`] and dispatching
    /// through [`Self::supports`] on every arm — so the compile-time weld
    /// to the three specific read-half field identifiers stays
    /// load-bearing: a future [`Capabilities`] field rename fails at
    /// `cargo build` here before drifting through any consumer that reads
    /// the read-half complement cardinality, and a hypothetical fourth
    /// non-mutating [`SecretOperation`] variant with its own
    /// [`Capabilities`] field surfaces at the cross-altitude filter-count
    /// agreement pin (via [`SecretOperation::is_non_mutating`]) rather
    /// than silently ceiling this predicate's answer at three. The two
    /// read-half projections stay independent witnesses of the same
    /// underlying three-field state, and the sum-complement pin catches
    /// drift on either single one. Matches the explicit-arms discipline
    /// of [`Self::supported_non_mutating_op_count`] at the same altitude,
    /// of the write-half complement [`Self::unsupported_mutating_op_count`]
    /// at the same altitude, and of the whole-set complement
    /// [`Self::unsupported_op_count`] one meta-partition step wider.
    ///
    /// The compile-time const weld is pinned by
    /// [`tests::capabilities_unsupported_non_mutating_op_count_is_const_callable`].
    #[must_use]
    pub const fn unsupported_non_mutating_op_count(self) -> u8 {
        (!self.get as u8) + (!self.list as u8) + (!self.versions as u8)
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

    /// Returns `true` for [`Self::Mem`]; equivalent to
    /// `self == SecretClientKind::Mem`. Per-variant sibling predicate
    /// on the closed seven-way runtime-client kind partition.
    ///
    /// Idiom-peer of [`crate::secret::SecretBackendKind::is_literal`]
    /// / [`crate::secret::SecretBackendKind::is_command`] / … on the
    /// payload-carrying secret-backend kind axis (commit `9dc6d1f`),
    /// [`crate::SecretErrorKind::is_not_found`] /
    /// [`crate::SecretErrorKind::is_unauthorized`] / … on the
    /// secret-client error-kind axis (commit `6b67a81`),
    /// [`crate::SecretOperation::is_get`] /
    /// [`crate::SecretOperation::is_list`] / … on the secret-client
    /// operation axis (commit `8c326b1`),
    /// [`crate::ConfigSourceKind::is_defaults`] /
    /// [`crate::ConfigSourceKind::is_env`] /
    /// [`crate::ConfigSourceKind::is_file`] on the shikumi-side
    /// layer-kind axis (commit `9600b8b`), and [`crate::Format::is_yaml`]
    /// / [`crate::Format::is_toml`] / … on the top-level config-file
    /// format axis (commit `95f2c76`): same sibling-predicate
    /// discipline applied to the runtime `SecretClient` implementor
    /// axis, the last surface-carrying closed-enum primitive in the
    /// crate holding zero per-variant sibling predicates.
    ///
    /// The seven sibling predicates form a closed disjoint partition
    /// of [`Self::ALL`] — every variant satisfies exactly one, none
    /// satisfies two, none satisfies zero — pinned by
    /// [`tests::secret_client_kind_predicates_are_a_closed_septet_partition`].
    /// The equality-agreement law (`k.is_X() == (k == Self::X)` for
    /// every variant) is pinned by
    /// [`tests::secret_client_kind_predicates_agree_with_equality_pointwise`].
    #[must_use]
    pub const fn is_mem(self) -> bool {
        matches!(self, Self::Mem)
    }

    /// Returns `true` for [`Self::Command`]; equivalent to
    /// `self == SecretClientKind::Command`. Per-variant sibling
    /// predicate; see [`Self::is_mem`] for the full contract.
    #[must_use]
    pub const fn is_command(self) -> bool {
        matches!(self, Self::Command)
    }

    /// Returns `true` for [`Self::Akeyless`]; equivalent to
    /// `self == SecretClientKind::Akeyless`. Per-variant sibling
    /// predicate; see [`Self::is_mem`] for the full contract.
    ///
    /// Coincides with
    /// [`crate::secret::SecretBackendKind::is_akeyless`] on the
    /// runtime-client / config-author-backend agreement corner where
    /// the two labels are byte-identical (`"akeyless"`).
    #[must_use]
    pub const fn is_akeyless(self) -> bool {
        matches!(self, Self::Akeyless)
    }

    /// Returns `true` for [`Self::AwsSecretsManager`]; equivalent to
    /// `self == SecretClientKind::AwsSecretsManager`. Per-variant
    /// sibling predicate; see [`Self::is_mem`] for the full contract.
    ///
    /// Distinct from
    /// [`crate::secret::SecretBackendKind::is_aws_secret`] by
    /// runtime-transport design — the runtime client labels its
    /// transport (`"aws-secrets-manager"`) while the config-author
    /// backend labels its YAML key (`"aws_secret"`) — but the two
    /// predicates classify the same upstream vault.
    #[must_use]
    pub const fn is_aws_secrets_manager(self) -> bool {
        matches!(self, Self::AwsSecretsManager)
    }

    /// Returns `true` for [`Self::OpConnect`]; equivalent to
    /// `self == SecretClientKind::OpConnect`. Per-variant sibling
    /// predicate; see [`Self::is_mem`] for the full contract.
    ///
    /// Distinct from [`crate::secret::SecretBackendKind::is_op`]:
    /// the config-author `Op` backend dispatches the `op` CLI, while
    /// this runtime client talks HTTP to a 1Password Connect server
    /// (different transport, same upstream 1Password vault).
    #[must_use]
    pub const fn is_op_connect(self) -> bool {
        matches!(self, Self::OpConnect)
    }

    /// Returns `true` for [`Self::Vault`]; equivalent to
    /// `self == SecretClientKind::Vault`. Per-variant sibling
    /// predicate; see [`Self::is_mem`] for the full contract.
    ///
    /// Coincides with [`crate::secret::SecretBackendKind::is_vault`]
    /// on the runtime-client / config-author-backend agreement corner
    /// where the two labels are byte-identical (`"vault"`).
    #[must_use]
    pub const fn is_vault(self) -> bool {
        matches!(self, Self::Vault)
    }

    /// Returns `true` for [`Self::GcpSecretManager`]; equivalent to
    /// `self == SecretClientKind::GcpSecretManager`. Per-variant
    /// sibling predicate; see [`Self::is_mem`] for the full contract.
    ///
    /// Distinct from
    /// [`crate::secret::SecretBackendKind::is_gcp_secret`] by
    /// runtime-transport design — the runtime client labels its
    /// transport (`"gcp-secret-manager"`) while the config-author
    /// backend labels its YAML key (`"gcp_secret"`) — but the two
    /// predicates classify the same upstream vault.
    #[must_use]
    pub const fn is_gcp_secret_manager(self) -> bool {
        matches!(self, Self::GcpSecretManager)
    }

    /// Returns `true` for the hyperscaler-managed Secret Manager pole
    /// of the seven-way [`SecretClientKind`] axis —
    /// [`Self::AwsSecretsManager`] (AWS Secrets Manager SDK) and
    /// [`Self::GcpSecretManager`] (GCP Secret Manager SDK) — `false`
    /// for the other five ([`Self::Mem`], [`Self::Command`],
    /// [`Self::Akeyless`], [`Self::OpConnect`], [`Self::Vault`]).
    ///
    /// The runtime-client altitude sibling of
    /// [`crate::secret::SecretBackendKind::is_cloud_secret_manager`]
    /// (commit `3553207`) on the config-author backend-kind axis,
    /// [`crate::secret::SecretBackend::is_cloud_secret_manager`] on
    /// the payload-carrying backend value, and
    /// [`crate::secret::SecretSource::is_cloud_secret_manager`]
    /// (commit `dc2ee39`) on the source-wrapping altitude. Closes
    /// the compound-polarity cloud-Secret-Manager ladder at the
    /// FOURTH and last altitude the axis is expressible on — the
    /// runtime `SecretClient` implementor axis, whose two
    /// hyperscaler cells ([`Self::AwsSecretsManager`],
    /// [`Self::GcpSecretManager`]) are the transport-side face of
    /// the two config-author cells
    /// ([`crate::secret::SecretBackendKind::AwsSecret`],
    /// [`crate::secret::SecretBackendKind::GcpSecret`]) the
    /// backend-side sibling already groups.
    ///
    /// Names the *cloud-provider Secret Manager* pole of the
    /// (cloud-Secret-Manager × everything-else) polarity axis at
    /// the runtime-client altitude, so a monitoring consumer
    /// holding a captured [`SecretClientKind`] and asking *"did
    /// this transport talk to a hyperscaler-managed Secret Manager
    /// API (AWS SDK / GCP SDK), or to any of the five other
    /// transports (in-memory scaffold, shell subprocess, Akeyless,
    /// 1Password Connect, `HashiCorp` Vault)?"* — a per-transport
    /// telemetry counter bucketing hyperscaler-Secret-Manager
    /// calls separately from the rest, an attestation manifest
    /// weighing hyperscaler-Secret-Manager provenance differently,
    /// a structured-log filter alerting on hyperscaler-resolved
    /// cells, a dashboard row grouping AWS + GCP under one heading
    /// — spells the *positive* form of the query at the call site
    /// instead of the two-arm disjunction
    /// `kind.is_aws_secrets_manager() || kind.is_gcp_secret_manager()`.
    ///
    /// **The transport-side face of the config-author compound.**
    /// The runtime-client altitude names the *transport* class
    /// (`"aws-secrets-manager"`, `"gcp-secret-manager"` — the
    /// [`SecretClient::backend_name`] labels) while the config-
    /// author backend-kind altitude names the *YAML-key* class
    /// (`"aws_secret"`, `"gcp_secret"` — the
    /// `#[serde(rename_all = "snake_case")]` tags). The two labels
    /// diverge by typescape design (transport vs. YAML key), but
    /// the two compound predicates classify the SAME two upstream
    /// vaults — the cross-altitude two-cell partition is welded by
    /// [`tests::secret_client_kind_is_cloud_secret_manager_agrees_with_secret_backend_kind_pointwise_on_shared_arms`],
    /// so a future edit that re-scoped the compound at either
    /// altitude without extending the other diverges here before
    /// drifting through any consumer that reasons about the two
    /// altitudes as one pole.
    ///
    /// The predicate excludes [`Self::OpConnect`] and
    /// [`Self::Vault`] for the same reason the backend-kind
    /// sibling excludes [`crate::secret::SecretBackendKind::Op`]
    /// and [`crate::secret::SecretBackendKind::Vault`]: those
    /// transports talk to hosted 1Password vaults and Vault
    /// clusters (Cloud or self-hosted) through their own
    /// protocols rather than a hyperscaler Secret Manager API.
    /// [`Self::Akeyless`] is excluded on the same
    /// hosted-secrets-platform-vs-hyperscaler-Secret-Manager
    /// distinction the backend-kind sibling draws.
    ///
    /// The compound ↔ two-arm disjunction law
    /// (`kind.is_cloud_secret_manager() ==
    /// kind.is_aws_secrets_manager() || kind.is_gcp_secret_manager()`)
    /// is pinned by
    /// [`tests::secret_client_kind_is_cloud_secret_manager_agrees_with_or_of_individual_siblings`].
    ///
    /// `const`-callable — matching the `const`-ness of the
    /// per-variant siblings, so a
    /// `kind.is_cloud_secret_manager()` composition stays const-
    /// callable end-to-end. The compile-time weld is pinned by
    /// [`tests::secret_client_kind_is_cloud_secret_manager_is_const_callable`].
    ///
    /// A future eighth [`Self`] variant landing under the compound
    /// pole (a hypothetical `AzureKeyVault` transport, say) must
    /// extend the `matches!` arm here in lockstep with the
    /// seven-way partition — otherwise the disjunction law fails
    /// on the new variant, catching the drift before it reaches
    /// any per-polarity consumer site.
    ///
    /// [`SecretClient::backend_name`]: crate::secret_client::SecretClient::backend_name
    #[must_use]
    pub const fn is_cloud_secret_manager(self) -> bool {
        matches!(self, Self::AwsSecretsManager | Self::GcpSecretManager)
    }

    /// Returns `true` for the five NON-hyperscaler-Secret-Manager cells
    /// of the seven-way [`SecretClientKind`] axis —
    /// [`Self::Mem`] (in-memory test scaffold),
    /// [`Self::Command`] (shell-subprocess `get` shim),
    /// [`Self::Akeyless`] (native HTTP Akeyless gateway),
    /// [`Self::OpConnect`] (1Password Connect HTTP transport), and
    /// [`Self::Vault`] (`HashiCorp` Vault KV v2 HTTP transport) —
    /// `false` for the two hyperscaler-managed cells
    /// ([`Self::AwsSecretsManager`], [`Self::GcpSecretManager`]).
    ///
    /// Compound-polarity complement of [`Self::is_cloud_secret_manager`]
    /// (commit `1390944`) at the runtime-client altitude, closing the
    /// compound-polarity sibling pair on the seven-way runtime
    /// [`SecretClient`] implementor axis. Idiom-peer of the same
    /// complement pole already carried at the three other altitudes
    /// the cloud-Secret-Manager compound is expressible on —
    /// [`crate::secret::SecretBackendKind::is_non_cloud_secret_manager`]
    /// (commit `5d7cd4c`) on the config-author backend-kind axis,
    /// [`crate::secret::SecretBackend::is_non_cloud_secret_manager`]
    /// (commit `9a76f5f`) on the payload-carrying backend value, and
    /// [`crate::secret::SecretSource::is_non_cloud_secret_manager`]
    /// (commit `658f0c7`) on the source-wrapping outer altitude —
    /// closing the FOURTH and last altitude the non-cloud-Secret-
    /// Manager pole is expressible on.
    ///
    /// Written as an exhaustive `match` naming BOTH arm groups
    /// (rather than `matches!(self, Self::Mem | Self::Command |
    /// Self::Akeyless | Self::OpConnect | Self::Vault)` with an
    /// implicit `false` default, or a bare `!self.is_cloud_secret_manager()`
    /// folded through the primary pole), so a hypothetical eighth
    /// variant landing on [`Self`] — a `KubernetesSecrets` runtime
    /// client on the non-cloud pole, an `AzureKeyVault` on the
    /// cloud-Secret-Manager pole — must be placed on one polarity
    /// or the other at `cargo build` rather than silently defaulting
    /// past a bare `false` literal and drifting through every
    /// consumer site that reasons about the cloud-vs-non-cloud
    /// partition at the runtime-client altitude. Idiom-peer of the
    /// same exhaustive-match discipline
    /// [`crate::secret::SecretBackendKind::is_non_cloud_secret_manager`]
    /// (commit `5d7cd4c`) carries at the config-author-backend
    /// altitude.
    ///
    /// Names the *everything-else* pole of the (cloud-Secret-Manager
    /// × everything-else) polarity axis at the runtime-client
    /// altitude, so a monitoring consumer holding a captured
    /// [`SecretClientKind`] and asking *"did this transport NOT
    /// talk to a hyperscaler-managed Secret Manager API?"* — a
    /// per-transport telemetry counter aggregating every non-
    /// hyperscaler-Secret-Manager transport into one bin (in-memory
    /// scaffold + shell subprocess + Akeyless + 1Password Connect
    /// + Vault), an attestation manifest weighing non-hyperscaler
    /// provenance separately from hyperscaler-managed reads, a
    /// structured-log filter routing non-hyperscaler-resolved cells
    /// away from the hyperscaler alerting bucket, a dashboard row
    /// grouping the five non-hyperscaler transports under one
    /// heading — reaches the same query through one named
    /// predicate instead of `!kind.is_cloud_secret_manager()` (the
    /// double-negative that reads awkwardly at the five-of-seven
    /// majority pole) or the five-arm disjunction
    /// `kind.is_mem() || kind.is_command() || kind.is_akeyless() ||
    /// kind.is_op_connect() || kind.is_vault()` (five method calls,
    /// ordering matters, a future eighth variant would silently drop).
    ///
    /// The modal-pair complement law
    /// (`kind.is_non_cloud_secret_manager() ==
    /// !kind.is_cloud_secret_manager()` pointwise on
    /// [`Self::ALL`]) is pinned by
    /// [`tests::secret_client_kind_is_non_cloud_secret_manager_is_complement_of_is_cloud_secret_manager`],
    /// so the two compound-polarity siblings stay strict
    /// complements on the seven-way partition — a future edit
    /// that widened either pole (e.g. reclassifying Vault as a
    /// hyperscaler Secret Manager, or adding an eighth variant
    /// without extending both `match` arms in lockstep) diverges
    /// there before drifting through any per-polarity consumer
    /// site.
    ///
    /// The compound ↔ five-arm disjunction law
    /// (`kind.is_non_cloud_secret_manager() ==
    /// kind.is_mem() || kind.is_command() || kind.is_akeyless() ||
    /// kind.is_op_connect() || kind.is_vault()`) is pinned by
    /// [`tests::secret_client_kind_is_non_cloud_secret_manager_agrees_with_or_of_individual_siblings`].
    ///
    /// The compound-polarity binary partition law
    /// (`u8::from(kind.is_cloud_secret_manager()) +
    ///  u8::from(kind.is_non_cloud_secret_manager()) == 1` for every
    /// variant, with the cardinality sub-pin `2 + 5 = 7 =
    /// SecretClientKind::ALL.len()`) is pinned by
    /// [`tests::secret_client_kind_is_cloud_secret_manager_and_is_non_cloud_secret_manager_form_binary_partition`].
    ///
    /// The cross-altitude two-cell partition weld with the
    /// config-author backend-kind altitude (the runtime-client and
    /// config-author altitudes both classify the SAME five upstream
    /// backends under the complement pole through the natural
    /// pairing) is pinned by
    /// [`tests::secret_client_kind_is_non_cloud_secret_manager_agrees_with_secret_backend_kind_pointwise_on_shared_arms`],
    /// so a future edit that re-scoped the compound at either
    /// altitude without extending the other diverges there before
    /// drifting through any consumer that reasons about the two
    /// altitudes as one pole.
    ///
    /// `const`-callable — matching the `const`-ness of the primary
    /// pole [`Self::is_cloud_secret_manager`] and the per-variant
    /// siblings, so a `kind.is_non_cloud_secret_manager()` composition
    /// stays const-callable end-to-end. The compile-time weld is
    /// pinned by
    /// [`tests::secret_client_kind_is_non_cloud_secret_manager_is_const_callable`].
    ///
    /// [`SecretClient`]: crate::secret_client::SecretClient
    #[must_use]
    pub const fn is_non_cloud_secret_manager(self) -> bool {
        match self {
            Self::Mem | Self::Command | Self::Akeyless | Self::OpConnect | Self::Vault => true,
            Self::AwsSecretsManager | Self::GcpSecretManager => false,
        }
    }

    /// The two CLOUD-SECRET-MANAGER [`SecretClientKind`] variants —
    /// [`Self::AwsSecretsManager`] (AWS Secrets Manager SDK) and
    /// [`Self::GcpSecretManager`] (GCP Secret Manager SDK) — carrying
    /// the *hyperscaler-managed Secret Manager API* pole of the
    /// (cloud-Secret-Manager × everything-else) polarity axis at the
    /// primitive's OWN altitude on the runtime-client axis, mirroring
    /// the shipped boolean predicate [`Self::is_cloud_secret_manager`]
    /// one altitude down: every variant in this slice satisfies
    /// `k.is_cloud_secret_manager()`, and no variant outside it does.
    /// Paired with [`Self::NON_CLOUD_SECRET_MANAGER`], the two disjoint
    /// slices partition [`Self::ALL`] at the static-slice altitude the
    /// same way the shipped boolean predicates
    /// [`Self::is_cloud_secret_manager`] / [`Self::is_non_cloud_secret_manager`]
    /// meta-partition it at the boolean altitude.
    ///
    /// Written as an explicit two-variant slice literal in the SAME
    /// relative declaration order the cloud-Secret-Manager pole
    /// occupies in [`Self::ALL`], rather than derived by filtering
    /// [`Self::ALL`] through [`Self::is_cloud_secret_manager`] at
    /// const-fn altitude — so the two declarations (the slice literal
    /// and the boolean predicate) remain independent load-bearing
    /// witnesses of the same meta-partition, and a future edit that
    /// shifts a variant across the polarity on ONE declaration surface
    /// but not the other diverges at test time on the first shape
    /// where they disagree. A hypothetical eighth cloud-Secret-Manager
    /// variant (e.g. an `AzureKeyVault` transport) lands here in
    /// lockstep with [`Self::is_cloud_secret_manager`]. Uses the same
    /// `pub const &'static [Self]` static-slice discipline as
    /// [`Self::ALL`].
    ///
    /// Idiom-peer of
    /// [`crate::secret::SecretBackendKind::CLOUD_SECRET_MANAGER`]
    /// (commit `04e0f5d`) at the same static-slice altitude on the
    /// config-author backend-kind axis, and
    /// [`crate::SecretOperation::MUTATING`] (commit `b2cfa2a`) on the
    /// operation-axis's read-vs-write meta-partition — applied here to
    /// the seven-way runtime-client axis's cloud-vs-non-cloud
    /// meta-partition, closing the FOURTH and last altitude the
    /// cloud-Secret-Manager slice constants are expressible on
    /// (mirroring the four altitudes the boolean predicates were
    /// already lifted onto — `SecretBackendKind`, `SecretBackend`,
    /// `SecretSource`, `SecretClientKind`).
    ///
    /// The two agreement laws
    /// (`CLOUD_SECRET_MANAGER.iter().all(|k| k.is_cloud_secret_manager())`
    /// and `CLOUD_SECRET_MANAGER.iter().all(|k| !k.is_non_cloud_secret_manager())`)
    /// are pinned by
    /// [`tests::secret_client_kind_cloud_secret_manager_slice_agrees_with_is_cloud_secret_manager_predicate`].
    /// Partition invariant with [`Self::NON_CLOUD_SECRET_MANAGER`]:
    /// [`tests::secret_client_kind_cloud_and_non_cloud_secret_manager_slices_partition_all`].
    /// Order-preservation against [`Self::ALL`]:
    /// [`tests::secret_client_kind_cloud_and_non_cloud_secret_manager_slices_preserve_all_order`].
    /// No duplicates:
    /// [`tests::secret_client_kind_cloud_secret_manager_slice_has_no_duplicates`].
    /// Cardinality-agreement with the boolean pole:
    /// [`tests::secret_client_kind_cloud_and_non_cloud_secret_manager_slice_lengths_agree_with_boolean_pole_cardinalities`].
    /// Const-time addressability:
    /// [`tests::secret_client_kind_cloud_and_non_cloud_secret_manager_slices_are_const_addressable`].
    pub const CLOUD_SECRET_MANAGER: &'static [Self] =
        &[Self::AwsSecretsManager, Self::GcpSecretManager];

    /// The five NON-CLOUD-SECRET-MANAGER [`SecretClientKind`] variants —
    /// [`Self::Mem`] (in-memory test scaffold), [`Self::Command`]
    /// (shell-subprocess `get` shim), [`Self::Akeyless`] (native HTTP
    /// Akeyless gateway), [`Self::OpConnect`] (1Password Connect HTTP
    /// transport), and [`Self::Vault`] (`HashiCorp` Vault KV v2 HTTP
    /// transport) — carrying the *everything-else* pole of the
    /// (cloud-Secret-Manager × everything-else) polarity axis at the
    /// primitive's OWN altitude. Complement pole of
    /// [`Self::CLOUD_SECRET_MANAGER`] on the seven-way
    /// [`SecretClientKind`] axis, mirroring the shipped boolean
    /// predicate [`Self::is_non_cloud_secret_manager`] one altitude
    /// down: every variant in this slice satisfies
    /// `k.is_non_cloud_secret_manager()`, and no variant outside it
    /// does.
    ///
    /// Written as an explicit five-variant slice literal in the SAME
    /// relative declaration order the non-cloud pole occupies in
    /// [`Self::ALL`], rather than derived by filtering [`Self::ALL`]
    /// through [`Self::is_non_cloud_secret_manager`] on every step.
    /// Idiom-peer of the shipped backend-axis complement slice
    /// [`crate::secret::SecretBackendKind::NON_CLOUD_SECRET_MANAGER`]
    /// (commit `04e0f5d`) at the same static-slice altitude.
    ///
    /// See [`Self::CLOUD_SECRET_MANAGER`] for the full contract, the
    /// discipline behind writing the slice as a literal (rather than a
    /// filter through [`Self::is_non_cloud_secret_manager`]), and the
    /// load-bearing test pins.
    pub const NON_CLOUD_SECRET_MANAGER: &'static [Self] = &[
        Self::Mem,
        Self::Command,
        Self::Akeyless,
        Self::OpConnect,
        Self::Vault,
    ];

    /// The [`Self::Mem`] pole of the seven-way identity meta-partition
    /// on the runtime-client kind axis at the static-slice altitude —
    /// the singleton slice `&[Self::Mem]` mirroring the shipped boolean
    /// predicate [`Self::is_mem`] one altitude down (per-variant
    /// polarity).
    ///
    /// Paired with [`Self::ONLY_COMMAND`], [`Self::ONLY_AKEYLESS`],
    /// [`Self::ONLY_AWS_SECRETS_MANAGER`], [`Self::ONLY_OP_CONNECT`],
    /// [`Self::ONLY_VAULT`], and [`Self::ONLY_GCP_SECRET_MANAGER`], the
    /// seven disjoint singletons partition [`Self::ALL`] at the
    /// static-slice altitude the same way the seven shipped boolean
    /// predicates [`Self::is_mem`] / [`Self::is_command`] /
    /// [`Self::is_akeyless`] / [`Self::is_aws_secrets_manager`] /
    /// [`Self::is_op_connect`] / [`Self::is_vault`] /
    /// [`Self::is_gcp_secret_manager`] meta-partition it at the boolean
    /// altitude. The seven constants sit in the same `impl
    /// SecretClientKind` block as [`Self::ALL`],
    /// [`Self::CLOUD_SECRET_MANAGER`] and
    /// [`Self::NON_CLOUD_SECRET_MANAGER`], and follow the same
    /// `pub const &'static [Self]` static-slice discipline.
    ///
    /// Written as an explicit one-variant slice literal (rather than
    /// derived by filtering [`Self::ALL`] through [`Self::is_mem`] at
    /// const-fn altitude), so the two declaration surfaces — the slice
    /// literal and the boolean predicate — remain independent
    /// load-bearing witnesses of the same identity partition. An edit
    /// that shifts a variant across the polarity on ONE surface but not
    /// the other diverges at test time on the first kind where they
    /// disagree, before drifting through any consumer that reads one
    /// altitude but not the other.
    ///
    /// **Idiom-peer.** Septenary landing of the per-half meta-partition
    /// slice-constant discipline in the crate, one cell narrower than
    /// the octonary identity landing on the config-author
    /// [`crate::secret::SecretBackendKind`] axis
    /// ([`crate::secret::SecretBackendKind::ONLY_LITERAL`] / … /
    /// `ONLY_GCP_SECRET`, commit `19364e3`) and one cell wider than the
    /// six-variant identity landings elsewhere in the crate. The
    /// compound-polarity slices [`Self::CLOUD_SECRET_MANAGER`] /
    /// [`Self::NON_CLOUD_SECRET_MANAGER`] (commit `399ee8a`) already
    /// ship the 2/5 meta-partition on the same axis at the same
    /// altitude; this landing adds the 1/1/1/1/1/1/1 identity
    /// meta-partition alongside, so an axis-crossing consumer reaches
    /// either the compound pole or a specific-client pole through one
    /// static slice reference without re-filtering.
    ///
    /// Welded by
    /// [`tests::secret_client_kind_identity_slices_agree_with_identity_predicates`],
    /// [`tests::secret_client_kind_identity_slices_partition_all`],
    /// [`tests::secret_client_kind_identity_slices_preserve_all_order`],
    /// [`tests::secret_client_kind_identity_slices_have_no_duplicates`],
    /// [`tests::secret_client_kind_identity_slice_lengths_agree_with_boolean_pole_cardinalities`],
    /// [`tests::secret_client_kind_identity_slices_are_const_addressable`],
    /// and
    /// [`tests::secret_client_kind_identity_slices_agree_with_compound_polarity_slices`].
    pub const ONLY_MEM: &'static [Self] = &[Self::Mem];

    /// The [`Self::Command`] pole of the seven-way identity meta-
    /// partition on the runtime-client kind axis at the static-slice
    /// altitude — the singleton slice `&[Self::Command]` mirroring the
    /// shipped boolean predicate [`Self::is_command`] one altitude
    /// down.
    ///
    /// See [`Self::ONLY_MEM`] for the full contract, the discipline
    /// behind writing the seven identity-partition constants as
    /// explicit slice literals (rather than filters through
    /// [`Self::is_command`]), and the load-bearing agreement,
    /// partition, order-preservation, no-duplicates, cardinality, and
    /// const-addressability pins the seven `ONLY_*` singletons share.
    pub const ONLY_COMMAND: &'static [Self] = &[Self::Command];

    /// The [`Self::Akeyless`] pole of the seven-way identity meta-
    /// partition on the runtime-client kind axis at the static-slice
    /// altitude — the singleton slice `&[Self::Akeyless]` mirroring the
    /// shipped boolean predicate [`Self::is_akeyless`] one altitude
    /// down.
    ///
    /// See [`Self::ONLY_MEM`] for the full contract and the
    /// load-bearing pins the seven `ONLY_*` singletons share.
    pub const ONLY_AKEYLESS: &'static [Self] = &[Self::Akeyless];

    /// The [`Self::AwsSecretsManager`] pole of the seven-way identity
    /// meta-partition on the runtime-client kind axis at the
    /// static-slice altitude — the singleton slice
    /// `&[Self::AwsSecretsManager]` mirroring the shipped boolean
    /// predicate [`Self::is_aws_secrets_manager`] one altitude down.
    ///
    /// Also the first cell of [`Self::CLOUD_SECRET_MANAGER`] — the two
    /// witnesses agree here (`ONLY_AWS_SECRETS_MANAGER` ⊆
    /// `CLOUD_SECRET_MANAGER`) per the identity-vs-compound partition
    /// cross-check. See [`Self::ONLY_MEM`] for the full contract and
    /// the load-bearing pins the seven `ONLY_*` singletons share.
    pub const ONLY_AWS_SECRETS_MANAGER: &'static [Self] = &[Self::AwsSecretsManager];

    /// The [`Self::OpConnect`] pole of the seven-way identity meta-
    /// partition on the runtime-client kind axis at the static-slice
    /// altitude — the singleton slice `&[Self::OpConnect]` mirroring
    /// the shipped boolean predicate [`Self::is_op_connect`] one
    /// altitude down.
    ///
    /// See [`Self::ONLY_MEM`] for the full contract and the
    /// load-bearing pins the seven `ONLY_*` singletons share.
    pub const ONLY_OP_CONNECT: &'static [Self] = &[Self::OpConnect];

    /// The [`Self::Vault`] pole of the seven-way identity meta-
    /// partition on the runtime-client kind axis at the static-slice
    /// altitude — the singleton slice `&[Self::Vault]` mirroring the
    /// shipped boolean predicate [`Self::is_vault`] one altitude down.
    ///
    /// See [`Self::ONLY_MEM`] for the full contract and the
    /// load-bearing pins the seven `ONLY_*` singletons share.
    pub const ONLY_VAULT: &'static [Self] = &[Self::Vault];

    /// The [`Self::GcpSecretManager`] pole of the seven-way identity
    /// meta-partition on the runtime-client kind axis at the
    /// static-slice altitude — the singleton slice
    /// `&[Self::GcpSecretManager]` mirroring the shipped boolean
    /// predicate [`Self::is_gcp_secret_manager`] one altitude down.
    ///
    /// Also the second cell of [`Self::CLOUD_SECRET_MANAGER`] — the two
    /// witnesses agree here (`ONLY_GCP_SECRET_MANAGER` ⊆
    /// `CLOUD_SECRET_MANAGER`) per the identity-vs-compound partition
    /// cross-check. See [`Self::ONLY_MEM`] for the full contract and
    /// the load-bearing pins the seven `ONLY_*` singletons share.
    pub const ONLY_GCP_SECRET_MANAGER: &'static [Self] = &[Self::GcpSecretManager];
}

impl crate::ClosedAxis for SecretClientKind {
    const ALL: &'static [Self] = Self::ALL;
}

impl crate::ClosedAxisLabel for SecretClientKind {
    fn as_str(self) -> &'static str {
        Self::as_str(self)
    }
}

// The canonical (Display, FromStr, Serialize, Deserialize) string-surface
// quartet on the runtime-client axis kind closed-enum, lifted to one
// macro after the ten hand-rolled idiom-peers preceding this commit
// (WatchEventClass at `94f8a8b`, ShikumiErrorKind at `4b53792`,
// DiffLineKind at `74ee853`, ConfigSourceKind at `ae24a13`,
// FormatProvenance at `212d6fb`, FigmentNameTagKind at `25bab65`,
// FigmentSourceKind at `8a0277d`, EnvMetadataTagKind at `58557d3`,
// SecretBackendKind at `360487a`, SecretRefShape at `bb249c0`). See
// `closed_axis_label_string_surface!` in `crate::macros` for the
// contract; behavior is byte-identical to the hand-rolled impls the
// macro replaces — the verbatim-label `Parse` error body, the
// case-insensitive `from_canonical_str` lowering, the `collect_str`-based
// serde emission, and the visitor's `expecting` message all match the
// prior surface pointwise. Pinned by
// `tests::secret_client_kind_display_matches_as_str`,
// `tests::secret_client_kind_from_str_*`, and
// `tests::secret_client_kind_serde_yaml_*`.
closed_axis_label_string_surface! {
    type = SecretClientKind,
    parse_error = "unknown secret client kind",
    expecting = "a canonical SecretClientKind label \
                 (`mem`, `command`, `akeyless`, `aws-secrets-manager`, \
                 `op-connect`, `vault`, `gcp-secret-manager`; case-insensitive)",
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
    fn secret_operation_is_get_true_only_for_get_variant() {
        // Per-variant polarity pin on the Get corner. Sibling to the
        // quintet-shape pins on SecretErrorKind
        // (`secret_error_kind_is_not_found_true_only_for_not_found_variant`)
        // and the trio-shape pins on ConfigSourceKind; a future edit
        // that flips the `matches!` arm on `is_get` fails here before
        // the equality-agreement pin masks it.
        assert!(SecretOperation::Get.is_get());
        assert!(!SecretOperation::List.is_get());
        assert!(!SecretOperation::Put.is_get());
        assert!(!SecretOperation::Delete.is_get());
        assert!(!SecretOperation::Rotate.is_get());
        assert!(!SecretOperation::GetVersion.is_get());
    }

    #[test]
    fn secret_operation_is_list_true_only_for_list_variant() {
        assert!(!SecretOperation::Get.is_list());
        assert!(SecretOperation::List.is_list());
        assert!(!SecretOperation::Put.is_list());
        assert!(!SecretOperation::Delete.is_list());
        assert!(!SecretOperation::Rotate.is_list());
        assert!(!SecretOperation::GetVersion.is_list());
    }

    #[test]
    fn secret_operation_is_put_true_only_for_put_variant() {
        assert!(!SecretOperation::Get.is_put());
        assert!(!SecretOperation::List.is_put());
        assert!(SecretOperation::Put.is_put());
        assert!(!SecretOperation::Delete.is_put());
        assert!(!SecretOperation::Rotate.is_put());
        assert!(!SecretOperation::GetVersion.is_put());
    }

    #[test]
    fn secret_operation_is_delete_true_only_for_delete_variant() {
        assert!(!SecretOperation::Get.is_delete());
        assert!(!SecretOperation::List.is_delete());
        assert!(!SecretOperation::Put.is_delete());
        assert!(SecretOperation::Delete.is_delete());
        assert!(!SecretOperation::Rotate.is_delete());
        assert!(!SecretOperation::GetVersion.is_delete());
    }

    #[test]
    fn secret_operation_is_rotate_true_only_for_rotate_variant() {
        assert!(!SecretOperation::Get.is_rotate());
        assert!(!SecretOperation::List.is_rotate());
        assert!(!SecretOperation::Put.is_rotate());
        assert!(!SecretOperation::Delete.is_rotate());
        assert!(SecretOperation::Rotate.is_rotate());
        assert!(!SecretOperation::GetVersion.is_rotate());
    }

    #[test]
    fn secret_operation_is_get_version_true_only_for_get_version_variant() {
        assert!(!SecretOperation::Get.is_get_version());
        assert!(!SecretOperation::List.is_get_version());
        assert!(!SecretOperation::Put.is_get_version());
        assert!(!SecretOperation::Delete.is_get_version());
        assert!(!SecretOperation::Rotate.is_get_version());
        assert!(SecretOperation::GetVersion.is_get_version());
    }

    #[test]
    fn secret_operation_predicates_are_a_closed_sextet_partition() {
        // Every SecretOperation::ALL cell satisfies exactly one of
        // the six sibling predicates: none satisfies two, none
        // satisfies zero. Sextet analogue of the quintet-partition
        // pin on `secret_error_kind_predicates_are_a_closed_quintet_partition`,
        // the ternary-partition pin on
        // `config_source_kind_predicates_are_a_closed_ternary_partition`,
        // and the binary-partition pins on the crate's Ord/partition
        // axes. A future operation landing on SecretOperation without
        // its own sibling predicate collapses the partition to "zero"
        // on that cell, failing here before drifting through any
        // per-operation dispatch site.
        for op in SecretOperation::ALL.iter().copied() {
            let hits = usize::from(op.is_get())
                + usize::from(op.is_list())
                + usize::from(op.is_put())
                + usize::from(op.is_delete())
                + usize::from(op.is_rotate())
                + usize::from(op.is_get_version());
            assert_eq!(
                hits, 1,
                "SecretOperation::{op:?} must satisfy exactly one of \
                 is_get/is_list/is_put/is_delete/is_rotate/is_get_version \
                 (satisfied {hits})",
            );
        }
    }

    #[test]
    fn secret_operation_predicates_agree_with_equality_pointwise() {
        // Sibling predicates agree with the closed-equality check
        // against their own variant, over the whole ALL slice. Dual
        // to the closed-sextet-partition pin above: the partition
        // pin catches a new variant landing without its own
        // predicate; this pin catches the dual case where a
        // predicate's arm silently accepts a second variant (a
        // future edit changing `matches!(self, Self::Get)` to
        // `matches!(self, Self::Get | Self::List)`).
        for op in SecretOperation::ALL.iter().copied() {
            assert_eq!(op.is_get(), op == SecretOperation::Get);
            assert_eq!(op.is_list(), op == SecretOperation::List);
            assert_eq!(op.is_put(), op == SecretOperation::Put);
            assert_eq!(op.is_delete(), op == SecretOperation::Delete);
            assert_eq!(op.is_rotate(), op == SecretOperation::Rotate);
            assert_eq!(op.is_get_version(), op == SecretOperation::GetVersion);
        }
    }

    // ── SecretOperation — is_mutating / is_non_mutating ────────────
    //
    // Compound-polarity sibling pair on the read-vs-write meta-partition
    // of the operation axis. Names the write-half pole (Put | Delete |
    // Rotate) and its non-mutating complement (Get | List | GetVersion)
    // at the primitive's altitude, lifting the meta-partition off the
    // three-arm disjunction consumers previously open-coded at every
    // RBAC gate, audit-log filter, and telemetry-bucketing site.

    #[test]
    fn secret_operation_is_mutating_partitions_write_half_from_read_half() {
        // Per-variant polarity table on the compound-polarity sibling of
        // the operation sextet axis: exactly the three write-half arms
        // (Put — create/update; Delete — destroy; Rotate — backend-side
        // generation of a new value) return true; the three read-half
        // arms (Get — read current; List — enumerate keys; GetVersion —
        // read historical) return false.
        assert!(!SecretOperation::Get.is_mutating());
        assert!(!SecretOperation::List.is_mutating());
        assert!(SecretOperation::Put.is_mutating());
        assert!(SecretOperation::Delete.is_mutating());
        assert!(SecretOperation::Rotate.is_mutating());
        assert!(!SecretOperation::GetVersion.is_mutating());
    }

    #[test]
    fn secret_operation_is_non_mutating_partitions_read_half_from_write_half() {
        // Dual of the write-half polarity table: exactly the three read-
        // half arms return true; the three write-half arms return false.
        assert!(SecretOperation::Get.is_non_mutating());
        assert!(SecretOperation::List.is_non_mutating());
        assert!(!SecretOperation::Put.is_non_mutating());
        assert!(!SecretOperation::Delete.is_non_mutating());
        assert!(!SecretOperation::Rotate.is_non_mutating());
        assert!(SecretOperation::GetVersion.is_non_mutating());
    }

    #[test]
    fn secret_operation_is_mutating_is_complement_of_is_non_mutating() {
        // The modal-pair complement law at the compound-polarity
        // altitude: `is_mutating() == !is_non_mutating()` pointwise on
        // SecretOperation::ALL. The two predicates partition ALL into
        // the write-half pole (Put | Delete | Rotate — three mutating
        // arms) and its complement (Get | List | GetVersion — three
        // non-mutating arms). A future edit that drifted one polarity
        // from the other fails here before any consumer of either
        // surface can observe the divergence. Idiom-peer of the
        // pair-complement laws on
        // `WatchEventClass::is_file_mutation` /
        // `WatchEventClass::is_ignored`,
        // `Format::is_feature_gated` / `Format::is_always_available`,
        // and `ConfigTierKind::is_computed` / `ConfigTierKind::is_custom`.
        for op in SecretOperation::ALL.iter().copied() {
            assert_eq!(
                op.is_mutating(),
                !op.is_non_mutating(),
                "is_mutating and !is_non_mutating must agree pointwise on {op:?}",
            );
        }
    }

    #[test]
    fn secret_operation_is_mutating_agrees_with_disjunction_of_mutating_siblings() {
        // The compound ↔ three-arm disjunction law at the compound-
        // polarity altitude: `is_mutating() == is_put() || is_delete()
        // || is_rotate()` pointwise on SecretOperation::ALL — the
        // write-half compound is exactly the disjunction of the three
        // singleton predicates naming the mutating arms. A future edit
        // that flipped one arm of the `match` in `is_mutating` without
        // flipping the corresponding singleton sibling fails here
        // before drifting through any consumer that reasons about the
        // three mutating arms as one group. Idiom-peer of the compound
        // ↔ disjunction pin on
        // `WatchEventClass::is_file_mutation_agrees_with_disjunction_of_mutation_siblings`
        // and `SecretClientKind::is_cloud_secret_manager_agrees_with_or_of_individual_siblings`.
        for op in SecretOperation::ALL.iter().copied() {
            assert_eq!(
                op.is_mutating(),
                op.is_put() || op.is_delete() || op.is_rotate(),
                "is_mutating must equal is_put || is_delete || is_rotate on {op:?}",
            );
        }
    }

    #[test]
    fn secret_operation_is_non_mutating_agrees_with_disjunction_of_non_mutating_siblings() {
        // The complementary compound ↔ three-arm disjunction law:
        // `is_non_mutating() == is_get() || is_list() || is_get_version()`
        // pointwise on SecretOperation::ALL — the read-half compound is
        // exactly the disjunction of the three singleton predicates
        // naming the non-mutating arms. Together with the mutating
        // sibling pin above, both poles route through named per-variant
        // siblings so an edit to any arm surfaces at BOTH pole
        // predicates rather than only one.
        for op in SecretOperation::ALL.iter().copied() {
            assert_eq!(
                op.is_non_mutating(),
                op.is_get() || op.is_list() || op.is_get_version(),
                "is_non_mutating must equal is_get || is_list || is_get_version on {op:?}",
            );
        }
    }

    #[test]
    fn secret_operation_is_mutating_and_is_non_mutating_are_a_closed_binary_partition() {
        // Cardinality-side invariant at the compound-polarity altitude:
        // exactly three SecretOperation::ALL cells satisfy `is_mutating`,
        // exactly three satisfy `is_non_mutating`, and the two counts
        // sum to `SecretOperation::ALL.len()`. Binary-partition analogue
        // of the closed-sextet-partition pin on the singleton
        // predicates. A future seventh SecretOperation variant that did
        // not extend one of the compound arms (or extended both) fails
        // at this cardinality invariant before drifting through any
        // consumer site — the compound-polarity ladder's own load-
        // bearing pin. Idiom-peer of
        // `watch_event_class_is_file_mutation_and_is_ignored_are_a_closed_binary_partition`
        // and `format_feature_gating_predicates_are_a_closed_binary_partition`.
        let mutating_cells = SecretOperation::ALL
            .iter()
            .copied()
            .filter(|op| op.is_mutating())
            .count();
        let non_mutating_cells = SecretOperation::ALL
            .iter()
            .copied()
            .filter(|op| op.is_non_mutating())
            .count();
        assert_eq!(
            mutating_cells, 3,
            "exactly three SecretOperation::ALL cells must satisfy is_mutating",
        );
        assert_eq!(
            non_mutating_cells, 3,
            "exactly three SecretOperation::ALL cells must satisfy is_non_mutating",
        );
        assert_eq!(
            mutating_cells + non_mutating_cells,
            SecretOperation::ALL.len(),
            "the compound-polarity binary partition must cover ALL",
        );
    }

    #[test]
    fn secret_operation_is_mutating_is_const_callable() {
        // The compound-polarity sibling is `const`-callable, so a
        // compile-time consumer (a `const` predicate table, a `const`-
        // evaluated switch over a `SecretOperation` singleton, a
        // `const`-eval-based static-assert on a dispatch arm) resolves
        // the polarity at compile time. Idiom-peer of
        // `watch_event_class_is_file_mutation_is_const_callable`. The
        // const-block asserts below make the weld load-bearing at
        // crate compile time: a future edit that flipped a polarity on
        // this predicate fails at `cargo build`, not just at this
        // test's runtime assertion.
        const _: () = assert!(SecretOperation::Put.is_mutating());
        const _: () = assert!(SecretOperation::Delete.is_mutating());
        const _: () = assert!(SecretOperation::Rotate.is_mutating());
        const _: () = assert!(!SecretOperation::Get.is_mutating());
        const _: () = assert!(!SecretOperation::List.is_mutating());
        const _: () = assert!(!SecretOperation::GetVersion.is_mutating());
        const _: () = assert!(SecretOperation::Get.is_non_mutating());
        const _: () = assert!(SecretOperation::List.is_non_mutating());
        const _: () = assert!(SecretOperation::GetVersion.is_non_mutating());
        const _: () = assert!(!SecretOperation::Put.is_non_mutating());
        const _: () = assert!(!SecretOperation::Delete.is_non_mutating());
        const _: () = assert!(!SecretOperation::Rotate.is_non_mutating());
    }

    #[test]
    fn secret_operation_is_mutating_ops_supported_by_full_capabilities() {
        // Cross-surface witness at the Capabilities boundary: every
        // mutating operation is advertised by `Capabilities::full()`,
        // so `op.is_mutating() ⇒ op.is_supported_by(Capabilities::full())`
        // holds pointwise on SecretOperation::ALL. Ties the compound
        // polarity to the capability surface it names — a future edit
        // that scoped `Capabilities::full()` down (dropping `put`/
        // `delete`/`rotate`) would silently break this implication,
        // and a future new mutating variant that this predicate names
        // but `Capabilities::full()` doesn't advertise fails here at
        // the cross-surface boundary rather than at a per-dispatch
        // site. Note: the reverse implication does NOT hold — the
        // three non-mutating operations are also supported by the
        // full-capability set (a superset of *all* six operations),
        // so `!op.is_mutating() ⇒ op.is_supported_by(Capabilities::full())`
        // is trivially true and carried by the peer
        // `capabilities_full_supports_every_operation` pin.
        let full = Capabilities::full();
        for op in SecretOperation::ALL.iter().copied() {
            if op.is_mutating() {
                assert!(
                    op.is_supported_by(full),
                    "mutating op {op:?} must be advertised by Capabilities::full()",
                );
            }
        }
    }

    #[test]
    fn secret_operation_read_only_capabilities_refuses_every_mutating_op() {
        // Cross-surface *refusal* witness at the Capabilities boundary:
        // every mutating operation is refused by
        // `Capabilities::read_only()`, so `op.is_mutating() ⇒
        // !op.is_supported_by(Capabilities::read_only())` holds
        // pointwise on SecretOperation::ALL. Names the RBAC-gate the
        // compound-polarity pole was lifted to serve directly at the
        // typed capability altitude: a daemon that constrains itself
        // to a `read_only()` capability set will refuse every
        // `is_mutating` dispatch by construction. The reverse
        // implication does NOT hold — `read_only()` also refuses the
        // non-mutating `List` and `GetVersion` operations, which is
        // exactly why the compound-polarity name here is
        // `is_mutating` / `is_non_mutating` rather than
        // `is_write` / `is_read_only` (the latter would falsely suggest
        // agreement with the get-only shape of `read_only()`).
        let read_only = Capabilities::read_only();
        for op in SecretOperation::ALL.iter().copied() {
            if op.is_mutating() {
                assert!(
                    !op.is_supported_by(read_only),
                    "mutating op {op:?} must be refused by Capabilities::read_only()",
                );
            }
        }
    }

    // ── SecretOperation — MUTATING / NON_MUTATING slice constants ──────
    //
    // The compound-polarity meta-partition of `SecretOperation::ALL`
    // lifted from the boolean predicate altitude (`is_mutating` /
    // `is_non_mutating`) onto the static-slice altitude. Each of the
    // four pins below welds one of the four load-bearing invariants:
    //   1. `secret_operation_mutating_slice_agrees_with_is_mutating_predicate`
    //      — every entry satisfies its polarity predicate and none
    //      outside does; the same for the complement slice.
    //   2. `secret_operation_mutating_and_non_mutating_slices_partition_all`
    //      — the two slices are disjoint, their union is ALL, and their
    //      combined length equals `ALL.len()`.
    //   3. `secret_operation_mutating_and_non_mutating_slices_preserve_all_order`
    //      — relative declaration order matches ALL, so the slice
    //      literal cannot silently reorder the meta-partition.
    //   4. `secret_operation_mutating_slice_has_no_duplicates` and
    //      `secret_operation_non_mutating_slice_has_no_duplicates` —
    //      each slice lists every variant at most once.

    #[test]
    fn secret_operation_mutating_slice_agrees_with_is_mutating_predicate() {
        // Cross-altitude weld: the slice's membership agrees with the
        // boolean predicate one altitude down. Every entry in MUTATING
        // satisfies `is_mutating` (and, by the meta-partition, none
        // satisfies `is_non_mutating`); every entry in NON_MUTATING
        // satisfies `is_non_mutating` (and none satisfies `is_mutating`).
        // A future edit that renamed a variant across the polarity on
        // one declaration surface but not the other diverges here rather
        // than silently. Idiom-peer of the shipped Capabilities per-half
        // filter-count pins that re-derive against the predicate.
        for op in SecretOperation::MUTATING.iter().copied() {
            assert!(
                op.is_mutating(),
                "SecretOperation::MUTATING entry {op:?} must satisfy is_mutating",
            );
            assert!(
                !op.is_non_mutating(),
                "SecretOperation::MUTATING entry {op:?} must NOT satisfy is_non_mutating",
            );
        }
        for op in SecretOperation::NON_MUTATING.iter().copied() {
            assert!(
                op.is_non_mutating(),
                "SecretOperation::NON_MUTATING entry {op:?} must satisfy is_non_mutating",
            );
            assert!(
                !op.is_mutating(),
                "SecretOperation::NON_MUTATING entry {op:?} must NOT satisfy is_mutating",
            );
        }
        // The dual direction: every variant outside MUTATING must fail
        // is_mutating, and every variant outside NON_MUTATING must fail
        // is_non_mutating — swept over ALL. This dual pin catches the
        // failure mode where a mutating variant is silently dropped from
        // MUTATING while still satisfying `is_mutating` at the boolean
        // altitude.
        for op in SecretOperation::ALL.iter().copied() {
            let in_mutating = SecretOperation::MUTATING.iter().any(|m| *m == op);
            let in_non_mutating = SecretOperation::NON_MUTATING.iter().any(|n| *n == op);
            assert_eq!(
                in_mutating,
                op.is_mutating(),
                "MUTATING membership must agree with is_mutating on {op:?}",
            );
            assert_eq!(
                in_non_mutating,
                op.is_non_mutating(),
                "NON_MUTATING membership must agree with is_non_mutating on {op:?}",
            );
        }
    }

    #[test]
    fn secret_operation_mutating_and_non_mutating_slices_partition_all() {
        // The two slices are DISJOINT (no variant appears in both), their
        // UNION is exactly ALL (no variant missing from both), and their
        // combined length equals `ALL.len()` (the meta-partition covers
        // the axis without overlap). This is the slice-altitude analogue
        // of the boolean-altitude pin
        // `secret_operation_is_mutating_and_is_non_mutating_are_a_closed_binary_partition`.
        // A future third-pole operation landing in ALL without being
        // classified onto one of the two slices fails here.
        assert_eq!(
            SecretOperation::MUTATING.len() + SecretOperation::NON_MUTATING.len(),
            SecretOperation::ALL.len(),
            "MUTATING and NON_MUTATING must together be the same size as ALL",
        );
        for m in SecretOperation::MUTATING.iter().copied() {
            assert!(
                !SecretOperation::NON_MUTATING.iter().any(|n| *n == m),
                "SecretOperation::{m:?} must NOT appear in both MUTATING and NON_MUTATING",
            );
        }
        for op in SecretOperation::ALL.iter().copied() {
            let in_mutating = SecretOperation::MUTATING.iter().any(|m| *m == op);
            let in_non_mutating = SecretOperation::NON_MUTATING.iter().any(|n| *n == op);
            assert!(
                in_mutating || in_non_mutating,
                "SecretOperation::{op:?} in ALL must appear in MUTATING or NON_MUTATING",
            );
        }
    }

    #[test]
    fn secret_operation_mutating_and_non_mutating_slices_preserve_all_order() {
        // The declaration order within each per-half slice matches the
        // relative order of those variants in `SecretOperation::ALL` — a
        // slice literal cannot silently reorder the meta-partition (which
        // would misalign per-half operation histograms or per-index
        // dashboards keyed on the slice). Idiom analogue of
        // `secret_operation_all_covers_every_variant`'s implicit-order
        // discipline. The all-slice pins the declaration order; this pin
        // welds the per-half slices to the same order.
        let mutating_from_all: Vec<SecretOperation> = SecretOperation::ALL
            .iter()
            .copied()
            .filter(|op| op.is_mutating())
            .collect();
        let non_mutating_from_all: Vec<SecretOperation> = SecretOperation::ALL
            .iter()
            .copied()
            .filter(|op| op.is_non_mutating())
            .collect();
        assert_eq!(
            SecretOperation::MUTATING.to_vec(),
            mutating_from_all,
            "SecretOperation::MUTATING must match ALL's mutating-order projection",
        );
        assert_eq!(
            SecretOperation::NON_MUTATING.to_vec(),
            non_mutating_from_all,
            "SecretOperation::NON_MUTATING must match ALL's non-mutating-order projection",
        );
    }

    #[test]
    fn secret_operation_mutating_slice_has_no_duplicates() {
        // Same set-shape discipline as `secret_operation_all_has_no_duplicates`.
        // Sorting on the canonical label decouples this pin from the
        // slice's declaration order (which is welded by the sibling
        // `secret_operation_mutating_and_non_mutating_slices_preserve_all_order`).
        let mut labels: Vec<&'static str> = SecretOperation::MUTATING
            .iter()
            .map(|o| o.as_str())
            .collect();
        let original_len = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            original_len,
            "SecretOperation::MUTATING must not list any variant twice",
        );
    }

    #[test]
    fn secret_operation_non_mutating_slice_has_no_duplicates() {
        // Read-half twin of the write-half no-duplicates pin.
        let mut labels: Vec<&'static str> = SecretOperation::NON_MUTATING
            .iter()
            .map(|o| o.as_str())
            .collect();
        let original_len = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            original_len,
            "SecretOperation::NON_MUTATING must not list any variant twice",
        );
    }

    #[test]
    fn secret_operation_mutating_and_non_mutating_slice_lengths_agree_with_boolean_pole_cardinalities()
     {
        // The slice lengths agree with the boolean-altitude pole
        // cardinalities: `MUTATING.len()` equals the number of ALL cells
        // satisfying `is_mutating`, and the same on the read half. Ties
        // the slice altitude back to the boolean altitude at the length
        // scalar the whole meta-partition is measured by (the same
        // constant `3` that both `Capabilities::supported_mutating_op_count`
        // and its complement `unsupported_mutating_op_count` sum to on
        // every reachable Capabilities shape).
        let mutating_boolean_count = SecretOperation::ALL
            .iter()
            .copied()
            .filter(|op| op.is_mutating())
            .count();
        let non_mutating_boolean_count = SecretOperation::ALL
            .iter()
            .copied()
            .filter(|op| op.is_non_mutating())
            .count();
        assert_eq!(
            SecretOperation::MUTATING.len(),
            mutating_boolean_count,
            "SecretOperation::MUTATING.len() must equal the is_mutating filter count on ALL",
        );
        assert_eq!(
            SecretOperation::NON_MUTATING.len(),
            non_mutating_boolean_count,
            "SecretOperation::NON_MUTATING.len() must equal the is_non_mutating filter count on ALL",
        );
    }

    #[test]
    fn secret_operation_mutating_and_non_mutating_slices_are_const_addressable() {
        // The two slice constants are addressable in const context — a
        // const-fn caller can index into them or take their `len()`
        // without going through a runtime iterator. Idiom-peer of the
        // sibling `secret_operation_is_mutating_is_const_callable` pin at
        // the boolean altitude. This weld pins that a hypothetical future
        // edit lifting `MUTATING` behind a `pub fn` (rather than
        // `pub const`) — losing const-time addressability — fails here.
        const MUTATING_LEN: usize = SecretOperation::MUTATING.len();
        const NON_MUTATING_LEN: usize = SecretOperation::NON_MUTATING.len();
        assert_eq!(MUTATING_LEN, 3);
        assert_eq!(NON_MUTATING_LEN, 3);
    }

    // ── SecretOperation — identity meta-partition slice constants ─────
    //
    // Senary landing of the per-half meta-partition slice-constant
    // discipline on the six-way SecretOperation axis (first landing on
    // the operation-axis primitive). Peer of the octonary
    // `SecretBackendKind::ONLY_LITERAL` / … / `ONLY_GCP_SECRET` (commit
    // `19364e3`), the septenary `SecretClientKind::ONLY_MEM` / … /
    // `ONLY_GCP_SECRET_MANAGER` (commit `d78ae31`), and the quinary
    // `TierArg::ONLY_BARE` / … / `ONLY_ENV` (commit `f7f5529`). The six
    // pins below lock the identity singletons as a coherent
    // meta-partition at the primitive's altitude alongside the shipped
    // compound-polarity `MUTATING` / `NON_MUTATING` pair one altitude
    // up.

    #[test]
    fn secret_operation_identity_slices_agree_with_identity_predicates() {
        // Six-way agreement pin across the (get × list × put × delete
        // × rotate × get_version) identity meta-partition. Every
        // ONLY_GET entry satisfies is_get and none of the five sibling
        // predicates; every ONLY_LIST entry satisfies is_list alone;
        // … and so on across all six halves. The two independent
        // declaration surfaces (slice literals + boolean predicates)
        // diverge at THIS pin on the first shape where they disagree,
        // before a consumer that reads one altitude but not the other
        // can observe the drift. Senary peer of
        // `secret_backend_kind_identity_slices_agree_with_identity_predicates`
        // (commit `19364e3`) two cells narrower.
        for op in SecretOperation::ONLY_GET.iter().copied() {
            assert!(op.is_get(), "ONLY_GET {op:?} must satisfy is_get");
            assert!(!op.is_list(), "ONLY_GET {op:?} must NOT satisfy is_list");
            assert!(!op.is_put(), "ONLY_GET {op:?} must NOT satisfy is_put");
            assert!(
                !op.is_delete(),
                "ONLY_GET {op:?} must NOT satisfy is_delete"
            );
            assert!(
                !op.is_rotate(),
                "ONLY_GET {op:?} must NOT satisfy is_rotate"
            );
            assert!(
                !op.is_get_version(),
                "ONLY_GET {op:?} must NOT satisfy is_get_version"
            );
        }
        for op in SecretOperation::ONLY_LIST.iter().copied() {
            assert!(op.is_list(), "ONLY_LIST {op:?} must satisfy is_list");
            assert!(!op.is_get(), "ONLY_LIST {op:?} must NOT satisfy is_get");
            assert!(!op.is_put(), "ONLY_LIST {op:?} must NOT satisfy is_put");
            assert!(
                !op.is_delete(),
                "ONLY_LIST {op:?} must NOT satisfy is_delete"
            );
            assert!(
                !op.is_rotate(),
                "ONLY_LIST {op:?} must NOT satisfy is_rotate"
            );
            assert!(
                !op.is_get_version(),
                "ONLY_LIST {op:?} must NOT satisfy is_get_version"
            );
        }
        for op in SecretOperation::ONLY_PUT.iter().copied() {
            assert!(op.is_put(), "ONLY_PUT {op:?} must satisfy is_put");
            assert!(!op.is_get(), "ONLY_PUT {op:?} must NOT satisfy is_get");
            assert!(!op.is_list(), "ONLY_PUT {op:?} must NOT satisfy is_list");
            assert!(
                !op.is_delete(),
                "ONLY_PUT {op:?} must NOT satisfy is_delete"
            );
            assert!(
                !op.is_rotate(),
                "ONLY_PUT {op:?} must NOT satisfy is_rotate"
            );
            assert!(
                !op.is_get_version(),
                "ONLY_PUT {op:?} must NOT satisfy is_get_version"
            );
        }
        for op in SecretOperation::ONLY_DELETE.iter().copied() {
            assert!(op.is_delete(), "ONLY_DELETE {op:?} must satisfy is_delete");
            assert!(!op.is_get(), "ONLY_DELETE {op:?} must NOT satisfy is_get");
            assert!(!op.is_list(), "ONLY_DELETE {op:?} must NOT satisfy is_list");
            assert!(!op.is_put(), "ONLY_DELETE {op:?} must NOT satisfy is_put");
            assert!(
                !op.is_rotate(),
                "ONLY_DELETE {op:?} must NOT satisfy is_rotate"
            );
            assert!(
                !op.is_get_version(),
                "ONLY_DELETE {op:?} must NOT satisfy is_get_version"
            );
        }
        for op in SecretOperation::ONLY_ROTATE.iter().copied() {
            assert!(op.is_rotate(), "ONLY_ROTATE {op:?} must satisfy is_rotate");
            assert!(!op.is_get(), "ONLY_ROTATE {op:?} must NOT satisfy is_get");
            assert!(!op.is_list(), "ONLY_ROTATE {op:?} must NOT satisfy is_list");
            assert!(!op.is_put(), "ONLY_ROTATE {op:?} must NOT satisfy is_put");
            assert!(
                !op.is_delete(),
                "ONLY_ROTATE {op:?} must NOT satisfy is_delete"
            );
            assert!(
                !op.is_get_version(),
                "ONLY_ROTATE {op:?} must NOT satisfy is_get_version"
            );
        }
        for op in SecretOperation::ONLY_GET_VERSION.iter().copied() {
            assert!(
                op.is_get_version(),
                "ONLY_GET_VERSION {op:?} must satisfy is_get_version"
            );
            assert!(
                !op.is_get(),
                "ONLY_GET_VERSION {op:?} must NOT satisfy is_get"
            );
            assert!(
                !op.is_list(),
                "ONLY_GET_VERSION {op:?} must NOT satisfy is_list"
            );
            assert!(
                !op.is_put(),
                "ONLY_GET_VERSION {op:?} must NOT satisfy is_put"
            );
            assert!(
                !op.is_delete(),
                "ONLY_GET_VERSION {op:?} must NOT satisfy is_delete"
            );
            assert!(
                !op.is_rotate(),
                "ONLY_GET_VERSION {op:?} must NOT satisfy is_rotate"
            );
        }
    }

    #[test]
    fn secret_operation_identity_slices_partition_all() {
        // Senary partition invariant: the six per-half slices are
        // pairwise-disjoint and their union covers ALL. Direct
        // application of the meta-partition sum law
        // `ONLY_GET.len() + ONLY_LIST.len() + ONLY_PUT.len() +
        //  ONLY_DELETE.len() + ONLY_ROTATE.len() +
        //  ONLY_GET_VERSION.len() == ALL.len()`.
        let identity_slices: [&[SecretOperation]; 6] = [
            SecretOperation::ONLY_GET,
            SecretOperation::ONLY_LIST,
            SecretOperation::ONLY_PUT,
            SecretOperation::ONLY_DELETE,
            SecretOperation::ONLY_ROTATE,
            SecretOperation::ONLY_GET_VERSION,
        ];
        for (i, left) in identity_slices.iter().enumerate() {
            for right in identity_slices.iter().skip(i + 1) {
                for op in left.iter() {
                    assert!(
                        !right.contains(op),
                        "SecretOperation::{op:?} appears in more than one identity slice",
                    );
                }
            }
        }
        for op in SecretOperation::ALL.iter().copied() {
            let held: usize = identity_slices
                .iter()
                .map(|s| usize::from(s.contains(&op)))
                .sum();
            assert_eq!(
                held, 1,
                "SecretOperation::{op:?} must appear in exactly one identity \
                 slice (found in {held})",
            );
        }
        let sum: usize = identity_slices.iter().map(|s| s.len()).sum();
        assert_eq!(
            sum,
            SecretOperation::ALL.len(),
            "identity slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn secret_operation_identity_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in SecretOperation::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted any pole (impossible for singleton halves
        // today, but the shape catches a hypothetical multi-cell
        // future variant reshuffle on the same axis) diverges at
        // THIS pin.
        macro_rules! pin {
            ($slice:expr, $predicate:ident) => {{
                let from_all: Vec<SecretOperation> = SecretOperation::ALL
                    .iter()
                    .copied()
                    .filter(|op| op.$predicate())
                    .collect();
                assert_eq!(
                    from_all,
                    $slice.to_vec(),
                    concat!(
                        stringify!($slice),
                        " must be ALL-filtered by ",
                        stringify!($predicate),
                        " in declaration order",
                    ),
                );
            }};
        }
        pin!(SecretOperation::ONLY_GET, is_get);
        pin!(SecretOperation::ONLY_LIST, is_list);
        pin!(SecretOperation::ONLY_PUT, is_put);
        pin!(SecretOperation::ONLY_DELETE, is_delete);
        pin!(SecretOperation::ONLY_ROTATE, is_rotate);
        pin!(SecretOperation::ONLY_GET_VERSION, is_get_version);
    }

    #[test]
    fn secret_operation_identity_slices_have_no_duplicates() {
        // No-duplicates pin on all six per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half fails at THIS pin before drifting
        // through any consumer that iterates the slice expecting a
        // set.
        for slice in [
            SecretOperation::ONLY_GET,
            SecretOperation::ONLY_LIST,
            SecretOperation::ONLY_PUT,
            SecretOperation::ONLY_DELETE,
            SecretOperation::ONLY_ROTATE,
            SecretOperation::ONLY_GET_VERSION,
        ] {
            let mut seen: Vec<SecretOperation> = Vec::with_capacity(slice.len());
            for op in slice {
                assert!(
                    !seen.contains(op),
                    "SecretOperation identity slice {slice:?} contains \
                     duplicate entry {op:?}",
                );
                seen.push(*op);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn secret_operation_identity_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on SecretOperation::ALL — i.e.,
        // `ONLY_GET.len() == ALL.iter().filter(is_get).count()` (and
        // symmetric for the five siblings) — the cardinality
        // projection at the slice altitude agrees with the boolean-
        // altitude projection on all six halves. Concrete positions
        // today: 1 + 1 + 1 + 1 + 1 + 1 = 6 = ALL.
        let counts = [
            (
                "is_get",
                SecretOperation::ONLY_GET.len(),
                SecretOperation::ALL
                    .iter()
                    .copied()
                    .filter(|op| op.is_get())
                    .count(),
            ),
            (
                "is_list",
                SecretOperation::ONLY_LIST.len(),
                SecretOperation::ALL
                    .iter()
                    .copied()
                    .filter(|op| op.is_list())
                    .count(),
            ),
            (
                "is_put",
                SecretOperation::ONLY_PUT.len(),
                SecretOperation::ALL
                    .iter()
                    .copied()
                    .filter(|op| op.is_put())
                    .count(),
            ),
            (
                "is_delete",
                SecretOperation::ONLY_DELETE.len(),
                SecretOperation::ALL
                    .iter()
                    .copied()
                    .filter(|op| op.is_delete())
                    .count(),
            ),
            (
                "is_rotate",
                SecretOperation::ONLY_ROTATE.len(),
                SecretOperation::ALL
                    .iter()
                    .copied()
                    .filter(|op| op.is_rotate())
                    .count(),
            ),
            (
                "is_get_version",
                SecretOperation::ONLY_GET_VERSION.len(),
                SecretOperation::ALL
                    .iter()
                    .copied()
                    .filter(|op| op.is_get_version())
                    .count(),
            ),
        ];
        for (name, slice_len, boolean_count) in counts {
            assert_eq!(
                slice_len, boolean_count,
                "identity slice for {name} must match the {name} count on ALL",
            );
            assert_eq!(
                slice_len, 1,
                "identity slice for {name} must be a singleton",
            );
        }
        assert_eq!(SecretOperation::ALL.len(), 6);
    }

    #[test]
    fn secret_operation_identity_slices_are_const_addressable() {
        // Const-time addressability pin: the six per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of any constant behind a `pub fn`
        // (which would drop const-callability) fails here before
        // drifting through a downstream `const`-context consumer.
        const ONLY_GET_LEN: usize = SecretOperation::ONLY_GET.len();
        const ONLY_LIST_LEN: usize = SecretOperation::ONLY_LIST.len();
        const ONLY_PUT_LEN: usize = SecretOperation::ONLY_PUT.len();
        const ONLY_DELETE_LEN: usize = SecretOperation::ONLY_DELETE.len();
        const ONLY_ROTATE_LEN: usize = SecretOperation::ONLY_ROTATE.len();
        const ONLY_GET_VERSION_LEN: usize = SecretOperation::ONLY_GET_VERSION.len();
        const ALL_LEN: usize = SecretOperation::ALL.len();
        assert_eq!(ONLY_GET_LEN, 1);
        assert_eq!(ONLY_LIST_LEN, 1);
        assert_eq!(ONLY_PUT_LEN, 1);
        assert_eq!(ONLY_DELETE_LEN, 1);
        assert_eq!(ONLY_ROTATE_LEN, 1);
        assert_eq!(ONLY_GET_VERSION_LEN, 1);
        assert_eq!(
            ONLY_GET_LEN
                + ONLY_LIST_LEN
                + ONLY_PUT_LEN
                + ONLY_DELETE_LEN
                + ONLY_ROTATE_LEN
                + ONLY_GET_VERSION_LEN,
            ALL_LEN,
        );
    }

    #[test]
    fn secret_operation_identity_slices_agree_with_compound_polarity_slices() {
        // Cross-altitude weld between the identity meta-partition
        // (ONLY_*) and the compound-polarity meta-partition (MUTATING
        // / NON_MUTATING). The union of the three identity singletons
        // in the mutating pole (ONLY_PUT + ONLY_DELETE + ONLY_ROTATE)
        // equals MUTATING as a set in declaration order, and the union
        // of the three non-mutating identity singletons (ONLY_GET +
        // ONLY_LIST + ONLY_GET_VERSION) equals NON_MUTATING likewise.
        // A future rearrangement of one meta-partition without the
        // other (say, moving `Rotate` into the non-mutating pole
        // without adding it to the identity → compound aggregation)
        // diverges at THIS pin, before drifting through a consumer
        // that materializes one altitude from the other.
        let mutating_from_identity: Vec<SecretOperation> = [
            SecretOperation::ONLY_PUT,
            SecretOperation::ONLY_DELETE,
            SecretOperation::ONLY_ROTATE,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            mutating_from_identity,
            SecretOperation::MUTATING.to_vec(),
            "identity singleton union on the mutating pole must reproduce \
             MUTATING in declaration order",
        );
        let non_mutating_from_identity: Vec<SecretOperation> = [
            SecretOperation::ONLY_GET,
            SecretOperation::ONLY_LIST,
            SecretOperation::ONLY_GET_VERSION,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            non_mutating_from_identity,
            SecretOperation::NON_MUTATING.to_vec(),
            "identity singleton union on the non-mutating pole must reproduce \
             NON_MUTATING in declaration order",
        );
    }

    // ── Capabilities — mutation-capability compound-polarity pair ──────
    //
    // Lift of the SecretOperation `is_mutating` / `is_non_mutating`
    // compound-polarity pair (commit `ca7131b`) onto the Capabilities
    // altitude. The four pins below lock the pair as a coherent
    // compound-polarity axis at the primitive's altitude:
    //   1. `capabilities_full_supports_any_mutating_op` — cross-surface
    //      anchor on the shipped `full()` constructor (mutation-capable
    //      pole).
    //   2. `capabilities_read_only_supports_no_mutating_op` — cross-
    //      surface anchor on the shipped `read_only()` constructor
    //      (mutation-incapable pole).
    //   3. `capabilities_supports_any_mutating_op_is_complement_of_supports_no_mutating_op`
    //      — the modal-pair complement law.
    //   4. `capabilities_supports_any_mutating_op_agrees_with_operation_is_mutating`
    //      — the cross-altitude weld with `SecretOperation::is_mutating`
    //      one altitude down.
    //   5. `capabilities_supports_any_mutating_op_is_const_callable` —
    //      const-callability weld.

    #[test]
    fn capabilities_full_supports_any_mutating_op() {
        // Cross-surface anchor: the shipped `Capabilities::full()` set
        // sits on the mutation-capable pole (advertises every mutating
        // operation, so the compound polarity trivially fires). A
        // future edit that scoped `Capabilities::full()` down (dropping
        // all three mutating flags) would silently flip this anchor
        // and fail here at the shipped-constructor boundary before
        // drifting through any RBAC gate reading the polarity.
        assert!(Capabilities::full().supports_any_mutating_op());
        assert!(!Capabilities::full().supports_no_mutating_op());
    }

    #[test]
    fn capabilities_read_only_supports_no_mutating_op() {
        // Cross-surface anchor: the shipped `Capabilities::read_only()`
        // set sits on the mutation-incapable pole (advertises none of
        // the three mutating operations). A future edit that widened
        // `read_only()` to grant any mutating flag would silently flip
        // this anchor. Note: the reverse implication does NOT hold —
        // the mutation-incapable pole does NOT imply the get-only
        // shape `read_only()` carries (a hypothetical
        // `list_and_versions_only()` set would also fire this
        // predicate), which is exactly why the compound name here is
        // `supports_no_mutating_op` rather than `is_read_only`.
        assert!(Capabilities::read_only().supports_no_mutating_op());
        assert!(!Capabilities::read_only().supports_any_mutating_op());
    }

    #[test]
    fn capabilities_supports_any_mutating_op_is_complement_of_supports_no_mutating_op() {
        // The modal-pair complement law at the Capabilities altitude:
        // `caps.supports_any_mutating_op() ==
        // !caps.supports_no_mutating_op()` pointwise on every
        // Capabilities shape in the canonical sample table. A future
        // edit that drifted one polarity from the other fails here
        // before any RBAC gate can observe the divergence. Idiom-peer
        // of the pair-complement laws on
        // `SecretOperation::is_mutating` / `SecretOperation::is_non_mutating`
        // one altitude down, and on
        // `ConfigTierKind::is_computed` / `ConfigTierKind::is_custom`
        // one primitive over.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: true,
                list: false,
                put: true,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: true,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: true,
                versions: false,
            },
        ];
        for caps in samples {
            assert_eq!(
                caps.supports_any_mutating_op(),
                !caps.supports_no_mutating_op(),
                "supports_any_mutating_op and !supports_no_mutating_op must agree pointwise on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_any_mutating_op_agrees_with_operation_is_mutating() {
        // The cross-altitude weld with `SecretOperation::is_mutating`
        // one altitude down: `caps.supports_any_mutating_op()` holds
        // iff there EXISTS a SecretOperation variant satisfying both
        // `op.is_mutating()` and `caps.supports(op)`. Locks the
        // Capabilities-altitude compound polarity to the operation-
        // altitude compound polarity through the (Capabilities →
        // SecretOperation) `supports` projection: a future edit that
        // flipped the polarity on either side without flipping the
        // other diverges here at test time, before drifting through
        // any RBAC gate that reasons about the two altitudes as one
        // pole. Cross-altitude analogue of the tag ↔ kind agreement
        // laws on `ConfigTier::is_computed` /
        // `ConfigTierKind::is_computed` and on `Provenance::is_computed`
        // / `ConfigTier::is_computed`.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: true,
                list: false,
                put: true,
                delete: true,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: true,
                versions: false,
            },
        ];
        for caps in samples {
            let by_disjunction_over_operation_axis = SecretOperation::ALL
                .iter()
                .copied()
                .any(|op| op.is_mutating() && caps.supports(op));
            assert_eq!(
                caps.supports_any_mutating_op(),
                by_disjunction_over_operation_axis,
                "supports_any_mutating_op must agree with any(op.is_mutating() && caps.supports(op)) on {caps:?}",
            );
            let by_conjunction_over_operation_axis = SecretOperation::ALL
                .iter()
                .copied()
                .all(|op| !op.is_mutating() || !caps.supports(op));
            assert_eq!(
                caps.supports_no_mutating_op(),
                by_conjunction_over_operation_axis,
                "supports_no_mutating_op must agree with all(!op.is_mutating() || !caps.supports(op)) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_any_mutating_op_is_const_callable() {
        // The Capabilities-altitude compound-polarity pair is
        // `const`-callable, matching the const-ness of the shipped
        // constructors `Capabilities::read_only` / `Capabilities::full`
        // and of the SecretOperation-altitude compound polarity
        // `SecretOperation::is_mutating` / `SecretOperation::is_non_mutating`
        // one altitude down. Const-block asserts make the weld
        // load-bearing at crate compile time: a future edit that
        // flipped a polarity on this predicate fails at `cargo build`,
        // not just at this test's runtime assertion. Idiom-peer of
        // `secret_operation_is_mutating_is_const_callable`.
        const _: () = assert!(Capabilities::full().supports_any_mutating_op());
        const _: () = assert!(!Capabilities::full().supports_no_mutating_op());
        const _: () = assert!(!Capabilities::read_only().supports_any_mutating_op());
        const _: () = assert!(Capabilities::read_only().supports_no_mutating_op());
    }

    #[test]
    fn capabilities_full_supports_any_non_mutating_op() {
        // Cross-surface anchor: the shipped `Capabilities::full()` set
        // sits on the read-capable pole of the READ-half compound-
        // polarity axis (advertises every non-mutating operation, so
        // the compound polarity trivially fires). A future edit that
        // scoped `Capabilities::full()` down (dropping every one of
        // `get` / `list` / `versions`) would silently flip this anchor
        // and fail here at the shipped-constructor boundary before
        // drifting through any RBAC gate reading the polarity.
        assert!(Capabilities::full().supports_any_non_mutating_op());
        assert!(!Capabilities::full().supports_no_non_mutating_op());
    }

    #[test]
    fn capabilities_read_only_supports_any_non_mutating_op() {
        // Cross-surface anchor: the shipped `Capabilities::read_only()`
        // set sits on the read-capable pole (advertises `get: true`,
        // with `list` / `versions` both `false`, so the read-half
        // three-arm disjunction still fires on the first arm). A
        // future edit that dropped `get: true` from `read_only()`
        // would silently flip this anchor. Note: unlike the WRITE-half
        // pair (where the two shipped constructors sit on OPPOSITE
        // poles), on the READ-half axis BOTH `full()` and `read_only()`
        // sit on the SAME (read-capable) pole — shikumi ships no
        // read-incapable constructor, so the non-mutating-pole
        // predicate only distinguishes hand-rolled `Capabilities`
        // shapes (e.g. a write-only backend). That is exactly what
        // the compound name `supports_any_non_mutating_op` (rather
        // than `is_readable`) records: the name partitions the axis
        // without claiming either shipped constructor as its
        // canonical anchor on the read-incapable pole.
        assert!(Capabilities::read_only().supports_any_non_mutating_op());
        assert!(!Capabilities::read_only().supports_no_non_mutating_op());
    }

    #[test]
    fn capabilities_supports_any_non_mutating_op_is_complement_of_supports_no_non_mutating_op() {
        // The modal-pair complement law at the Capabilities altitude
        // on the READ-half axis: `caps.supports_any_non_mutating_op()
        // == !caps.supports_no_non_mutating_op()` pointwise on every
        // Capabilities shape in the canonical sample table. A future
        // edit that drifted one polarity from the other fails here
        // before any RBAC gate can observe the divergence. Idiom-peer
        // of the pair-complement law on
        // `Capabilities::supports_any_mutating_op` /
        // `Capabilities::supports_no_mutating_op` on the WRITE-half
        // axis at this same altitude, of
        // `SecretOperation::is_non_mutating` /
        // `SecretOperation::is_mutating` one altitude down, and of
        // `ConfigTierKind::is_computed` / `ConfigTierKind::is_custom`
        // one primitive over. The sample table includes a write-only
        // shape (put/delete/rotate all `true`, get/list/versions all
        // `false`) that is the *distinguishing* case for the READ-half
        // axis — neither shipped constructor exercises the read-
        // incapable pole, so an explicit hand-rolled shape here is
        // what keeps the complement law non-trivial across both
        // poles.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: false,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
        ];
        for caps in samples {
            assert_eq!(
                caps.supports_any_non_mutating_op(),
                !caps.supports_no_non_mutating_op(),
                "supports_any_non_mutating_op and !supports_no_non_mutating_op must agree pointwise on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_any_non_mutating_op_agrees_with_operation_is_non_mutating() {
        // The cross-altitude weld with `SecretOperation::is_non_mutating`
        // one altitude down: `caps.supports_any_non_mutating_op()`
        // holds iff there EXISTS a SecretOperation variant satisfying
        // both `op.is_non_mutating()` and `caps.supports(op)`. Locks
        // the Capabilities-altitude READ-half compound polarity to the
        // operation-altitude READ-half compound polarity through the
        // (Capabilities → SecretOperation) `supports` projection: a
        // future edit that flipped the polarity on either side without
        // flipping the other diverges here at test time, before
        // drifting through any RBAC gate that reasons about the two
        // altitudes as one pole. Cross-altitude analogue of the
        // WRITE-half weld
        // `capabilities_supports_any_mutating_op_agrees_with_operation_is_mutating`
        // at this same altitude and of the tag ↔ kind agreement laws
        // on `ConfigTier::is_computed` / `ConfigTierKind::is_computed`
        // and on `Provenance::is_computed` / `ConfigTier::is_computed`.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: true,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
        ];
        for caps in samples {
            let by_disjunction_over_operation_axis = SecretOperation::ALL
                .iter()
                .copied()
                .any(|op| op.is_non_mutating() && caps.supports(op));
            assert_eq!(
                caps.supports_any_non_mutating_op(),
                by_disjunction_over_operation_axis,
                "supports_any_non_mutating_op must agree with any(op.is_non_mutating() && caps.supports(op)) on {caps:?}",
            );
            let by_conjunction_over_operation_axis = SecretOperation::ALL
                .iter()
                .copied()
                .all(|op| !op.is_non_mutating() || !caps.supports(op));
            assert_eq!(
                caps.supports_no_non_mutating_op(),
                by_conjunction_over_operation_axis,
                "supports_no_non_mutating_op must agree with all(!op.is_non_mutating() || !caps.supports(op)) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_any_non_mutating_op_is_const_callable() {
        // The Capabilities-altitude READ-half compound-polarity pair
        // is `const`-callable, matching the const-ness of the shipped
        // constructors `Capabilities::read_only` / `Capabilities::full`,
        // of the WRITE-half pair
        // `Capabilities::supports_any_mutating_op` /
        // `Capabilities::supports_no_mutating_op` at this same
        // altitude, and of the SecretOperation-altitude compound
        // polarity `SecretOperation::is_mutating` /
        // `SecretOperation::is_non_mutating` one altitude down. Const-
        // block asserts make the weld load-bearing at crate compile
        // time: a future edit that flipped a polarity on this predicate
        // fails at `cargo build`, not just at this test's runtime
        // assertion. Idiom-peer of
        // `capabilities_supports_any_mutating_op_is_const_callable` on
        // the WRITE pole and of
        // `secret_operation_is_mutating_is_const_callable` one
        // altitude down.
        const _: () = assert!(Capabilities::full().supports_any_non_mutating_op());
        const _: () = assert!(!Capabilities::full().supports_no_non_mutating_op());
        const _: () = assert!(Capabilities::read_only().supports_any_non_mutating_op());
        const _: () = assert!(!Capabilities::read_only().supports_no_non_mutating_op());
    }

    // ── Capabilities — supports_every / not_every mutating_op ──────
    //
    // The universal (∀) pole of the WRITE-half mutating-op meta-
    // partition at the Capabilities altitude, orthogonal to the
    // existential (∃) pole `supports_any_mutating_op` /
    // `supports_no_mutating_op` already shipped on this altitude.
    // Together the two axes form a 2×2 quantifier matrix on the
    // WRITE-half. Six tests pin the pair as a coherent axis:
    //   1. `capabilities_full_supports_every_mutating_op` — the
    //      shipped `Capabilities::full()` set fires the ∀ pole
    //      (every mutating flag `true`).
    //   2. `capabilities_read_only_supports_not_every_mutating_op` —
    //      the shipped `Capabilities::read_only()` set fires the
    //      complement (no mutating flag `true`, so definitely
    //      missing at least one).
    //   3. `capabilities_supports_every_mutating_op_is_complement_of_supports_not_every_mutating_op`
    //      — the modal-pair complement law.
    //   4. `capabilities_supports_every_mutating_op_agrees_with_operation_is_mutating`
    //      — the cross-altitude ∀-weld with `SecretOperation::is_mutating`
    //      one altitude down.
    //   5. `capabilities_supports_every_mutating_op_implies_supports_any_mutating_op`
    //      — the cross-quantifier implication ∀ ⇒ ∃ on the same
    //      altitude, the substantive weld this pair adds on top of
    //      the ∃ pair.
    //   6. `capabilities_supports_every_mutating_op_is_const_callable`
    //      — const-callability weld.

    #[test]
    fn capabilities_full_supports_every_mutating_op() {
        // Cross-surface anchor: the shipped `Capabilities::full()` set
        // fires the ∀ pole (advertises every one of `put`, `delete`,
        // `rotate`, so the three-arm conjunction fires). A future edit
        // that dropped ANY mutating flag from `full()` would silently
        // flip this anchor and fail here at the shipped-constructor
        // boundary before drifting through any fleet secret-mirroring
        // controller or rotate-scheduled backfill gate reading the ∀
        // pole.
        assert!(Capabilities::full().supports_every_mutating_op());
        assert!(!Capabilities::full().supports_not_every_mutating_op());
    }

    #[test]
    fn capabilities_read_only_supports_not_every_mutating_op() {
        // Cross-surface anchor: the shipped `Capabilities::read_only()`
        // set sits on the complement pole (advertises none of the
        // three mutating operations, so definitely misses at least
        // one). A future edit that widened `read_only()` to grant
        // every mutating flag would silently flip this anchor.
        assert!(Capabilities::read_only().supports_not_every_mutating_op());
        assert!(!Capabilities::read_only().supports_every_mutating_op());
    }

    #[test]
    fn capabilities_supports_every_mutating_op_is_complement_of_supports_not_every_mutating_op() {
        // The modal-pair complement law at the Capabilities altitude
        // on the ∀-quantifier axis: `caps.supports_every_mutating_op()
        // == !caps.supports_not_every_mutating_op()` pointwise on
        // every Capabilities shape in the canonical sample table. A
        // future edit that drifted one polarity from the other fails
        // here before any consumer can observe the divergence. Idiom-
        // peer of the ∃-quantifier complement law on
        // `Capabilities::supports_any_mutating_op` /
        // `Capabilities::supports_no_mutating_op` at this same
        // altitude. The sample table explicitly includes the
        // partial-mutation shapes (put-only, delete-only, rotate-only,
        // put+delete) that are the distinguishing cases for the ∀
        // axis — none of them fires `supports_every_mutating_op`, all
        // of them fire `supports_not_every_mutating_op`, while `full`
        // fires the former alone.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: true,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: true,
                delete: true,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: true,
                list: true,
                put: true,
                delete: false,
                rotate: true,
                versions: true,
            },
        ];
        for caps in samples {
            assert_eq!(
                caps.supports_every_mutating_op(),
                !caps.supports_not_every_mutating_op(),
                "supports_every_mutating_op and !supports_not_every_mutating_op must agree pointwise on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_every_mutating_op_agrees_with_operation_is_mutating() {
        // The cross-altitude ∀-weld with `SecretOperation::is_mutating`
        // one altitude down: `caps.supports_every_mutating_op()` holds
        // iff EVERY SecretOperation variant satisfying `op.is_mutating()`
        // also satisfies `caps.supports(op)` — i.e. universally-quantified
        // over the mutating half of the operation axis. Locks the
        // Capabilities-altitude ∀ pole to the operation-altitude
        // mutating meta-partition through the (Capabilities →
        // SecretOperation) `supports` projection: a future edit that
        // flipped the polarity on either side without flipping the
        // other diverges here at test time, before drifting through
        // any fleet controller that reasons about the two altitudes
        // as one pole. Cross-altitude ∀-analogue of the ∃-weld
        // `capabilities_supports_any_mutating_op_agrees_with_operation_is_mutating`.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: true,
                delete: true,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: false,
                rotate: true,
                versions: false,
            },
        ];
        for caps in samples {
            let by_conjunction_over_operation_axis = SecretOperation::ALL
                .iter()
                .copied()
                .all(|op| !op.is_mutating() || caps.supports(op));
            assert_eq!(
                caps.supports_every_mutating_op(),
                by_conjunction_over_operation_axis,
                "supports_every_mutating_op must agree with all(!op.is_mutating() || caps.supports(op)) on {caps:?}",
            );
            let by_disjunction_over_operation_axis = SecretOperation::ALL
                .iter()
                .copied()
                .any(|op| op.is_mutating() && !caps.supports(op));
            assert_eq!(
                caps.supports_not_every_mutating_op(),
                by_disjunction_over_operation_axis,
                "supports_not_every_mutating_op must agree with any(op.is_mutating() && !caps.supports(op)) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_every_mutating_op_implies_supports_any_mutating_op() {
        // The cross-quantifier implication weld ∀ ⇒ ∃ at the
        // Capabilities altitude on the WRITE half — the substantive
        // new relationship this ∀ pair adds on top of the already-
        // shipped ∃ pair. Symmetrically: the ¬∃ pole (i.e.
        // `supports_no_mutating_op`) implies the ¬∀ complement
        // (`supports_not_every_mutating_op`). Pinned pointwise on the
        // canonical sample table, including the partial-mutation
        // shapes that make the implication non-trivial (they fire
        // both ∃ AND ¬∀, but not ∀ nor ¬∃). A future edit that
        // flipped either polarity in isolation of the other fails
        // here before any RBAC gate that carries the (∀, ∃) pair as
        // co-equal read-together fields can observe the divergence.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: true,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
        ];
        for caps in samples {
            if caps.supports_every_mutating_op() {
                assert!(
                    caps.supports_any_mutating_op(),
                    "∀ ⇒ ∃: supports_every_mutating_op holds but supports_any_mutating_op does not on {caps:?}",
                );
            }
            if caps.supports_no_mutating_op() {
                assert!(
                    caps.supports_not_every_mutating_op(),
                    "¬∃ ⇒ ¬∀: supports_no_mutating_op holds but supports_not_every_mutating_op does not on {caps:?}",
                );
            }
        }
    }

    #[test]
    fn capabilities_supports_every_mutating_op_is_const_callable() {
        // The Capabilities-altitude ∀-quantifier pair is `const`-
        // callable, matching the const-ness of the shipped
        // constructors `Capabilities::read_only` / `Capabilities::full`
        // and of the ∃-quantifier pair
        // `Capabilities::supports_any_mutating_op` /
        // `Capabilities::supports_no_mutating_op` at this same
        // altitude. Const-block asserts make the weld load-bearing at
        // crate compile time: a future edit that flipped a polarity
        // on this predicate fails at `cargo build`, not just at this
        // test's runtime assertion. Idiom-peer of
        // `capabilities_supports_any_mutating_op_is_const_callable` on
        // the ∃ quantifier.
        const _: () = assert!(Capabilities::full().supports_every_mutating_op());
        const _: () = assert!(!Capabilities::full().supports_not_every_mutating_op());
        const _: () = assert!(!Capabilities::read_only().supports_every_mutating_op());
        const _: () = assert!(Capabilities::read_only().supports_not_every_mutating_op());
    }

    // ── Capabilities — supports_every / not_every non_mutating_op ──
    //
    // The universal (∀) pole of the READ-half non-mutating-op meta-
    // partition at the Capabilities altitude, orthogonal to the
    // existential (∃) pole `supports_any_non_mutating_op` /
    // `supports_no_non_mutating_op` already shipped on this altitude,
    // and the READ-half analogue of the WRITE-half ∀ pair
    // `supports_every_mutating_op` / `supports_not_every_mutating_op`.
    // Together the four predicates form the (any/no × every/not_every)
    // × (write/read) closed matrix at the Capabilities altitude — the
    // last remaining quantifier cell that had no direct name. Six
    // tests pin the pair as a coherent axis, mirroring the WRITE-half
    // ∀-pair suite:
    //   1. `capabilities_full_supports_every_non_mutating_op` — the
    //      shipped `Capabilities::full()` set fires the ∀ pole (every
    //      non-mutating flag `true`).
    //   2. `capabilities_read_only_supports_not_every_non_mutating_op`
    //      — the shipped `Capabilities::read_only()` set (get-only)
    //      fires the complement (missing `list` and `versions`). Note
    //      this is the ANCHOR that distinguishes the ∀ axis from the
    //      ∃ axis on the READ half: on the ∃ axis both `full` and
    //      `read_only` fire the read-capable pole, so the shipped-
    //      constructor pair cannot distinguish partial-read from full-
    //      read shapes; on the ∀ axis the two constructors sit on
    //      OPPOSITE poles.
    //   3. `capabilities_supports_every_non_mutating_op_is_complement_of_supports_not_every_non_mutating_op`
    //      — the modal-pair complement law.
    //   4. `capabilities_supports_every_non_mutating_op_agrees_with_operation_is_non_mutating`
    //      — the cross-altitude ∀-weld with `SecretOperation::is_non_mutating`
    //      one altitude down.
    //   5. `capabilities_supports_every_non_mutating_op_implies_supports_any_non_mutating_op`
    //      — the cross-quantifier implication ∀ ⇒ ∃ on the same
    //      altitude, the substantive weld this pair adds on top of
    //      the ∃ pair.
    //   6. `capabilities_supports_every_non_mutating_op_is_const_callable`
    //      — const-callability weld.

    #[test]
    fn capabilities_full_supports_every_non_mutating_op() {
        // Cross-surface anchor: the shipped `Capabilities::full()` set
        // fires the ∀ pole on the READ half (advertises every one of
        // `get`, `list`, `versions`, so the three-arm conjunction
        // fires). A future edit that dropped ANY non-mutating flag
        // from `full()` would silently flip this anchor and fail here
        // at the shipped-constructor boundary before drifting through
        // any full read-cycle audit backend or snapshot-exporter
        // pipeline reading the ∀ pole.
        assert!(Capabilities::full().supports_every_non_mutating_op());
        assert!(!Capabilities::full().supports_not_every_non_mutating_op());
    }

    #[test]
    fn capabilities_read_only_supports_not_every_non_mutating_op() {
        // Cross-surface anchor: the shipped `Capabilities::read_only()`
        // set is get-only (advertises `get` but refuses `list` and
        // `versions`, per the fields declared in `Capabilities::read_only`),
        // so it fires the ¬∀ complement pole on the READ half —
        // partial read capability, missing at least one non-mutating
        // op. This is the anchor that structurally distinguishes the
        // ∀ axis from the ∃ axis on the READ half: on the ∃ axis both
        // shipped constructors sit on the SAME (read-capable) pole
        // (see `capabilities_read_only_supports_any_non_mutating_op`),
        // so a partial-read shape like `read_only()` cannot be told
        // apart from `full()` by the ∃ predicate alone. A future edit
        // that widened `read_only()` to grant `list` and `versions`
        // would silently flip this anchor.
        assert!(Capabilities::read_only().supports_not_every_non_mutating_op());
        assert!(!Capabilities::read_only().supports_every_non_mutating_op());
    }

    #[test]
    fn capabilities_supports_every_non_mutating_op_is_complement_of_supports_not_every_non_mutating_op()
     {
        // The modal-pair complement law at the Capabilities altitude
        // on the ∀-quantifier axis for the READ half:
        // `caps.supports_every_non_mutating_op() ==
        // !caps.supports_not_every_non_mutating_op()` pointwise on
        // every Capabilities shape in the canonical sample table. A
        // future edit that drifted one polarity from the other fails
        // here before any consumer can observe the divergence. Idiom-
        // peer of the WRITE-half ∀-quantifier complement law on
        // `Capabilities::supports_every_mutating_op` /
        // `Capabilities::supports_not_every_mutating_op` at this same
        // altitude. The sample table explicitly includes the partial-
        // read shapes (get-only via `read_only()`, list-only, versions-
        // only, get+list, get+versions) that are the distinguishing
        // cases for the ∀ axis — none of them fires
        // `supports_every_non_mutating_op`, all of them fire
        // `supports_not_every_non_mutating_op`, while `full` fires the
        // former alone.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: true,
                list: true,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
        ];
        for caps in samples {
            assert_eq!(
                caps.supports_every_non_mutating_op(),
                !caps.supports_not_every_non_mutating_op(),
                "supports_every_non_mutating_op and !supports_not_every_non_mutating_op must agree pointwise on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_every_non_mutating_op_agrees_with_operation_is_non_mutating() {
        // The cross-altitude ∀-weld with `SecretOperation::is_non_mutating`
        // one altitude down: `caps.supports_every_non_mutating_op()`
        // holds iff EVERY SecretOperation variant satisfying
        // `op.is_non_mutating()` also satisfies `caps.supports(op)`
        // — i.e. universally-quantified over the non-mutating half of
        // the operation axis. Locks the Capabilities-altitude ∀ pole
        // to the operation-altitude non-mutating meta-partition through
        // the (Capabilities → SecretOperation) `supports` projection:
        // a future edit that flipped the polarity on either side
        // without flipping the other diverges here at test time,
        // before drifting through any full read-cycle audit backend
        // that reasons about the two altitudes as one pole. Cross-
        // altitude ∀-analogue on the READ half of the WRITE-half weld
        // `capabilities_supports_every_mutating_op_agrees_with_operation_is_mutating`.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: true,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: false,
                list: true,
                put: true,
                delete: true,
                rotate: true,
                versions: true,
            },
        ];
        for caps in samples {
            let by_conjunction_over_operation_axis = SecretOperation::ALL
                .iter()
                .copied()
                .all(|op| !op.is_non_mutating() || caps.supports(op));
            assert_eq!(
                caps.supports_every_non_mutating_op(),
                by_conjunction_over_operation_axis,
                "supports_every_non_mutating_op must agree with all(!op.is_non_mutating() || caps.supports(op)) on {caps:?}",
            );
            let by_disjunction_over_operation_axis = SecretOperation::ALL
                .iter()
                .copied()
                .any(|op| op.is_non_mutating() && !caps.supports(op));
            assert_eq!(
                caps.supports_not_every_non_mutating_op(),
                by_disjunction_over_operation_axis,
                "supports_not_every_non_mutating_op must agree with any(op.is_non_mutating() && !caps.supports(op)) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_every_non_mutating_op_implies_supports_any_non_mutating_op() {
        // The cross-quantifier implication weld ∀ ⇒ ∃ at the
        // Capabilities altitude on the READ half — the substantive
        // new relationship this ∀ pair adds on top of the already-
        // shipped ∃ pair. Symmetrically: the ¬∃ pole
        // (`supports_no_non_mutating_op`) implies the ¬∀ complement
        // (`supports_not_every_non_mutating_op`). Pinned pointwise on
        // the canonical sample table, including the partial-read
        // shapes that make the implication non-trivial (they fire
        // both ∃ AND ¬∀, but not ∀ nor ¬∃) — the get-only shape
        // `read_only()` in particular is exactly such a partial-read
        // shape and demonstrates the shipped-constructor asymmetry
        // between the ∀ and ∃ axes named in
        // `capabilities_read_only_supports_not_every_non_mutating_op`.
        // A future edit that flipped either polarity in isolation of
        // the other fails here before any consumer that carries the
        // (∀, ∃) pair as co-equal read-together fields can observe
        // the divergence.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
        ];
        for caps in samples {
            if caps.supports_every_non_mutating_op() {
                assert!(
                    caps.supports_any_non_mutating_op(),
                    "∀ ⇒ ∃: supports_every_non_mutating_op holds but supports_any_non_mutating_op does not on {caps:?}",
                );
            }
            if caps.supports_no_non_mutating_op() {
                assert!(
                    caps.supports_not_every_non_mutating_op(),
                    "¬∃ ⇒ ¬∀: supports_no_non_mutating_op holds but supports_not_every_non_mutating_op does not on {caps:?}",
                );
            }
        }
    }

    #[test]
    fn capabilities_supports_every_non_mutating_op_is_const_callable() {
        // The Capabilities-altitude ∀-quantifier pair on the READ
        // half is `const`-callable, matching the const-ness of the
        // shipped constructors `Capabilities::read_only` /
        // `Capabilities::full` and of the WRITE-half ∀-quantifier pair
        // `Capabilities::supports_every_mutating_op` /
        // `Capabilities::supports_not_every_mutating_op` at this same
        // altitude. Const-block asserts make the weld load-bearing at
        // crate compile time: a future edit that flipped a polarity
        // on this predicate fails at `cargo build`, not just at this
        // test's runtime assertion. Idiom-peer of
        // `capabilities_supports_every_mutating_op_is_const_callable`
        // on the WRITE half. Note the anchor asymmetry: `full()`
        // fires ∀ (three trues), `read_only()` fires ¬∀ (get-only,
        // missing `list` and `versions`) — the two shipped
        // constructors sit on OPPOSITE poles of this axis, unlike
        // the ∃ axis where both sit on the read-capable pole.
        const _: () = assert!(Capabilities::full().supports_every_non_mutating_op());
        const _: () = assert!(!Capabilities::full().supports_not_every_non_mutating_op());
        const _: () = assert!(!Capabilities::read_only().supports_every_non_mutating_op());
        const _: () = assert!(Capabilities::read_only().supports_not_every_non_mutating_op());
    }

    // ── Capabilities — whole-set (unpartitioned) ∃ / ∀ pairs ────────
    //
    // Pin table for the two whole-set compound-polarity pairs
    // `supports_any_op` / `supports_no_op` (∃) and
    // `supports_every_op` / `supports_not_every_op` (∀) at the
    // Capabilities altitude — orthogonal to (and welding back together)
    // the (any/no × every/not_every) × (write/read) closed matrix
    // already shipped:
    //   1. `capabilities_full_supports_any_op` — cross-surface anchor
    //      on the shipped `full()` constructor (capable pole of ∃).
    //   2. `capabilities_read_only_supports_any_op` — cross-surface
    //      anchor on the shipped `read_only()` constructor (also on
    //      the capable pole of ∃: even the get-only shape advertises
    //      SOME operation).
    //   3. `capabilities_empty_supports_no_op` — cross-surface anchor
    //      on the hand-built all-`false` shape (∃-mute pole).
    //   4. `capabilities_supports_any_op_is_complement_of_supports_no_op`
    //      — the ∃ modal-pair complement law.
    //   5. `capabilities_supports_any_op_agrees_with_operation_axis_disjunction`
    //      — the cross-altitude weld with the operation axis (∃).
    //   6. `capabilities_supports_any_op_agrees_with_meta_partition_union`
    //      — the meta-partition union law: whole-set ∃ = ∃-mutating ∨
    //      ∃-non-mutating, and dually whole-set ¬∃ = ¬∃-mutating ∧
    //      ¬∃-non-mutating.
    //   7. `capabilities_supports_any_op_is_const_callable` —
    //      const-callability weld on the ∃ pair.
    //   8. `capabilities_full_supports_every_op` — cross-surface
    //      anchor on `full()` (∀ pole).
    //   9. `capabilities_read_only_supports_not_every_op` —
    //      cross-surface anchor on `read_only()` (missing every
    //      mutating op and two of three non-mutating ops).
    //  10. `capabilities_supports_every_op_agrees_with_full_constructor`
    //      — the ∀ pole exactly characterises the shipped `full()`
    //      constructor.
    //  11. `capabilities_supports_every_op_is_complement_of_supports_not_every_op`
    //      — the ∀ modal-pair complement law.
    //  12. `capabilities_supports_every_op_agrees_with_operation_axis_conjunction`
    //      — the cross-altitude weld with the operation axis (∀).
    //  13. `capabilities_supports_every_op_agrees_with_meta_partition_intersection`
    //      — the meta-partition intersection law: whole-set ∀ =
    //      ∀-mutating ∧ ∀-non-mutating.
    //  14. `capabilities_supports_every_op_implies_supports_any_op`
    //      — the cross-quantifier ∀ ⇒ ∃ weld on the whole-set axis.
    //  15. `capabilities_supports_every_op_is_const_callable` —
    //      const-callability weld on the ∀ pair.

    #[test]
    fn capabilities_full_supports_any_op() {
        // Cross-surface anchor: the shipped `Capabilities::full()` set
        // sits on the capable pole of the whole-set ∃ axis (advertises
        // every operation, so the ∃ predicate trivially fires).
        assert!(Capabilities::full().supports_any_op());
        assert!(!Capabilities::full().supports_no_op());
    }

    #[test]
    fn capabilities_read_only_supports_any_op() {
        // Cross-surface anchor: the shipped `Capabilities::read_only()`
        // set also sits on the capable pole of the whole-set ∃ axis
        // (advertises `get: true`, so ∃ fires despite the five
        // remaining flags being `false`). Both shipped constructors
        // sit on the SAME pole of this axis by construction; the
        // ∃-mute pole is only reachable via a hand-built all-`false`
        // Capabilities value.
        assert!(Capabilities::read_only().supports_any_op());
        assert!(!Capabilities::read_only().supports_no_op());
    }

    #[test]
    fn capabilities_empty_supports_no_op() {
        // Cross-surface anchor on the hand-built all-`false` shape:
        // the ∃-mute pole (no shipped constructor lands here, but the
        // pole is reachable and must remain crisply named). A future
        // edit that flipped either polarity would silently drift the
        // ∃-mute anchor; this pin locks the pole to the exact
        // all-`false` shape.
        let empty = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        assert!(!empty.supports_any_op());
        assert!(empty.supports_no_op());
    }

    #[test]
    fn capabilities_supports_any_op_is_complement_of_supports_no_op() {
        // The modal-pair complement law at the Capabilities altitude on
        // the whole-set ∃ axis: `caps.supports_any_op() ==
        // !caps.supports_no_op()` pointwise on every shape in the
        // canonical sample table.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: true,
                rotate: false,
                versions: false,
            },
        ];
        for caps in samples {
            assert_eq!(
                caps.supports_any_op(),
                !caps.supports_no_op(),
                "supports_any_op and !supports_no_op must agree pointwise on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_any_op_agrees_with_operation_axis_disjunction() {
        // Cross-altitude weld with the operation axis: the whole-set ∃
        // pole holds iff there EXISTS a SecretOperation variant `op`
        // with `caps.supports(op)`. Locks the Capabilities-altitude
        // whole-set predicate to the operation-altitude enumeration
        // through the (Capabilities → SecretOperation) `supports`
        // projection: a future edit that flipped the polarity on
        // either side without flipping the other diverges here at
        // test time.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: true,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: true,
                versions: false,
            },
        ];
        for caps in samples {
            let by_disjunction_over_operation_axis = SecretOperation::ALL
                .iter()
                .copied()
                .any(|op| caps.supports(op));
            assert_eq!(
                caps.supports_any_op(),
                by_disjunction_over_operation_axis,
                "supports_any_op must agree with any(caps.supports(op)) over SecretOperation::ALL on {caps:?}",
            );
            let by_conjunction_over_operation_axis = SecretOperation::ALL
                .iter()
                .copied()
                .all(|op| !caps.supports(op));
            assert_eq!(
                caps.supports_no_op(),
                by_conjunction_over_operation_axis,
                "supports_no_op must agree with all(!caps.supports(op)) over SecretOperation::ALL on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_any_op_agrees_with_meta_partition_union() {
        // Meta-partition union / intersection law at the Capabilities
        // altitude: the whole-set ∃ pole is the union of the two
        // partitioned ∃ poles across the mutating-vs-non-mutating
        // meta-partition, and dually the whole-set ¬∃ pole is the
        // intersection of the two partitioned ¬∃ poles. This locks
        // the whole-set pair to the already-shipped WRITE-half and
        // READ-half ∃ pairs — a future edit that shifted a field from
        // one half to the other on ONE of the three predicates
        // diverges here.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: true,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
        ];
        for caps in samples {
            assert_eq!(
                caps.supports_any_op(),
                caps.supports_any_mutating_op() || caps.supports_any_non_mutating_op(),
                "meta-partition union: supports_any_op must equal supports_any_mutating_op ∨ supports_any_non_mutating_op on {caps:?}",
            );
            assert_eq!(
                caps.supports_no_op(),
                caps.supports_no_mutating_op() && caps.supports_no_non_mutating_op(),
                "meta-partition intersection: supports_no_op must equal supports_no_mutating_op ∧ supports_no_non_mutating_op on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_any_op_is_const_callable() {
        // The whole-set ∃-quantifier pair is `const`-callable, matching
        // the const-ness of the shipped constructors and of the four
        // partitioned ∃/∀ pairs at this altitude. Const-block asserts
        // make the weld load-bearing at crate compile time.
        const _: () = assert!(Capabilities::full().supports_any_op());
        const _: () = assert!(!Capabilities::full().supports_no_op());
        const _: () = assert!(Capabilities::read_only().supports_any_op());
        const _: () = assert!(!Capabilities::read_only().supports_no_op());
    }

    #[test]
    fn capabilities_full_supports_every_op() {
        // Cross-surface anchor: the shipped `Capabilities::full()` set
        // sits on the ∀ pole of the whole-set universal axis
        // (advertises every one of the six operations).
        assert!(Capabilities::full().supports_every_op());
        assert!(!Capabilities::full().supports_not_every_op());
    }

    #[test]
    fn capabilities_read_only_supports_not_every_op() {
        // Cross-surface anchor: the shipped `Capabilities::read_only()`
        // set sits on the ¬∀ pole of the whole-set universal axis
        // (advertises `get` alone, missing every mutating op and two
        // of three non-mutating ops). Anchor asymmetry: on the ∃ axis
        // both shipped constructors sit on the capable pole, on the
        // ∀ axis they sit on OPPOSITE poles — `read_only` is the
        // partial shape that distinguishes the two quantifiers on the
        // whole-set axis, mirroring its role on the READ-half ∀ axis.
        assert!(!Capabilities::read_only().supports_every_op());
        assert!(Capabilities::read_only().supports_not_every_op());
    }

    #[test]
    fn capabilities_supports_every_op_agrees_with_full_constructor() {
        // The whole-set ∀ pole exactly characterises the shipped
        // `full()` constructor: `caps.supports_every_op() ⇔ caps ==
        // Capabilities::full()`. A future edit that scoped `full()`
        // down (dropping one of the six flags) would silently break
        // this equivalence — the anchor pins the shipped constructor's
        // whole-set shape to the ∀ predicate.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: true,
                delete: true,
                rotate: false,
                versions: true,
            },
        ];
        for caps in samples {
            assert_eq!(
                caps.supports_every_op(),
                caps == Capabilities::full(),
                "supports_every_op must exactly characterise Capabilities::full() on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_every_op_is_complement_of_supports_not_every_op() {
        // The modal-pair complement law at the Capabilities altitude on
        // the whole-set ∀ axis.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: true,
            },
        ];
        for caps in samples {
            assert_eq!(
                caps.supports_every_op(),
                !caps.supports_not_every_op(),
                "supports_every_op and !supports_not_every_op must agree pointwise on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_every_op_agrees_with_operation_axis_conjunction() {
        // Cross-altitude weld: `caps.supports_every_op() ==
        // SecretOperation::ALL.iter().all(|op| caps.supports(*op))`.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: true,
            },
        ];
        for caps in samples {
            let by_conjunction = SecretOperation::ALL
                .iter()
                .copied()
                .all(|op| caps.supports(op));
            assert_eq!(
                caps.supports_every_op(),
                by_conjunction,
                "supports_every_op must agree with all(caps.supports(op)) over SecretOperation::ALL on {caps:?}",
            );
            let by_disjunction_of_negation = SecretOperation::ALL
                .iter()
                .copied()
                .any(|op| !caps.supports(op));
            assert_eq!(
                caps.supports_not_every_op(),
                by_disjunction_of_negation,
                "supports_not_every_op must agree with any(!caps.supports(op)) over SecretOperation::ALL on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_every_op_agrees_with_meta_partition_intersection() {
        // Meta-partition intersection law at the Capabilities altitude:
        // the whole-set ∀ pole is the intersection of the two partitioned
        // ∀ poles across the mutating-vs-non-mutating meta-partition.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: true,
            },
        ];
        for caps in samples {
            assert_eq!(
                caps.supports_every_op(),
                caps.supports_every_mutating_op() && caps.supports_every_non_mutating_op(),
                "meta-partition intersection: supports_every_op must equal supports_every_mutating_op ∧ supports_every_non_mutating_op on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supports_every_op_implies_supports_any_op() {
        // Cross-quantifier weld on the whole-set axis: ∀ ⇒ ∃, and
        // dually ¬∃ ⇒ ¬∀. A future edit that drifted one polarity
        // from the other on this pair fails here.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
        ];
        for caps in samples {
            if caps.supports_every_op() {
                assert!(
                    caps.supports_any_op(),
                    "∀ ⇒ ∃: supports_every_op holds but supports_any_op does not on {caps:?}",
                );
            }
            if caps.supports_no_op() {
                assert!(
                    caps.supports_not_every_op(),
                    "¬∃ ⇒ ¬∀: supports_no_op holds but supports_not_every_op does not on {caps:?}",
                );
            }
        }
    }

    #[test]
    fn capabilities_supports_every_op_is_const_callable() {
        // The whole-set ∀-quantifier pair is `const`-callable.
        const _: () = assert!(Capabilities::full().supports_every_op());
        const _: () = assert!(!Capabilities::full().supports_not_every_op());
        const _: () = assert!(!Capabilities::read_only().supports_every_op());
        const _: () = assert!(Capabilities::read_only().supports_not_every_op());
    }

    // ── Capabilities — cardinality projection ──────────────────────
    //
    // Pin table for the `supported_op_count` cardinality projection
    // at the Capabilities altitude — orthogonal to (and welding
    // together via arithmetic threshold identities) the whole
    // twelve-predicate (any/no × every/not_every) × (write/read/whole)
    // compound-polarity matrix already shipped on this altitude:
    //   1. `capabilities_full_supported_op_count_is_six` — cross-
    //      surface anchor on the shipped `full()` constructor
    //      (top of the closed range).
    //   2. `capabilities_read_only_supported_op_count_is_one` —
    //      cross-surface anchor on the shipped `read_only()`
    //      constructor.
    //   3. `capabilities_empty_supported_op_count_is_zero` —
    //      cross-surface anchor on the hand-built all-`false` shape
    //      (bottom of the closed range).
    //   4. `capabilities_supported_op_count_agrees_with_operation_axis_filter_count`
    //      — the cross-altitude weld with the operation axis via
    //      the `SecretOperation::ALL.iter().filter(supports).count()`
    //      re-derivation.
    //   5. `capabilities_supported_op_count_thresholds_agree_with_whole_set_compound_polarity_matrix`
    //      — the four threshold identities that recover the whole-
    //      set ∃/¬∃/∀/¬∀ compound-polarity pairs from the count.
    //   6. `capabilities_supported_op_count_stays_within_all_len_bound`
    //      — the closed-range bound `count() as usize <=
    //      SecretOperation::ALL.len()` for every reachable shape.
    //   7. `capabilities_supported_op_count_is_const_callable` —
    //      const-callability weld on the cardinality projection.

    #[test]
    fn capabilities_full_supported_op_count_is_six() {
        // Cross-surface anchor: the shipped `Capabilities::full()`
        // set advertises every operation, so the cardinality projection
        // returns the top of the closed range `0..=6`. A future edit
        // that dropped ANY flag from `full()` would silently drift the
        // top anchor; this pin locks the top of the range to the
        // shipped six-flag shape.
        assert_eq!(Capabilities::full().supported_op_count(), 6);
    }

    #[test]
    fn capabilities_read_only_supported_op_count_is_one() {
        // Cross-surface anchor: the shipped `Capabilities::read_only()`
        // set advertises `get` alone, so the cardinality projection
        // returns exactly `1`. A future edit that widened `read_only()`
        // (or narrowed it below the singleton get-only shape) would
        // silently drift this anchor; this pin locks the read-only
        // shape to its intended singleton cardinality.
        assert_eq!(Capabilities::read_only().supported_op_count(), 1);
    }

    #[test]
    fn capabilities_empty_supported_op_count_is_zero() {
        // Cross-surface anchor on the hand-built all-`false` shape:
        // the ∃-mute pole (no shipped constructor lands here, but the
        // pole is reachable and must carry the bottom cardinality by
        // construction). Anchors the bottom of the closed range `0..=6`.
        let empty = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        assert_eq!(empty.supported_op_count(), 0);
    }

    #[test]
    fn capabilities_supported_op_count_agrees_with_operation_axis_filter_count() {
        // The cross-altitude weld with the operation axis one altitude
        // down: the count reported by the projection must agree with
        // the re-derivation `SecretOperation::ALL.iter().filter(|op|
        // caps.supports(**op)).count()` pointwise on the canonical
        // sample table. A future edit that shifted the flag ↔ operation
        // pointwise correspondence in `Capabilities::supports` (an
        // arm swap, a dropped arm, a new operation whose supports arm
        // reads the wrong field) diverges here.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: true,
                delete: false,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: false,
                list: true,
                put: false,
                delete: true,
                rotate: false,
                versions: true,
            },
        ];
        for caps in samples {
            let filter_count = SecretOperation::ALL
                .iter()
                .filter(|op| caps.supports(**op))
                .count();
            assert_eq!(
                caps.supported_op_count() as usize,
                filter_count,
                "supported_op_count must agree with SecretOperation::ALL filter count on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supported_op_count_thresholds_agree_with_whole_set_compound_polarity_matrix() {
        // The load-bearing weld: the four threshold identities that
        // recover the whole-set ∃/¬∃/∀/¬∀ compound-polarity pairs from
        // the cardinality projection. A future edit that drifted the
        // count from the twelve compound predicates on ONE shape
        // diverges here rather than silently.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: false,
                list: true,
                put: true,
                delete: true,
                rotate: true,
                versions: true,
            },
        ];
        for caps in samples {
            let count = caps.supported_op_count();
            assert_eq!(
                caps.supports_any_op(),
                count > 0,
                "supports_any_op must equal (supported_op_count > 0) on {caps:?}",
            );
            assert_eq!(
                caps.supports_no_op(),
                count == 0,
                "supports_no_op must equal (supported_op_count == 0) on {caps:?}",
            );
            assert_eq!(
                caps.supports_every_op(),
                count == 6,
                "supports_every_op must equal (supported_op_count == 6) on {caps:?}",
            );
            assert_eq!(
                caps.supports_not_every_op(),
                count < 6,
                "supports_not_every_op must equal (supported_op_count < 6) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supported_op_count_stays_within_all_len_bound() {
        // Bounds pin: the count stays in the closed range `0..=6` for
        // every reachable Capabilities shape. The bound is exactly
        // `SecretOperation::ALL.len()` for the shipped six-variant
        // operation axis; a hypothetical seventh SecretOperation
        // variant with its own Capabilities field would raise the
        // bound in lockstep at the field-adder site. Sweeps the full
        // 2^6 = 64 reachable shapes exhaustively.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.supported_op_count();
            assert!(
                (count as usize) <= SecretOperation::ALL.len(),
                "supported_op_count must stay within SecretOperation::ALL.len() = {} on {caps:?}, got {count}",
                SecretOperation::ALL.len(),
            );
            assert_eq!(
                count,
                bits.count_ones() as u8,
                "supported_op_count must equal the popcount of the six-bit shape on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supported_op_count_is_const_callable() {
        // The cardinality projection is `const`-callable, matching the
        // twelve compound-polarity predicates at this same altitude.
        const _: () = assert!(Capabilities::full().supported_op_count() == 6);
        const _: () = assert!(Capabilities::read_only().supported_op_count() == 1);
        const EMPTY: Capabilities = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        const _: () = assert!(EMPTY.supported_op_count() == 0);
    }

    // ── Capabilities — per-half cardinality projections ────────────
    //
    // Pin table for the write/read-half slices of the cardinality
    // projection at the Capabilities altitude — orthogonal to (and
    // welding together with the shipped whole-set `supported_op_count`
    // via the meta-partition sum law) the twelve compound-polarity
    // predicates already at this altitude. The two per-half slices are
    // strictly parallel; their tests are folded together on the shape
    // sweeps and split apart on the write-half-only / read-half-only
    // constructor anchors:
    //   1. `capabilities_supported_op_count_is_sum_of_per_half_op_counts`
    //      — the load-bearing meta-partition sum law:
    //      whole == write-half + read-half on every reachable shape.
    //   2. `capabilities_full_supported_mutating_op_count_is_three` /
    //      `capabilities_full_supported_non_mutating_op_count_is_three`
    //      — cross-surface top-anchors on the shipped `full()`
    //      constructor (both halves saturate).
    //   3. `capabilities_read_only_supported_mutating_op_count_is_zero`
    //      / `capabilities_read_only_supported_non_mutating_op_count_is_one`
    //      — cross-surface anchors on the shipped `read_only()`
    //      constructor (write half is bottom, read half is the get-only
    //      singleton).
    //   4. `capabilities_empty_supported_per_half_op_counts_are_zero`
    //      — cross-surface bottom anchors on the hand-built all-`false`
    //      shape (both halves at the bottom of the closed range).
    //   5. `capabilities_supported_mutating_op_count_agrees_with_operation_axis_filter_count`
    //      / `capabilities_supported_non_mutating_op_count_agrees_with_operation_axis_filter_count`
    //      — the cross-altitude welds with the operation axis via
    //      `SecretOperation::ALL.iter().filter(is_mutating &&
    //      supports).count()` and its is_non_mutating dual.
    //   6. `capabilities_supported_mutating_op_count_thresholds_agree_with_write_half_compound_polarity_matrix`
    //      / `capabilities_supported_non_mutating_op_count_thresholds_agree_with_read_half_compound_polarity_matrix`
    //      — the four threshold identities per half that recover the
    //      write-half and read-half ∃/¬∃/∀/¬∀ compound-polarity pairs
    //      from the per-half count.
    //   7. `capabilities_supported_mutating_op_count_stays_within_write_half_bound`
    //      / `capabilities_supported_non_mutating_op_count_stays_within_read_half_bound`
    //      — the closed-range bounds `count as usize <= 3` for every
    //      reachable shape, with an independent oracle via
    //      `u32::count_ones` on the three-bit half-shape.
    //   8. `capabilities_supported_mutating_op_count_is_const_callable`
    //      / `capabilities_supported_non_mutating_op_count_is_const_callable`
    //      — const-callability welds on both per-half projections.

    #[test]
    fn capabilities_supported_op_count_is_sum_of_per_half_op_counts() {
        // The load-bearing meta-partition sum law: the whole-set
        // cardinality equals the sum of the two per-half cardinalities
        // on every reachable Capabilities shape. A future edit that
        // shifts a field from one half to the other on ONE of the
        // three projections (whole / write-half / read-half) diverges
        // here rather than silently. Swept exhaustively over the full
        // 2^6 = 64 reachable shapes.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            assert_eq!(
                caps.supported_op_count(),
                caps.supported_mutating_op_count() + caps.supported_non_mutating_op_count(),
                "supported_op_count must equal supported_mutating_op_count + supported_non_mutating_op_count on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_full_supported_mutating_op_count_is_three() {
        // Cross-surface top-anchor on the shipped `Capabilities::full()`
        // constructor: it advertises every write-half operation, so the
        // write-half cardinality saturates at the meta-partition size
        // (3 = SecretOperation::ALL.iter().filter(is_mutating).count()).
        assert_eq!(Capabilities::full().supported_mutating_op_count(), 3);
    }

    #[test]
    fn capabilities_full_supported_non_mutating_op_count_is_three() {
        // Cross-surface top-anchor on `Capabilities::full()`: the
        // read-half cardinality saturates at 3 =
        // SecretOperation::ALL.iter().filter(is_non_mutating).count().
        assert_eq!(Capabilities::full().supported_non_mutating_op_count(), 3);
    }

    #[test]
    fn capabilities_read_only_supported_mutating_op_count_is_zero() {
        // Cross-surface anchor on `Capabilities::read_only()`: it
        // advertises NO mutating operations, so the write-half
        // cardinality is exactly 0. A future edit that widened
        // `read_only()` onto ANY mutating flag would silently drift
        // this anchor; this pin locks the read-only shape's mutation
        // pole at the bottom of the closed range.
        assert_eq!(Capabilities::read_only().supported_mutating_op_count(), 0);
    }

    #[test]
    fn capabilities_read_only_supported_non_mutating_op_count_is_one() {
        // Cross-surface anchor on `Capabilities::read_only()`: it
        // advertises `get` alone (and not `list` or `versions`), so
        // the read-half cardinality is exactly the get-only singleton
        // `1`. A future edit that widened `read_only()` onto `list` or
        // `versions` (or dropped `get`) would silently drift this
        // anchor; this pin locks the read-only shape to its intended
        // get-only singleton on the read half.
        assert_eq!(
            Capabilities::read_only().supported_non_mutating_op_count(),
            1,
        );
    }

    #[test]
    fn capabilities_empty_supported_per_half_op_counts_are_zero() {
        // Cross-surface bottom anchors on the hand-built all-`false`
        // shape: both per-half cardinalities land at the bottom of the
        // closed range `0..=3`. No shipped constructor lands here, but
        // the pole is reachable and must carry the bottom cardinality
        // on both halves by construction.
        let empty = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        assert_eq!(empty.supported_mutating_op_count(), 0);
        assert_eq!(empty.supported_non_mutating_op_count(), 0);
    }

    #[test]
    fn capabilities_supported_mutating_op_count_agrees_with_operation_axis_filter_count() {
        // The cross-altitude weld with the operation axis one altitude
        // down on the write-half: the count must agree with the
        // re-derivation `SecretOperation::ALL.iter().filter(|op|
        // op.is_mutating() && caps.supports(**op)).count()` pointwise
        // over the exhaustive 2^6 = 64 shape sweep. A future edit that
        // shifted a field from one half to the other on either the
        // per-half count or on `SecretOperation::is_mutating` diverges
        // here.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let filter_count = SecretOperation::ALL
                .iter()
                .filter(|op| op.is_mutating() && caps.supports(**op))
                .count();
            assert_eq!(
                caps.supported_mutating_op_count() as usize,
                filter_count,
                "supported_mutating_op_count must agree with the is_mutating filter count on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supported_non_mutating_op_count_agrees_with_operation_axis_filter_count() {
        // Read-half dual of the above: the count must agree with the
        // re-derivation via `SecretOperation::is_non_mutating` on the
        // full 64-shape sweep.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let filter_count = SecretOperation::ALL
                .iter()
                .filter(|op| op.is_non_mutating() && caps.supports(**op))
                .count();
            assert_eq!(
                caps.supported_non_mutating_op_count() as usize,
                filter_count,
                "supported_non_mutating_op_count must agree with the is_non_mutating filter count on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supported_mutating_op_count_thresholds_agree_with_write_half_compound_polarity_matrix()
     {
        // The load-bearing weld on the write half: the four threshold
        // identities that recover the write-half ∃/¬∃/∀/¬∀ compound-
        // polarity quartet from the per-half cardinality. A future edit
        // that drifted the write-half count from the four compound
        // predicates on ONE shape diverges here rather than silently.
        // Swept exhaustively over the full 2^6 = 64 reachable shapes.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.supported_mutating_op_count();
            assert_eq!(
                caps.supports_any_mutating_op(),
                count > 0,
                "supports_any_mutating_op must equal (supported_mutating_op_count > 0) on {caps:?}",
            );
            assert_eq!(
                caps.supports_no_mutating_op(),
                count == 0,
                "supports_no_mutating_op must equal (supported_mutating_op_count == 0) on {caps:?}",
            );
            assert_eq!(
                caps.supports_every_mutating_op(),
                count == 3,
                "supports_every_mutating_op must equal (supported_mutating_op_count == 3) on {caps:?}",
            );
            assert_eq!(
                caps.supports_not_every_mutating_op(),
                count < 3,
                "supports_not_every_mutating_op must equal (supported_mutating_op_count < 3) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supported_non_mutating_op_count_thresholds_agree_with_read_half_compound_polarity_matrix()
     {
        // Read-half dual: the four threshold identities that recover
        // the read-half ∃/¬∃/∀/¬∀ compound-polarity quartet from the
        // per-half cardinality. Swept over the full 2^6 = 64 shapes.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.supported_non_mutating_op_count();
            assert_eq!(
                caps.supports_any_non_mutating_op(),
                count > 0,
                "supports_any_non_mutating_op must equal (supported_non_mutating_op_count > 0) on {caps:?}",
            );
            assert_eq!(
                caps.supports_no_non_mutating_op(),
                count == 0,
                "supports_no_non_mutating_op must equal (supported_non_mutating_op_count == 0) on {caps:?}",
            );
            assert_eq!(
                caps.supports_every_non_mutating_op(),
                count == 3,
                "supports_every_non_mutating_op must equal (supported_non_mutating_op_count == 3) on {caps:?}",
            );
            assert_eq!(
                caps.supports_not_every_non_mutating_op(),
                count < 3,
                "supports_not_every_non_mutating_op must equal (supported_non_mutating_op_count < 3) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supported_mutating_op_count_stays_within_write_half_bound() {
        // Bounds pin on the write half: the count stays in the closed
        // range `0..=3` for every reachable Capabilities shape (the
        // bound is exactly the write-half meta-partition size for the
        // shipped six-variant operation axis). Independent oracle: the
        // three-bit popcount of `(put, delete, rotate)` via
        // `u32::count_ones` — a future edit that dropped, doubled, or
        // mis-signed one term of the three-term sum diverges here on
        // the first shape where that term flips, orthogonal to the
        // threshold-identity pin above.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.supported_mutating_op_count();
            assert!(
                count <= 3,
                "supported_mutating_op_count must stay within the write-half meta-partition size 3 on {caps:?}, got {count}",
            );
            let write_half_bits = ((bits >> 2) & 0b111) as u32;
            assert_eq!(
                count,
                write_half_bits.count_ones() as u8,
                "supported_mutating_op_count must equal the popcount of the three write-half bits (put|delete|rotate) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supported_non_mutating_op_count_stays_within_read_half_bound() {
        // Read-half dual of the above: bounded by 3, independent oracle
        // via `u32::count_ones` on the three-bit `(get, list, versions)`
        // half-shape. Note the bit layout: bits 0 (get) and 1 (list)
        // pack together, and bit 5 (versions) sits at the top of the
        // six-bit shape; the oracle re-packs the three read-half bits
        // into `(get << 0) | (list << 1) | (versions << 2)` so the
        // popcount is orthogonal to the bit assignment above.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.supported_non_mutating_op_count();
            assert!(
                count <= 3,
                "supported_non_mutating_op_count must stay within the read-half meta-partition size 3 on {caps:?}, got {count}",
            );
            let read_half_bits = ((bits & 0b0000_0001) as u32)
                | ((bits & 0b0000_0010) as u32)
                | ((((bits >> 5) & 0b1) as u32) << 2);
            assert_eq!(
                count,
                read_half_bits.count_ones() as u8,
                "supported_non_mutating_op_count must equal the popcount of the three read-half bits (get|list|versions) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_supported_mutating_op_count_is_const_callable() {
        // The write-half cardinality projection is `const`-callable,
        // matching the discipline of the four write-half compound-
        // polarity predicates and the whole-set count at this altitude.
        const _: () = assert!(Capabilities::full().supported_mutating_op_count() == 3);
        const _: () = assert!(Capabilities::read_only().supported_mutating_op_count() == 0);
        const EMPTY: Capabilities = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        const _: () = assert!(EMPTY.supported_mutating_op_count() == 0);
    }

    #[test]
    fn capabilities_supported_non_mutating_op_count_is_const_callable() {
        // Read-half dual: the read-half cardinality projection is
        // `const`-callable.
        const _: () = assert!(Capabilities::full().supported_non_mutating_op_count() == 3);
        const _: () = assert!(Capabilities::read_only().supported_non_mutating_op_count() == 1);
        const EMPTY: Capabilities = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        const _: () = assert!(EMPTY.supported_non_mutating_op_count() == 0);
    }

    // ── Capabilities — complement cardinality projection ───────────
    //
    // Pin table for the `unsupported_op_count` complement projection at
    // the Capabilities altitude — the compound-polarity sibling of the
    // shipped whole-set `supported_op_count` (commit `67b95a3`), closing
    // the pair via the axis-cardinality sum-complement law:
    //   1. `capabilities_full_unsupported_op_count_is_zero` — cross-
    //      surface anchor on the shipped `full()` constructor
    //      (bottom of the closed range).
    //   2. `capabilities_read_only_unsupported_op_count_is_five` —
    //      cross-surface anchor on the shipped `read_only()`
    //      constructor.
    //   3. `capabilities_empty_unsupported_op_count_is_six` —
    //      cross-surface anchor on the hand-built all-`false` shape
    //      (top of the closed range).
    //   4. `capabilities_supported_and_unsupported_op_counts_sum_to_axis_cardinality`
    //      — the load-bearing sum-complement law that welds the two
    //      polarity projections to the axis cardinality.
    //   5. `capabilities_unsupported_op_count_agrees_with_operation_axis_filter_count`
    //      — the cross-altitude weld with the operation axis via the
    //      `SecretOperation::ALL.iter().filter(!supports).count()`
    //      re-derivation.
    //   6. `capabilities_unsupported_op_count_thresholds_agree_with_whole_set_compound_polarity_matrix`
    //      — the four inverse threshold identities that recover the
    //      whole-set ∃/¬∃/∀/¬∀ compound-polarity pairs from the count.
    //   7. `capabilities_unsupported_op_count_stays_within_all_len_bound`
    //      — the closed-range bound with a popcount oracle on the
    //      inverted six-bit shape, swept exhaustively over 2^6 shapes.
    //   8. `capabilities_unsupported_op_count_is_const_callable` —
    //      const-callability weld on the complement projection.

    #[test]
    fn capabilities_full_unsupported_op_count_is_zero() {
        // Cross-surface anchor: the shipped `Capabilities::full()`
        // set advertises every operation, so the complement projection
        // returns the bottom of the closed range `0..=6`. A future edit
        // that dropped ANY flag from `full()` would silently drift the
        // bottom anchor; this pin locks it to the shipped six-flag shape.
        assert_eq!(Capabilities::full().unsupported_op_count(), 0);
    }

    #[test]
    fn capabilities_read_only_unsupported_op_count_is_five() {
        // Cross-surface anchor: the shipped `Capabilities::read_only()`
        // set advertises `get` alone, so the complement projection
        // returns exactly `5` (the five operations OTHER than `get`).
        // A future edit that widened `read_only()` (or narrowed it below
        // the singleton get-only shape) would silently drift this anchor.
        assert_eq!(Capabilities::read_only().unsupported_op_count(), 5);
    }

    #[test]
    fn capabilities_empty_unsupported_op_count_is_six() {
        // Cross-surface anchor: the hand-built all-`false` shape
        // advertises no operation, so the complement projection returns
        // the top of the closed range `0..=6`. Locks the top of the
        // range to the shipped six-variant operation axis.
        let empty = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        assert_eq!(empty.unsupported_op_count(), 6);
    }

    #[test]
    fn capabilities_supported_and_unsupported_op_counts_sum_to_axis_cardinality() {
        // The load-bearing axis-cardinality sum-complement law:
        // `supported_op_count() + unsupported_op_count() ==
        // SecretOperation::ALL.len() as u8` for every reachable shape.
        // A future edit that drifted ONE of the two polarity projections
        // (a dropped term, a doubled term, a mis-signed term) diverges
        // here on the first shape where that term flips, rather than
        // silently. Sweeps the full 2^6 = 64 reachable shapes.
        let axis_cardinality = SecretOperation::ALL.len() as u8;
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            assert_eq!(
                caps.supported_op_count() + caps.unsupported_op_count(),
                axis_cardinality,
                "supported_op_count + unsupported_op_count must equal SecretOperation::ALL.len() = {axis_cardinality} on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_op_count_agrees_with_operation_axis_filter_count() {
        // The cross-altitude weld with the operation axis one altitude
        // down: the complement count reported by the projection must
        // agree with the re-derivation `SecretOperation::ALL.iter()
        // .filter(|op| !caps.supports(**op)).count()` pointwise on the
        // canonical sample table. A future edit that shifted the flag
        // ↔ operation pointwise correspondence in `Capabilities::supports`
        // (an arm swap, a dropped arm, a new operation whose supports
        // arm reads the wrong field) diverges here.
        let samples = [
            Capabilities::read_only(),
            Capabilities::full(),
            Capabilities {
                get: false,
                list: false,
                put: false,
                delete: false,
                rotate: false,
                versions: false,
            },
            Capabilities {
                get: true,
                list: true,
                put: false,
                delete: false,
                rotate: false,
                versions: true,
            },
            Capabilities {
                get: false,
                list: false,
                put: true,
                delete: true,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: true,
                list: false,
                put: true,
                delete: false,
                rotate: true,
                versions: false,
            },
            Capabilities {
                get: false,
                list: true,
                put: false,
                delete: true,
                rotate: false,
                versions: true,
            },
        ];
        for caps in samples {
            let filter_count = SecretOperation::ALL
                .iter()
                .filter(|op| !caps.supports(**op))
                .count();
            assert_eq!(
                caps.unsupported_op_count() as usize,
                filter_count,
                "unsupported_op_count must agree with SecretOperation::ALL !supports filter count on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_op_count_thresholds_agree_with_whole_set_compound_polarity_matrix()
    {
        // The load-bearing inverse-weld: the four inverse threshold
        // identities that recover the whole-set ∃/¬∃/∀/¬∀ compound-
        // polarity pairs from the complement projection. A future edit
        // that drifted the count from the twelve compound predicates on
        // ONE shape diverges here rather than silently. Swept
        // exhaustively over the 2^6 = 64 reachable shapes.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.unsupported_op_count();
            assert_eq!(
                caps.supports_no_op(),
                count == 6,
                "supports_no_op must equal (unsupported_op_count == 6) on {caps:?}",
            );
            assert_eq!(
                caps.supports_every_op(),
                count == 0,
                "supports_every_op must equal (unsupported_op_count == 0) on {caps:?}",
            );
            assert_eq!(
                caps.supports_any_op(),
                count < 6,
                "supports_any_op must equal (unsupported_op_count < 6) on {caps:?}",
            );
            assert_eq!(
                caps.supports_not_every_op(),
                count > 0,
                "supports_not_every_op must equal (unsupported_op_count > 0) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_op_count_stays_within_all_len_bound() {
        // Bounds pin: the complement count stays in the closed range
        // `0..=6` for every reachable Capabilities shape. The bound is
        // exactly `SecretOperation::ALL.len()` for the shipped
        // six-variant operation axis; a hypothetical seventh
        // SecretOperation variant with its own Capabilities field would
        // raise the bound in lockstep at the field-adder site. Sweeps
        // the full 2^6 = 64 reachable shapes and reconciles against
        // `u32::count_ones` on the INVERTED six-bit shape as an
        // independent oracle — a future edit that dropped, doubled, or
        // mis-signed one term on the six-term complement sum diverges
        // at the popcount check on the first shape where that term
        // flips.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.unsupported_op_count();
            assert!(
                (count as usize) <= SecretOperation::ALL.len(),
                "unsupported_op_count must stay within SecretOperation::ALL.len() = {} on {caps:?}, got {count}",
                SecretOperation::ALL.len(),
            );
            let inverted = (!bits) & 0b0011_1111;
            assert_eq!(
                count,
                inverted.count_ones() as u8,
                "unsupported_op_count must equal the popcount of the inverted six-bit shape on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_op_count_is_const_callable() {
        // The complement projection is `const`-callable, matching the
        // shipped `supported_op_count` and the twelve compound-polarity
        // predicates at this same altitude.
        const _: () = assert!(Capabilities::full().unsupported_op_count() == 0);
        const _: () = assert!(Capabilities::read_only().unsupported_op_count() == 5);
        const EMPTY: Capabilities = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        const _: () = assert!(EMPTY.unsupported_op_count() == 6);
    }

    // ── Capabilities — write-half complement cardinality projection ─
    //
    // Pin table for `unsupported_mutating_op_count` — the write-half
    // slice of the complement projection at the Capabilities altitude,
    // compound-polarity sibling of the shipped `supported_mutating_op_count`
    // (commit `69eb383`), closing the write-half pair via the
    // meta-partition sum-complement law `supported_mutating_op_count +
    // unsupported_mutating_op_count == 3`. Peer of the whole-set
    // complement `unsupported_op_count` (commit `d6f627d`) restricted to
    // the write-half three-field partition:
    //   1. `capabilities_full_unsupported_mutating_op_count_is_zero` —
    //      cross-surface anchor on `full()` (bottom of `0..=3`).
    //   2. `capabilities_read_only_unsupported_mutating_op_count_is_three`
    //      — cross-surface anchor on `read_only()` (top of `0..=3`,
    //      since `read_only()` advertises no write-half op).
    //   3. `capabilities_empty_unsupported_mutating_op_count_is_three` —
    //      cross-surface anchor on the hand-built all-`false` shape
    //      (top of `0..=3`).
    //   4. `capabilities_supported_and_unsupported_mutating_op_counts_sum_to_write_half_size`
    //      — the load-bearing write-half sum-complement law welding the
    //      two polarity slices to the write-half meta-partition size.
    //   5. `capabilities_unsupported_mutating_op_count_agrees_with_operation_axis_filter_count`
    //      — the cross-altitude weld via
    //      `SecretOperation::ALL.iter().filter(is_mutating && !supports)
    //      .count()`.
    //   6. `capabilities_unsupported_mutating_op_count_thresholds_agree_with_write_half_compound_polarity_matrix`
    //      — the four inverse threshold identities that recover the
    //      write-half ∃/¬∃/∀/¬∀ pair from the write-half complement count.
    //   7. `capabilities_unsupported_mutating_op_count_stays_within_write_half_bound`
    //      — the closed-range bound with a popcount oracle on the
    //      INVERTED three write-half bits, swept exhaustively over 2^6
    //      shapes.
    //   8. `capabilities_unsupported_mutating_op_count_is_const_callable`
    //      — const-callability weld on the write-half complement
    //      projection.

    #[test]
    fn capabilities_full_unsupported_mutating_op_count_is_zero() {
        // Cross-surface anchor: the shipped `Capabilities::full()`
        // constructor advertises every write-half operation, so the
        // write-half complement projection returns the bottom of the
        // closed range `0..=3`. A future edit that dropped a write-half
        // flag from `full()` would silently drift this anchor; this pin
        // locks the write-half bottom of the range to the shipped shape.
        assert_eq!(Capabilities::full().unsupported_mutating_op_count(), 0);
    }

    #[test]
    fn capabilities_read_only_unsupported_mutating_op_count_is_three() {
        // Cross-surface anchor: the shipped `Capabilities::read_only()`
        // constructor advertises `get` alone (no write-half op), so the
        // write-half complement projection saturates at the top of the
        // closed range `0..=3`. A future edit that widened `read_only()`
        // onto ANY write-half flag (a rogue `put`, `delete`, or `rotate`)
        // would silently drift this anchor; this pin locks the read-only
        // shape's write-half pole at the top of the range.
        assert_eq!(Capabilities::read_only().unsupported_mutating_op_count(), 3,);
    }

    #[test]
    fn capabilities_empty_unsupported_mutating_op_count_is_three() {
        // Cross-surface anchor: the hand-built all-`false` shape
        // advertises no operation, so the write-half complement projection
        // saturates at the top of the closed range `0..=3`. Locks the
        // top of the range on the empty pole (no shipped constructor
        // lands here, but the pole is reachable).
        let empty = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        assert_eq!(empty.unsupported_mutating_op_count(), 3);
    }

    #[test]
    fn capabilities_supported_and_unsupported_mutating_op_counts_sum_to_write_half_size() {
        // The load-bearing write-half sum-complement law:
        // `supported_mutating_op_count() + unsupported_mutating_op_count()
        // == 3` (the write-half meta-partition size) for every reachable
        // shape. A future edit that drifted ONE of the two write-half
        // polarity projections (a dropped term, a doubled term, a
        // mis-signed term on either three-term sum) diverges here on the
        // first shape where that term flips, rather than silently. Sweeps
        // the full 2^6 = 64 reachable shapes.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            assert_eq!(
                caps.supported_mutating_op_count() + caps.unsupported_mutating_op_count(),
                3,
                "supported_mutating_op_count + unsupported_mutating_op_count must equal 3 on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_mutating_op_count_agrees_with_operation_axis_filter_count() {
        // The cross-altitude weld with the operation axis one altitude
        // down on the write-half complement: the count must agree with
        // the re-derivation `SecretOperation::ALL.iter().filter(|op|
        // op.is_mutating() && !caps.supports(**op)).count()` pointwise
        // over the exhaustive 2^6 = 64 shape sweep. A future edit that
        // shifted a field from one half to the other on either the
        // write-half complement count or on `SecretOperation::is_mutating`
        // diverges here.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let filter_count = SecretOperation::ALL
                .iter()
                .filter(|op| op.is_mutating() && !caps.supports(**op))
                .count();
            assert_eq!(
                caps.unsupported_mutating_op_count() as usize,
                filter_count,
                "unsupported_mutating_op_count must agree with the is_mutating && !supports filter count on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_mutating_op_count_thresholds_agree_with_write_half_compound_polarity_matrix()
     {
        // The load-bearing inverse-weld: the four inverse threshold
        // identities that recover the write-half ∃/¬∃/∀/¬∀ compound-
        // polarity quartet from the write-half complement projection.
        // A future edit that drifted the write-half complement count
        // from the four write-half compound predicates on ONE shape
        // diverges here rather than silently. Swept exhaustively over
        // the 2^6 = 64 reachable shapes.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.unsupported_mutating_op_count();
            assert_eq!(
                caps.supports_no_mutating_op(),
                count == 3,
                "supports_no_mutating_op must equal (unsupported_mutating_op_count == 3) on {caps:?}",
            );
            assert_eq!(
                caps.supports_every_mutating_op(),
                count == 0,
                "supports_every_mutating_op must equal (unsupported_mutating_op_count == 0) on {caps:?}",
            );
            assert_eq!(
                caps.supports_any_mutating_op(),
                count < 3,
                "supports_any_mutating_op must equal (unsupported_mutating_op_count < 3) on {caps:?}",
            );
            assert_eq!(
                caps.supports_not_every_mutating_op(),
                count > 0,
                "supports_not_every_mutating_op must equal (unsupported_mutating_op_count > 0) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_mutating_op_count_stays_within_write_half_bound() {
        // Bounds pin on the write-half complement: the count stays in
        // the closed range `0..=3` for every reachable Capabilities
        // shape (the bound is exactly the write-half meta-partition
        // size for the shipped six-variant operation axis). Independent
        // oracle: the three-bit popcount of the INVERTED `(put, delete,
        // rotate)` half-shape via `u32::count_ones` — a future edit
        // that dropped, doubled, or mis-signed one term on the three-
        // term complement sum diverges here on the first shape where
        // that term flips, orthogonal to the sum-complement pin above
        // (where a matching drift on `supported_mutating_op_count` would
        // mask it) and to the threshold-identity pin (where a matching
        // drift on the compound-polarity quartet would mask it).
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.unsupported_mutating_op_count();
            assert!(
                count <= 3,
                "unsupported_mutating_op_count must stay within the write-half meta-partition size 3 on {caps:?}, got {count}",
            );
            let inverted_write_half_bits = ((!bits) >> 2) & 0b111;
            assert_eq!(
                count,
                u32::from(inverted_write_half_bits).count_ones() as u8,
                "unsupported_mutating_op_count must equal the popcount of the inverted three write-half bits (put|delete|rotate) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_mutating_op_count_is_const_callable() {
        // The write-half complement cardinality projection is `const`-
        // callable, matching the discipline of the four write-half
        // compound-polarity predicates, of `supported_mutating_op_count`
        // at the same altitude, and of the whole-set complement
        // `unsupported_op_count` one meta-partition step wider.
        const _: () = assert!(Capabilities::full().unsupported_mutating_op_count() == 0);
        const _: () = assert!(Capabilities::read_only().unsupported_mutating_op_count() == 3);
        const EMPTY: Capabilities = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        const _: () = assert!(EMPTY.unsupported_mutating_op_count() == 3);
    }

    // Pin table for `unsupported_non_mutating_op_count` — the read-half
    // slice of the complement projection at the Capabilities altitude,
    // compound-polarity sibling of the shipped `supported_non_mutating_op_count`,
    // closing the read-half pair via the meta-partition sum-complement
    // law `supported_non_mutating_op_count + unsupported_non_mutating_op_count
    // == 3`. Idiom-peer of the write-half complement
    // `unsupported_mutating_op_count` at the same altitude and of the
    // whole-set complement `unsupported_op_count` one meta-partition step
    // wider, restricted to the read-half three-field partition. This is
    // the sixth and final projection at the cardinality altitude — the
    // 2×3 `(supported, unsupported) × (whole, write-half, read-half)`
    // matrix closes here:
    //   1. `capabilities_full_unsupported_non_mutating_op_count_is_zero`
    //      — cross-surface anchor on `full()` (bottom of `0..=3`).
    //   2. `capabilities_read_only_unsupported_non_mutating_op_count_is_two`
    //      — cross-surface anchor on `read_only()` (get is advertised
    //      but list/versions are not, so the read-half complement is 2
    //      = 3 − 1, the mid-range read-half value the `read_only()`
    //      shape uniquely reaches at this altitude).
    //   3. `capabilities_empty_unsupported_non_mutating_op_count_is_three`
    //      — cross-surface anchor on the hand-built all-`false` shape
    //      (top of `0..=3`).
    //   4. `capabilities_supported_and_unsupported_non_mutating_op_counts_sum_to_read_half_size`
    //      — the load-bearing read-half sum-complement law welding the
    //      two polarity slices to the read-half meta-partition size.
    //   5. `capabilities_unsupported_op_count_is_sum_of_per_half_unsupported_op_counts`
    //      — the load-bearing meta-partition sum law on the COMPLEMENT
    //      polarity: `unsupported_op_count == unsupported_mutating_op_count
    //      + unsupported_non_mutating_op_count`, mirroring the shipped
    //      supported-side meta-partition sum law and closing the 2×3
    //      cardinality matrix.
    //   6. `capabilities_unsupported_non_mutating_op_count_agrees_with_operation_axis_filter_count`
    //      — the cross-altitude weld via
    //      `SecretOperation::ALL.iter().filter(is_non_mutating &&
    //      !supports).count()`.
    //   7. `capabilities_unsupported_non_mutating_op_count_thresholds_agree_with_read_half_compound_polarity_matrix`
    //      — the four inverse threshold identities that recover the
    //      read-half ∃/¬∃/∀/¬∀ pair from the read-half complement count.
    //   8. `capabilities_unsupported_non_mutating_op_count_stays_within_read_half_bound`
    //      — the closed-range bound with a popcount oracle on the
    //      INVERTED three read-half bits, swept exhaustively over 2^6
    //      shapes.
    //   9. `capabilities_unsupported_non_mutating_op_count_is_const_callable`
    //      — const-callability weld on the read-half complement
    //      projection.

    #[test]
    fn capabilities_full_unsupported_non_mutating_op_count_is_zero() {
        // Cross-surface anchor: the shipped `Capabilities::full()`
        // constructor advertises every read-half operation, so the
        // read-half complement projection returns the bottom of the
        // closed range `0..=3`. A future edit that dropped a read-half
        // flag from `full()` would silently drift this anchor; this pin
        // locks the read-half bottom of the range to the shipped shape.
        assert_eq!(Capabilities::full().unsupported_non_mutating_op_count(), 0);
    }

    #[test]
    fn capabilities_read_only_unsupported_non_mutating_op_count_is_two() {
        // Cross-surface anchor: the shipped `Capabilities::read_only()`
        // constructor advertises `get` alone on the read half — `list`
        // and `versions` are both `false` — so the read-half complement
        // projection lands at 2 = 3 − 1, the mid-range read-half value
        // uniquely reached by the `read_only()` shape at this altitude.
        // A future edit that widened `read_only()` onto `list` or
        // `versions` (or narrowed `get` off) would silently drift this
        // anchor; this pin locks the read-only shape's read-half
        // complement pole at 2.
        assert_eq!(
            Capabilities::read_only().unsupported_non_mutating_op_count(),
            2,
        );
    }

    #[test]
    fn capabilities_empty_unsupported_non_mutating_op_count_is_three() {
        // Cross-surface anchor: the hand-built all-`false` shape
        // advertises no operation, so the read-half complement projection
        // saturates at the top of the closed range `0..=3`. Locks the
        // top of the range on the empty pole (no shipped constructor
        // lands here, but the pole is reachable).
        let empty = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        assert_eq!(empty.unsupported_non_mutating_op_count(), 3);
    }

    #[test]
    fn capabilities_supported_and_unsupported_non_mutating_op_counts_sum_to_read_half_size() {
        // The load-bearing read-half sum-complement law:
        // `supported_non_mutating_op_count() +
        // unsupported_non_mutating_op_count() == 3` (the read-half
        // meta-partition size) for every reachable shape. A future edit
        // that drifted ONE of the two read-half polarity projections (a
        // dropped term, a doubled term, a mis-signed term on either
        // three-term sum) diverges here on the first shape where that
        // term flips, rather than silently. Sweeps the full 2^6 = 64
        // reachable shapes.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            assert_eq!(
                caps.supported_non_mutating_op_count() + caps.unsupported_non_mutating_op_count(),
                3,
                "supported_non_mutating_op_count + unsupported_non_mutating_op_count must equal 3 on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_op_count_is_sum_of_per_half_unsupported_op_counts() {
        // The load-bearing meta-partition sum law on the COMPLEMENT
        // polarity: the whole-set complement cardinality equals the sum
        // of the two per-half complement cardinalities on every
        // reachable Capabilities shape. Mirrors the shipped
        // supported-side law
        // `supported_op_count == supported_mutating_op_count +
        // supported_non_mutating_op_count` and closes the 2×3
        // `(polarity × partition)` cardinality matrix at the
        // Capabilities altitude. A future edit that shifts a field from
        // one half to the other on ONE of the three COMPLEMENT
        // projections (whole / write-half / read-half) diverges here
        // rather than silently. Swept exhaustively over the full 2^6 =
        // 64 reachable shapes.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            assert_eq!(
                caps.unsupported_op_count(),
                caps.unsupported_mutating_op_count() + caps.unsupported_non_mutating_op_count(),
                "unsupported_op_count must equal unsupported_mutating_op_count + unsupported_non_mutating_op_count on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_non_mutating_op_count_agrees_with_operation_axis_filter_count() {
        // The cross-altitude weld with the operation axis one altitude
        // down on the read-half complement: the count must agree with
        // the re-derivation `SecretOperation::ALL.iter().filter(|op|
        // op.is_non_mutating() && !caps.supports(**op)).count()`
        // pointwise over the exhaustive 2^6 = 64 shape sweep. A future
        // edit that shifted a field from one half to the other on
        // either the read-half complement count or on
        // `SecretOperation::is_non_mutating` diverges here.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let filter_count = SecretOperation::ALL
                .iter()
                .filter(|op| op.is_non_mutating() && !caps.supports(**op))
                .count();
            assert_eq!(
                caps.unsupported_non_mutating_op_count() as usize,
                filter_count,
                "unsupported_non_mutating_op_count must agree with the is_non_mutating && !supports filter count on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_non_mutating_op_count_thresholds_agree_with_read_half_compound_polarity_matrix()
     {
        // The load-bearing inverse-weld: the four inverse threshold
        // identities that recover the read-half ∃/¬∃/∀/¬∀ compound-
        // polarity quartet from the read-half complement projection. A
        // future edit that drifted the read-half complement count from
        // the four read-half compound predicates on ONE shape diverges
        // here rather than silently. Swept exhaustively over the 2^6 =
        // 64 reachable shapes.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.unsupported_non_mutating_op_count();
            assert_eq!(
                caps.supports_no_non_mutating_op(),
                count == 3,
                "supports_no_non_mutating_op must equal (unsupported_non_mutating_op_count == 3) on {caps:?}",
            );
            assert_eq!(
                caps.supports_every_non_mutating_op(),
                count == 0,
                "supports_every_non_mutating_op must equal (unsupported_non_mutating_op_count == 0) on {caps:?}",
            );
            assert_eq!(
                caps.supports_any_non_mutating_op(),
                count < 3,
                "supports_any_non_mutating_op must equal (unsupported_non_mutating_op_count < 3) on {caps:?}",
            );
            assert_eq!(
                caps.supports_not_every_non_mutating_op(),
                count > 0,
                "supports_not_every_non_mutating_op must equal (unsupported_non_mutating_op_count > 0) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_non_mutating_op_count_stays_within_read_half_bound() {
        // Bounds pin on the read-half complement: the count stays in
        // the closed range `0..=3` for every reachable Capabilities
        // shape (the bound is exactly the read-half meta-partition size
        // for the shipped six-variant operation axis). Independent
        // oracle: the three-bit popcount of the INVERTED `(get, list,
        // versions)` half-shape via `u32::count_ones` — a future edit
        // that dropped, doubled, or mis-signed one term on the three-
        // term complement sum diverges here on the first shape where
        // that term flips, orthogonal to the sum-complement pin above
        // (where a matching drift on `supported_non_mutating_op_count`
        // would mask it), to the meta-partition complement sum pin
        // (where a matching drift on `unsupported_op_count` or
        // `unsupported_mutating_op_count` would mask it), and to the
        // threshold-identity pin (where a matching drift on the
        // read-half compound-polarity quartet would mask it).
        //
        // Read-half bits in the packed shape are `get` (bit 0), `list`
        // (bit 1), and `versions` (bit 5): mask the three read-half
        // bits into a contiguous 0b_xxx byte before inverting so the
        // popcount reads only those three positions.
        for bits in 0u8..64 {
            let caps = Capabilities {
                get: (bits & 0b00_0001) != 0,
                list: (bits & 0b00_0010) != 0,
                put: (bits & 0b00_0100) != 0,
                delete: (bits & 0b00_1000) != 0,
                rotate: (bits & 0b01_0000) != 0,
                versions: (bits & 0b10_0000) != 0,
            };
            let count = caps.unsupported_non_mutating_op_count();
            assert!(
                count <= 3,
                "unsupported_non_mutating_op_count must stay within the read-half meta-partition size 3 on {caps:?}, got {count}",
            );
            let read_half_bits = (bits & 0b0000_0011) | ((bits & 0b0010_0000) >> 3);
            let inverted_read_half_bits = (!read_half_bits) & 0b111;
            assert_eq!(
                count,
                u32::from(inverted_read_half_bits).count_ones() as u8,
                "unsupported_non_mutating_op_count must equal the popcount of the inverted three read-half bits (get|list|versions) on {caps:?}",
            );
        }
    }

    #[test]
    fn capabilities_unsupported_non_mutating_op_count_is_const_callable() {
        // The read-half complement cardinality projection is `const`-
        // callable, matching the discipline of the four read-half
        // compound-polarity predicates, of `supported_non_mutating_op_count`
        // at the same altitude, of the write-half complement
        // `unsupported_mutating_op_count` at the same altitude, and of
        // the whole-set complement `unsupported_op_count` one
        // meta-partition step wider.
        const _: () = assert!(Capabilities::full().unsupported_non_mutating_op_count() == 0);
        const _: () = assert!(Capabilities::read_only().unsupported_non_mutating_op_count() == 2);
        const EMPTY: Capabilities = Capabilities {
            get: false,
            list: false,
            put: false,
            delete: false,
            rotate: false,
            versions: false,
        };
        const _: () = assert!(EMPTY.unsupported_non_mutating_op_count() == 3);
    }

    // ── SecretOperation — Ord / Display / FromStr / serde ──────────
    //
    // The (Ord, Display, FromStr, serde::{Serialize, Deserialize})
    // quartet idiom-peer of the lift already landed on
    // `ShikumiErrorKind` (commit `911b598`), `SecretClientKind`
    // (commit `24c7b33`), `DiffLineKind` (commit `c403e1a`),
    // `WatchEventClass` (commit `94f8a8b`), `EnvMetadataTagKind`
    // (commit `b556b75`), `SecretRefShape` (commit `8a84bb6`),
    // `SecretBackendKind` (commit `9b1da86`), `FigmentNameTagKind`
    // (commit `64a47e7`), `FigmentSourceKind` (commit `5df265c`),
    // `ConfigSourceKind` (commit `e0b96d1`), and `SecretErrorKind`
    // (commit `38b9964`), now lifted onto the secret-client
    // operation axis primitive.

    #[test]
    fn secret_operation_ord_matches_all_declaration_order() {
        // The derived Ord on SecretOperation is declaration-order
        // lex over ALL: `Get < List < Put < Delete < Rotate <
        // GetVersion`. A BTreeMap keyed on the operation axis
        // (per-operation request-rate histograms, per-operation
        // latency dashboards, attestation manifests recording the
        // operation-mix histogram of refused calls, structured-
        // diagnostic legends bucketing per-operation counters in
        // declaration order) emits rows in declaration order
        // deterministically without a hand-rolled comparator at the
        // renderer.
        //
        // Two-leg pin: (1) ALL is a strictly-increasing chain under
        // Ord, (2) cmp/partial_cmp agree with the array-index lex
        // over ALL on every pair (and reflexivity holds).
        use std::cmp::Ordering;
        for window in SecretOperation::ALL.windows(2) {
            assert!(
                window[0] < window[1],
                "SecretOperation::ALL must be strictly increasing under Ord, \
                 but {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
        for (i, &a) in SecretOperation::ALL.iter().enumerate() {
            for (j, &b) in SecretOperation::ALL.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    a.cmp(&b),
                    expected,
                    "SecretOperation::cmp must match ALL-index lex for ({a:?}, {b:?})",
                );
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "SecretOperation::partial_cmp must agree with cmp for ({a:?}, {b:?})",
                );
                if i == j {
                    assert_eq!(a.cmp(&b), Ordering::Equal, "Ord must be reflexive on {a:?}",);
                }
            }
        }
    }

    #[test]
    fn secret_operation_btreemap_emits_in_declaration_order() {
        // The compounding payoff of the Ord derive at a typed
        // consumer site: a BTreeMap<SecretOperation, _> emits keys
        // in declaration order on `iter()` / `into_iter()`
        // regardless of insertion order, matching
        // `SecretOperation::ALL`.
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<SecretOperation, u32> = BTreeMap::new();
        counts.insert(SecretOperation::GetVersion, 6);
        counts.insert(SecretOperation::Get, 1);
        counts.insert(SecretOperation::Rotate, 5);
        counts.insert(SecretOperation::List, 2);
        counts.insert(SecretOperation::Delete, 4);
        counts.insert(SecretOperation::Put, 3);
        let observed: Vec<SecretOperation> = counts.keys().copied().collect();
        assert_eq!(
            observed,
            SecretOperation::ALL.to_vec(),
            "BTreeMap<SecretOperation, _> must emit keys in ALL declaration order",
        );
    }

    #[test]
    fn secret_operation_display_matches_as_str() {
        // Display writes the canonical label as_str returns, byte-
        // for-byte. The two surfaces stay aligned by construction —
        // a future rename of either must update the other in
        // lockstep.
        for op in SecretOperation::ALL.iter().copied() {
            assert_eq!(
                format!("{op}"),
                op.as_str(),
                "Display must agree with as_str for {op:?}",
            );
        }
    }

    #[test]
    fn secret_operation_from_str_round_trips_over_every_variant() {
        // Display → FromStr identity round-trip over every variant.
        // FromStr lowers through ClosedAxisLabel::from_canonical_str,
        // so any future override of that trait method is held to
        // this law at the inherent FromStr surface as well.
        for op in SecretOperation::ALL {
            let rendered = op.to_string();
            let parsed: SecretOperation = rendered
                .parse()
                .expect("FromStr must round-trip Display output");
            assert_eq!(parsed, *op, "FromStr must round-trip {op:?}");
        }
    }

    #[test]
    fn secret_operation_from_str_is_case_insensitive() {
        // FromStr lowers through ClosedAxisLabel::from_canonical_str
        // which uses eq_ignore_ascii_case over ALL — uppercase and
        // mixed-case scalars an operator might type into an env var
        // or CLI flag parse pointwise to the same variant.
        assert_eq!(
            "GET".parse::<SecretOperation>().unwrap(),
            SecretOperation::Get,
        );
        assert_eq!(
            "List".parse::<SecretOperation>().unwrap(),
            SecretOperation::List,
        );
        assert_eq!(
            "pUt".parse::<SecretOperation>().unwrap(),
            SecretOperation::Put,
        );
        assert_eq!(
            "DELETE".parse::<SecretOperation>().unwrap(),
            SecretOperation::Delete,
        );
        assert_eq!(
            "Rotate".parse::<SecretOperation>().unwrap(),
            SecretOperation::Rotate,
        );
        assert_eq!(
            "Get_Version".parse::<SecretOperation>().unwrap(),
            SecretOperation::GetVersion,
        );
    }

    #[test]
    fn secret_operation_from_str_unknown_operation_error_carries_label_verbatim() {
        // Unrecognized labels reject through ShikumiError::Parse
        // with the offending substring embedded verbatim in the
        // rendered message — same verbatim-rejection discipline as
        // the prior sibling lifts.
        for bad in &["metadata", "versions", "describe", "", "  get"] {
            let err = bad
                .parse::<SecretOperation>()
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
    fn secret_operation_serde_yaml_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over
        // every variant through serde_yaml. Closes the (Serialize,
        // Deserialize) idiom-peer of the (Display, FromStr) stdlib
        // pair on the operation axis primitive.
        for op in SecretOperation::ALL {
            let yaml = serde_yaml::to_string(op).expect("Serialize must succeed");
            let parsed: SecretOperation =
                serde_yaml::from_str(&yaml).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *op, "serde_yaml round-trip must preserve {op:?}");
        }
    }

    #[test]
    fn secret_operation_serde_json_round_trips_over_every_variant() {
        // Serde Serialize → Deserialize identity round-trip over
        // every variant through serde_json.
        for op in SecretOperation::ALL {
            let json = serde_json::to_string(op).expect("Serialize must succeed");
            let parsed: SecretOperation =
                serde_json::from_str(&json).expect("Deserialize must accept Serialize output");
            assert_eq!(parsed, *op, "serde_json round-trip must preserve {op:?}");
        }
    }

    #[test]
    fn secret_operation_serde_yaml_is_case_insensitive() {
        // Deserialize lowers through FromStr which lowers through
        // ClosedAxisLabel::from_canonical_str (eq_ignore_ascii_case),
        // so uppercase or mixed-case scalars parse pointwise.
        let cases: &[(&str, SecretOperation)] = &[
            ("GET", SecretOperation::Get),
            ("List", SecretOperation::List),
            ("pUt", SecretOperation::Put),
            ("DELETE", SecretOperation::Delete),
            ("Rotate", SecretOperation::Rotate),
            ("Get_Version", SecretOperation::GetVersion),
        ];
        for (input, expected) in cases {
            let parsed: SecretOperation =
                serde_yaml::from_str(input).expect("case-insensitive Deserialize must succeed");
            assert_eq!(
                parsed, *expected,
                "serde_yaml must parse case-insensitively for input {input:?}",
            );
        }
    }

    #[test]
    fn secret_operation_serde_yaml_unknown_operation_error_carries_label_verbatim() {
        // An unrecognized operation axis label surfaces at the serde
        // error site with the offending substring verbatim in the
        // rendered message, lifted through ShikumiError::Parse's
        // Display impl.
        for bad in &["metadata", "versions", "describe", "purge"] {
            let err = serde_yaml::from_str::<SecretOperation>(bad)
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
    fn secret_operation_serde_yaml_emission_is_bare_scalar() {
        // Concrete-position pin on the YAML emission shape: a
        // SecretOperation serializes as a bare snake_case scalar,
        // not as a quoted string or a tagged enum.
        let pairs: &[(SecretOperation, &str)] = &[
            (SecretOperation::Get, "get\n"),
            (SecretOperation::List, "list\n"),
            (SecretOperation::Put, "put\n"),
            (SecretOperation::Delete, "delete\n"),
            (SecretOperation::Rotate, "rotate\n"),
            (SecretOperation::GetVersion, "get_version\n"),
        ];
        for (op, expected) in pairs {
            let yaml = serde_yaml::to_string(op).unwrap();
            assert_eq!(yaml, *expected, "YAML emission mismatch for {op:?}");
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
    fn secret_error_kind_is_not_found_true_only_for_not_found_variant() {
        // Per-variant polarity pin on the NotFound corner. Sibling to
        // the trio-shape pins on ConfigSourceKind
        // (`config_source_kind_is_defaults_true_only_for_defaults_variant`)
        // and the binary-axis pins on the crate's Ord/partition
        // primitives; a future edit that flips the `matches!` arm on
        // `is_not_found` fails here before the equality-agreement pin
        // masks it.
        assert!(SecretErrorKind::NotFound.is_not_found());
        assert!(!SecretErrorKind::Unauthorized.is_not_found());
        assert!(!SecretErrorKind::Unsupported.is_not_found());
        assert!(!SecretErrorKind::Backend.is_not_found());
        assert!(!SecretErrorKind::Shikumi.is_not_found());
    }

    #[test]
    fn secret_error_kind_is_unauthorized_true_only_for_unauthorized_variant() {
        assert!(!SecretErrorKind::NotFound.is_unauthorized());
        assert!(SecretErrorKind::Unauthorized.is_unauthorized());
        assert!(!SecretErrorKind::Unsupported.is_unauthorized());
        assert!(!SecretErrorKind::Backend.is_unauthorized());
        assert!(!SecretErrorKind::Shikumi.is_unauthorized());
    }

    #[test]
    fn secret_error_kind_is_unsupported_true_only_for_unsupported_variant() {
        assert!(!SecretErrorKind::NotFound.is_unsupported());
        assert!(!SecretErrorKind::Unauthorized.is_unsupported());
        assert!(SecretErrorKind::Unsupported.is_unsupported());
        assert!(!SecretErrorKind::Backend.is_unsupported());
        assert!(!SecretErrorKind::Shikumi.is_unsupported());
    }

    #[test]
    fn secret_error_kind_is_backend_true_only_for_backend_variant() {
        assert!(!SecretErrorKind::NotFound.is_backend());
        assert!(!SecretErrorKind::Unauthorized.is_backend());
        assert!(!SecretErrorKind::Unsupported.is_backend());
        assert!(SecretErrorKind::Backend.is_backend());
        assert!(!SecretErrorKind::Shikumi.is_backend());
    }

    #[test]
    fn secret_error_kind_is_shikumi_true_only_for_shikumi_variant() {
        assert!(!SecretErrorKind::NotFound.is_shikumi());
        assert!(!SecretErrorKind::Unauthorized.is_shikumi());
        assert!(!SecretErrorKind::Unsupported.is_shikumi());
        assert!(!SecretErrorKind::Backend.is_shikumi());
        assert!(SecretErrorKind::Shikumi.is_shikumi());
    }

    #[test]
    fn secret_error_kind_predicates_are_a_closed_quintet_partition() {
        // Every SecretErrorKind::ALL cell satisfies exactly one of the
        // five sibling predicates: none satisfies two, none satisfies
        // zero. Quintet analogue of the ternary-partition pin on
        // `config_source_kind_predicates_are_a_closed_ternary_partition`
        // and the binary-partition pins on the crate's Ord/partition
        // axes (`partition_face_predicates_are_a_closed_binary_partition`,
        // `secret_ref_shape_predicates_are_a_closed_binary_partition`).
        // A future variant landing on SecretErrorKind without its own
        // sibling predicate collapses the partition to "zero" on that
        // cell, failing here before drifting through any consumer site.
        for k in SecretErrorKind::ALL.iter().copied() {
            let hits = usize::from(k.is_not_found())
                + usize::from(k.is_unauthorized())
                + usize::from(k.is_unsupported())
                + usize::from(k.is_backend())
                + usize::from(k.is_shikumi());
            assert_eq!(
                hits, 1,
                "SecretErrorKind::{k:?} must satisfy exactly one of \
                 is_not_found/is_unauthorized/is_unsupported/is_backend/is_shikumi \
                 (satisfied {hits})",
            );
        }
    }

    #[test]
    fn secret_error_kind_predicates_agree_with_equality_pointwise() {
        // Kind-side predicates agree with the closed-equality check
        // against their own variant, over the whole ALL slice. Dual
        // to the closed-quintet-partition pin above: the partition pin
        // catches a new variant landing without its own predicate;
        // this pin catches the dual case where a predicate's arm
        // silently accepts a second variant (a future edit changing
        // `matches!(self, Self::NotFound)` to
        // `matches!(self, Self::NotFound | Self::Unauthorized)`).
        for k in SecretErrorKind::ALL.iter().copied() {
            assert_eq!(k.is_not_found(), k == SecretErrorKind::NotFound);
            assert_eq!(k.is_unauthorized(), k == SecretErrorKind::Unauthorized);
            assert_eq!(k.is_unsupported(), k == SecretErrorKind::Unsupported);
            assert_eq!(k.is_backend(), k == SecretErrorKind::Backend);
            assert_eq!(k.is_shikumi(), k == SecretErrorKind::Shikumi);
        }
    }

    #[test]
    fn secret_error_kind_shikumi_predicate_agrees_with_as_shikumi_pointwise() {
        // Structural bridge: `err.kind().is_shikumi()` agrees with
        // `err.as_shikumi().is_some()` over the canonical construction
        // table, matching the pre-existing
        // `secret_error_as_shikumi_agrees_with_kind_pointwise` pin
        // through the new kind-side sibling predicate (rather than
        // through the closed-equality against SecretErrorKind::Shikumi).
        // Consumers can now phrase the check without spelling the
        // kind-axis equality at their own site.
        for (err, expected_kind) in one_per_secret_error_kind() {
            assert_eq!(
                err.as_shikumi().is_some(),
                err.kind().is_shikumi(),
                "as_shikumi().is_some() must agree with kind().is_shikumi() on {err:?}",
            );
            assert_eq!(err.kind().is_shikumi(), expected_kind.is_shikumi());
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

    // ── SecretError — tag-side quintet sibling predicates ────────────
    //
    // Peer of the ShikumiError tag-side septet (`error::tests` —
    // `shikumi_error_predicates_are_a_closed_septet_partition`,
    // `shikumi_error_predicates_agree_pointwise_with_shikumi_error_kind_predicates`,
    // and the seven `kind_agrees_with_is_*_pointwise` bridges). The
    // pre-existing pointwise-agreement suite pinned the kind() axis
    // alone; the tag-side siblings on `SecretError` now let observers
    // holding the borrowed error phrase per-variant classification
    // questions at the tag altitude, and this test cluster pins the
    // cross-altitude agreement.

    #[test]
    fn secret_error_is_not_found_agrees_with_kind_pointwise() {
        // Pointwise-agreement bridge on the NotFound arm. Peer of
        // `kind_agrees_with_is_not_found_pointwise` on the
        // ShikumiError tag-side septet: for every canonical
        // construction-table cell, `err.is_not_found()` agrees with
        // the closed-equality check against `SecretErrorKind::NotFound`.
        for (err, _) in one_per_secret_error_kind() {
            assert_eq!(
                err.is_not_found(),
                err.kind() == SecretErrorKind::NotFound,
                "is_not_found must agree with kind() for {err:?}",
            );
        }
    }

    #[test]
    fn secret_error_is_unauthorized_agrees_with_kind_pointwise() {
        for (err, _) in one_per_secret_error_kind() {
            assert_eq!(
                err.is_unauthorized(),
                err.kind() == SecretErrorKind::Unauthorized,
                "is_unauthorized must agree with kind() for {err:?}",
            );
        }
    }

    #[test]
    fn secret_error_is_unsupported_agrees_with_kind_pointwise() {
        for (err, _) in one_per_secret_error_kind() {
            assert_eq!(
                err.is_unsupported(),
                err.kind() == SecretErrorKind::Unsupported,
                "is_unsupported must agree with kind() for {err:?}",
            );
        }
    }

    #[test]
    fn secret_error_is_backend_agrees_with_kind_pointwise() {
        for (err, _) in one_per_secret_error_kind() {
            assert_eq!(
                err.is_backend(),
                err.kind() == SecretErrorKind::Backend,
                "is_backend must agree with kind() for {err:?}",
            );
        }
    }

    #[test]
    fn secret_error_is_shikumi_agrees_with_kind_pointwise() {
        for (err, _) in one_per_secret_error_kind() {
            assert_eq!(
                err.is_shikumi(),
                err.kind() == SecretErrorKind::Shikumi,
                "is_shikumi must agree with kind() for {err:?}",
            );
        }
    }

    #[test]
    fn secret_error_predicates_are_a_closed_quintet_partition() {
        // Tag-side quintet-partition pin, sibling of the kind-side
        // `secret_error_kind_predicates_are_a_closed_quintet_partition`
        // one altitude up on the closed [`SecretErrorKind`] partition.
        // Every value in the canonical construction table satisfies
        // exactly one of the five tag-side sibling predicates: none
        // satisfies two, none satisfies zero. A future variant landing
        // on SecretError without its own tag-side sibling predicate
        // collapses the partition to "zero" on that constructed cell,
        // failing here before drifting through any consumer site (a
        // retry-policy dispatch reading the tag-side answer before
        // projecting through kind(), a structured-log field naming
        // the tag-side variant, a cross-thread failure-tag capture on
        // the borrowed error's owned payloads).
        for (err, _) in one_per_secret_error_kind() {
            let hits = usize::from(err.is_not_found())
                + usize::from(err.is_unauthorized())
                + usize::from(err.is_unsupported())
                + usize::from(err.is_backend())
                + usize::from(err.is_shikumi());
            assert_eq!(
                hits, 1,
                "{err:?} must satisfy exactly one of \
                 is_not_found/is_unauthorized/is_unsupported/is_backend/is_shikumi \
                 (satisfied {hits})",
            );
        }
    }

    #[test]
    fn secret_error_predicates_agree_pointwise_with_secret_error_kind_predicates() {
        // Structural bridge between the tag-side quintet and the
        // kind-side quintet: for every constructed error and every
        // sibling arm, `err.is_X() == err.kind().is_X()`. Peer of
        // `shikumi_error_predicates_agree_pointwise_with_shikumi_error_kind_predicates`
        // on the ShikumiError axis one crate module over. A future
        // rename or matches!-arm drift on either altitude fails here
        // before the two altitudes silently disagree on any consumer
        // site (a per-kind retry-policy dispatch reading the kind
        // side and a resolver reading the tag side must classify the
        // same error identically).
        for (err, _) in one_per_secret_error_kind() {
            let k = err.kind();
            assert_eq!(err.is_not_found(), k.is_not_found(), "not_found on {err:?}");
            assert_eq!(
                err.is_unauthorized(),
                k.is_unauthorized(),
                "unauthorized on {err:?}",
            );
            assert_eq!(
                err.is_unsupported(),
                k.is_unsupported(),
                "unsupported on {err:?}",
            );
            assert_eq!(err.is_backend(), k.is_backend(), "backend on {err:?}");
            assert_eq!(err.is_shikumi(), k.is_shikumi(), "shikumi on {err:?}");
        }
    }

    #[test]
    fn secret_error_is_shikumi_agrees_with_as_shikumi_pointwise() {
        // Structural bridge between the new tag-side convenience
        // `SecretError::is_shikumi` and the pre-existing
        // `SecretError::as_shikumi` partial projection:
        // `err.is_shikumi() == err.as_shikumi().is_some()` for every
        // constructed error. Extends the pre-existing
        // `secret_error_as_shikumi_agrees_with_kind_pointwise` pin
        // through the new tag-side sibling predicate rather than the
        // kind-equality against `SecretErrorKind::Shikumi`, letting
        // observers phrase the check without spelling the closed-
        // equality on the kind axis at their own site.
        for (err, _) in one_per_secret_error_kind() {
            assert_eq!(
                err.is_shikumi(),
                err.as_shikumi().is_some(),
                "is_shikumi must agree with as_shikumi().is_some() on {err:?}",
            );
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
    fn secret_client_kind_is_mem_true_only_for_mem_variant() {
        // Sibling of the per-variant polarity pins on
        // `secret_operation_is_get_true_only_for_get_variant`,
        // `secret_error_kind_is_not_found_true_only_for_not_found_variant`,
        // `secret_backend_kind_is_literal_true_only_for_literal_variant`.
        // A future edit that flips the `matches!` arm on `is_mem` to
        // accept a second variant fails here before drifting through
        // any per-client dispatch site.
        assert!(SecretClientKind::Mem.is_mem());
        assert!(!SecretClientKind::Command.is_mem());
        assert!(!SecretClientKind::Akeyless.is_mem());
        assert!(!SecretClientKind::AwsSecretsManager.is_mem());
        assert!(!SecretClientKind::OpConnect.is_mem());
        assert!(!SecretClientKind::Vault.is_mem());
        assert!(!SecretClientKind::GcpSecretManager.is_mem());
    }

    #[test]
    fn secret_client_kind_is_command_true_only_for_command_variant() {
        assert!(!SecretClientKind::Mem.is_command());
        assert!(SecretClientKind::Command.is_command());
        assert!(!SecretClientKind::Akeyless.is_command());
        assert!(!SecretClientKind::AwsSecretsManager.is_command());
        assert!(!SecretClientKind::OpConnect.is_command());
        assert!(!SecretClientKind::Vault.is_command());
        assert!(!SecretClientKind::GcpSecretManager.is_command());
    }

    #[test]
    fn secret_client_kind_is_akeyless_true_only_for_akeyless_variant() {
        assert!(!SecretClientKind::Mem.is_akeyless());
        assert!(!SecretClientKind::Command.is_akeyless());
        assert!(SecretClientKind::Akeyless.is_akeyless());
        assert!(!SecretClientKind::AwsSecretsManager.is_akeyless());
        assert!(!SecretClientKind::OpConnect.is_akeyless());
        assert!(!SecretClientKind::Vault.is_akeyless());
        assert!(!SecretClientKind::GcpSecretManager.is_akeyless());
    }

    #[test]
    fn secret_client_kind_is_aws_secrets_manager_true_only_for_aws_secrets_manager_variant() {
        assert!(!SecretClientKind::Mem.is_aws_secrets_manager());
        assert!(!SecretClientKind::Command.is_aws_secrets_manager());
        assert!(!SecretClientKind::Akeyless.is_aws_secrets_manager());
        assert!(SecretClientKind::AwsSecretsManager.is_aws_secrets_manager());
        assert!(!SecretClientKind::OpConnect.is_aws_secrets_manager());
        assert!(!SecretClientKind::Vault.is_aws_secrets_manager());
        assert!(!SecretClientKind::GcpSecretManager.is_aws_secrets_manager());
    }

    #[test]
    fn secret_client_kind_is_op_connect_true_only_for_op_connect_variant() {
        assert!(!SecretClientKind::Mem.is_op_connect());
        assert!(!SecretClientKind::Command.is_op_connect());
        assert!(!SecretClientKind::Akeyless.is_op_connect());
        assert!(!SecretClientKind::AwsSecretsManager.is_op_connect());
        assert!(SecretClientKind::OpConnect.is_op_connect());
        assert!(!SecretClientKind::Vault.is_op_connect());
        assert!(!SecretClientKind::GcpSecretManager.is_op_connect());
    }

    #[test]
    fn secret_client_kind_is_vault_true_only_for_vault_variant() {
        assert!(!SecretClientKind::Mem.is_vault());
        assert!(!SecretClientKind::Command.is_vault());
        assert!(!SecretClientKind::Akeyless.is_vault());
        assert!(!SecretClientKind::AwsSecretsManager.is_vault());
        assert!(!SecretClientKind::OpConnect.is_vault());
        assert!(SecretClientKind::Vault.is_vault());
        assert!(!SecretClientKind::GcpSecretManager.is_vault());
    }

    #[test]
    fn secret_client_kind_is_gcp_secret_manager_true_only_for_gcp_secret_manager_variant() {
        assert!(!SecretClientKind::Mem.is_gcp_secret_manager());
        assert!(!SecretClientKind::Command.is_gcp_secret_manager());
        assert!(!SecretClientKind::Akeyless.is_gcp_secret_manager());
        assert!(!SecretClientKind::AwsSecretsManager.is_gcp_secret_manager());
        assert!(!SecretClientKind::OpConnect.is_gcp_secret_manager());
        assert!(!SecretClientKind::Vault.is_gcp_secret_manager());
        assert!(SecretClientKind::GcpSecretManager.is_gcp_secret_manager());
    }

    #[test]
    fn secret_client_kind_predicates_are_a_closed_septet_partition() {
        // Every SecretClientKind::ALL cell satisfies exactly one of
        // the seven sibling predicates: none satisfies two, none
        // satisfies zero. Septet analogue of the sextet-partition
        // pin on `secret_operation_predicates_are_a_closed_sextet_partition`,
        // the octuple-partition pin on
        // `secret_backend_kind_predicates_are_a_closed_octuple_partition`,
        // and the quintet-partition pin on
        // `secret_error_kind_predicates_are_a_closed_quintet_partition`.
        // A future eighth `SecretClientKind` variant landing without
        // its own sibling predicate collapses the partition to zero
        // on that cell, failing here before drifting through any
        // per-client dispatch site.
        for k in SecretClientKind::ALL.iter().copied() {
            let hits = usize::from(k.is_mem())
                + usize::from(k.is_command())
                + usize::from(k.is_akeyless())
                + usize::from(k.is_aws_secrets_manager())
                + usize::from(k.is_op_connect())
                + usize::from(k.is_vault())
                + usize::from(k.is_gcp_secret_manager());
            assert_eq!(
                hits, 1,
                "SecretClientKind::{k:?} must satisfy exactly one of \
                 is_mem/is_command/is_akeyless/is_aws_secrets_manager/\
                 is_op_connect/is_vault/is_gcp_secret_manager \
                 (satisfied {hits})",
            );
        }
    }

    #[test]
    fn secret_client_kind_predicates_agree_with_equality_pointwise() {
        // Sibling predicates agree with the closed-equality check
        // against their own variant, over the whole ALL slice. Dual
        // to the closed-septet-partition pin above: the partition
        // pin catches a new variant landing without its own
        // predicate; this pin catches the dual case where a
        // predicate's arm silently accepts a second variant (a
        // future edit changing `matches!(self, Self::Mem)` to
        // `matches!(self, Self::Mem | Self::Command)`).
        for k in SecretClientKind::ALL.iter().copied() {
            assert_eq!(k.is_mem(), k == SecretClientKind::Mem);
            assert_eq!(k.is_command(), k == SecretClientKind::Command);
            assert_eq!(k.is_akeyless(), k == SecretClientKind::Akeyless);
            assert_eq!(
                k.is_aws_secrets_manager(),
                k == SecretClientKind::AwsSecretsManager,
            );
            assert_eq!(k.is_op_connect(), k == SecretClientKind::OpConnect);
            assert_eq!(k.is_vault(), k == SecretClientKind::Vault);
            assert_eq!(
                k.is_gcp_secret_manager(),
                k == SecretClientKind::GcpSecretManager,
            );
        }
    }

    #[test]
    fn secret_client_kind_is_cloud_secret_manager_partitions_cloud_from_non_cloud() {
        // Concrete-position polarity pin at the runtime-client altitude
        // for the compound-polarity cloud-Secret-Manager sibling:
        // exactly {AwsSecretsManager, GcpSecretManager} satisfy
        // is_cloud_secret_manager, and the other five kinds do not.
        // Peer of
        // `secret_backend_kind_is_cloud_secret_manager_partitions_cloud_from_non_cloud`
        // (commit `3553207`) on the config-author backend axis — same
        // compound-polarity discipline, scaled to a 2-of-7 pole on the
        // runtime-client axis.
        for &kind in SecretClientKind::ALL {
            let expected = matches!(
                kind,
                SecretClientKind::AwsSecretsManager | SecretClientKind::GcpSecretManager,
            );
            assert_eq!(
                kind.is_cloud_secret_manager(),
                expected,
                "is_cloud_secret_manager returned {} on {kind:?} (expected {expected})",
                kind.is_cloud_secret_manager(),
            );
        }
    }

    #[test]
    fn secret_client_kind_is_cloud_secret_manager_agrees_with_or_of_individual_siblings() {
        // Compound-polarity ↔ two-arm disjunction pointwise law:
        // `kind.is_cloud_secret_manager() ==
        //     (kind.is_aws_secrets_manager() || kind.is_gcp_secret_manager())`
        // for every kind in ALL. Locks the (compound = disjunction)
        // invariant so any future edit that peeked past the two
        // AWS / GCP arms (widening the compound to accept Vault or
        // OpConnect, or adding a third cloud arm without extending
        // the two individual siblings in lockstep) diverges here
        // before drifting through the partition-integrity pins on
        // either side. Peer of
        // `secret_backend_kind_is_cloud_secret_manager_agrees_with_or_of_individual_siblings`
        // one altitude down.
        for &kind in SecretClientKind::ALL {
            assert_eq!(
                kind.is_cloud_secret_manager(),
                kind.is_aws_secrets_manager() || kind.is_gcp_secret_manager(),
                "compound-polarity ↔ (is_aws_secrets_manager || is_gcp_secret_manager) drift on {kind:?}",
            );
        }
    }

    #[test]
    fn secret_client_kind_is_cloud_secret_manager_is_const_callable() {
        // Compile-time weld between the const-fn constructors on
        // `SecretClientKind::ALL` and the const-fn
        // `is_cloud_secret_manager` predicate: a direct `const`
        // binding fires on the two cloud-Secret-Manager cells and
        // only those. Matches the same const-callability weld the
        // peer compound-polarity siblings
        // `SecretBackendKind::is_cloud_secret_manager` (commit
        // `3553207`) and `SecretSource::is_cloud_secret_manager`
        // (commit `dc2ee39`) carry at their altitudes — no
        // `static` workaround needed here because
        // `SecretClientKind` is `Copy` and admits a direct `const`
        // binding.
        const MEM_IS_CLOUD: bool = SecretClientKind::Mem.is_cloud_secret_manager();
        const COMMAND_IS_CLOUD: bool = SecretClientKind::Command.is_cloud_secret_manager();
        const AKEYLESS_IS_CLOUD: bool = SecretClientKind::Akeyless.is_cloud_secret_manager();
        const AWS_IS_CLOUD: bool = SecretClientKind::AwsSecretsManager.is_cloud_secret_manager();
        const OP_CONNECT_IS_CLOUD: bool = SecretClientKind::OpConnect.is_cloud_secret_manager();
        const VAULT_IS_CLOUD: bool = SecretClientKind::Vault.is_cloud_secret_manager();
        const GCP_IS_CLOUD: bool = SecretClientKind::GcpSecretManager.is_cloud_secret_manager();
        assert!(!MEM_IS_CLOUD);
        assert!(!COMMAND_IS_CLOUD);
        assert!(!AKEYLESS_IS_CLOUD);
        assert!(AWS_IS_CLOUD);
        assert!(!OP_CONNECT_IS_CLOUD);
        assert!(!VAULT_IS_CLOUD);
        assert!(GCP_IS_CLOUD);
    }

    #[test]
    fn secret_client_kind_is_cloud_secret_manager_agrees_with_secret_backend_kind_pointwise_on_shared_arms()
     {
        // Cross-altitude two-cell partition weld: the runtime-client
        // altitude and the config-author backend-kind altitude both
        // group the SAME two upstream vaults (AWS Secrets Manager,
        // GCP Secret Manager) under the compound pole, even though
        // their per-variant labels diverge by typescape design
        // (transport `"aws-secrets-manager"` / `"gcp-secret-manager"`
        // vs. YAML-key `"aws_secret"` / `"gcp_secret"`). The
        // agreement on the two shared arms:
        //
        //   client.is_cloud_secret_manager() ==
        //     backend.is_cloud_secret_manager()
        //
        // where (client, backend) is the natural pairing
        // (AwsSecretsManager, AwsSecret) and
        // (GcpSecretManager, GcpSecret). A future edit that
        // re-scoped the compound at either altitude without
        // extending the other (adding Akeyless to one side alone,
        // say) diverges here before drifting through any consumer
        // that reasons about the two altitudes as one pole.
        use crate::secret::SecretBackendKind;
        assert_eq!(
            SecretClientKind::AwsSecretsManager.is_cloud_secret_manager(),
            SecretBackendKind::AwsSecret.is_cloud_secret_manager(),
            "runtime-client / config-author cloud-Secret-Manager agreement drifted on the AWS arm",
        );
        assert_eq!(
            SecretClientKind::GcpSecretManager.is_cloud_secret_manager(),
            SecretBackendKind::GcpSecret.is_cloud_secret_manager(),
            "runtime-client / config-author cloud-Secret-Manager agreement drifted on the GCP arm",
        );
        // Both must be true — the pin above is not vacuous only
        // if the compound fires on both altitudes for both arms.
        assert!(SecretClientKind::AwsSecretsManager.is_cloud_secret_manager());
        assert!(SecretClientKind::GcpSecretManager.is_cloud_secret_manager());
    }

    #[test]
    fn secret_client_kind_is_non_cloud_secret_manager_partitions_non_cloud_from_cloud() {
        // Concrete-position polarity pin at the runtime-client
        // altitude for the compound-polarity complement sibling:
        // exactly {Mem, Command, Akeyless, OpConnect, Vault}
        // satisfy is_non_cloud_secret_manager, and the two cloud-
        // Secret-Manager kinds (AwsSecretsManager, GcpSecretManager)
        // do not. Mirror of the primary-pole partition pin
        // `secret_client_kind_is_cloud_secret_manager_partitions_cloud_from_non_cloud`
        // on the five-of-seven complement pole, closing the
        // compound-polarity sibling pair on the seven-way runtime-
        // client axis. Idiom-peer of the same complement-pole
        // partition pin
        // `secret_backend_kind_is_non_cloud_secret_manager_partitions_non_cloud_from_cloud`
        // (commit `5d7cd4c`) at the config-author-backend altitude.
        for &kind in SecretClientKind::ALL {
            let expected = matches!(
                kind,
                SecretClientKind::Mem
                    | SecretClientKind::Command
                    | SecretClientKind::Akeyless
                    | SecretClientKind::OpConnect
                    | SecretClientKind::Vault,
            );
            assert_eq!(
                kind.is_non_cloud_secret_manager(),
                expected,
                "is_non_cloud_secret_manager returned {} on {kind:?} (expected {expected})",
                kind.is_non_cloud_secret_manager(),
            );
        }
    }

    #[test]
    fn secret_client_kind_is_non_cloud_secret_manager_is_complement_of_is_cloud_secret_manager() {
        // Modal-pair complement law pointwise on every variant:
        // `kind.is_non_cloud_secret_manager() ==
        //     !kind.is_cloud_secret_manager()`
        // for every kind in ALL. Locks the two compound-polarity
        // siblings as a strict complement pair on the seven-way
        // partition — a future edit that widened either pole (e.g.
        // reclassifying Vault as a cloud Secret Manager, or adding
        // an eighth variant without extending both `match` arms in
        // lockstep) would collapse the equivalence here before
        // drifting through any per-polarity consumer site. Idiom-
        // peer of
        // `secret_backend_kind_is_non_cloud_secret_manager_is_complement_of_is_cloud_secret_manager`
        // (commit `5d7cd4c`) at the config-author-backend altitude.
        for &kind in SecretClientKind::ALL {
            assert_eq!(
                kind.is_non_cloud_secret_manager(),
                !kind.is_cloud_secret_manager(),
                "modal-pair complement law drift on {kind:?}",
            );
        }
    }

    #[test]
    fn secret_client_kind_is_non_cloud_secret_manager_agrees_with_or_of_individual_siblings() {
        // Compound-polarity ↔ five-arm disjunction pointwise law on
        // the runtime-client side:
        // `kind.is_non_cloud_secret_manager() ==
        //     (kind.is_mem() || kind.is_command() ||
        //      kind.is_akeyless() || kind.is_op_connect() ||
        //      kind.is_vault())`
        // for every kind in ALL. Locks the (compound = disjunction)
        // invariant against a future edit that peeked past the five
        // non-cloud arms (widening the compound to accept
        // AwsSecretsManager, or shrinking one of the five per-variant
        // arms without extending the `match` arms in lockstep).
        // Mirror of the primary-pole two-arm disjunction pin
        // `secret_client_kind_is_cloud_secret_manager_agrees_with_or_of_individual_siblings`
        // on the complement side.
        for &kind in SecretClientKind::ALL {
            assert_eq!(
                kind.is_non_cloud_secret_manager(),
                kind.is_mem()
                    || kind.is_command()
                    || kind.is_akeyless()
                    || kind.is_op_connect()
                    || kind.is_vault(),
                "compound-polarity ↔ (five-arm disjunction) drift on {kind:?}",
            );
        }
    }

    #[test]
    fn secret_client_kind_is_cloud_secret_manager_and_is_non_cloud_secret_manager_form_binary_partition()
     {
        // Compound-polarity binary partition law:
        // `u8::from(kind.is_cloud_secret_manager()) +
        //  u8::from(kind.is_non_cloud_secret_manager()) == 1`
        // for every kind in ALL. Exactly ONE of the two compound-
        // polarity siblings fires on every variant — neither both
        // (which would break disjointness: some cell would be
        // simultaneously cloud AND non-cloud) nor neither (which
        // would break jointness: some cell would be classified as
        // neither cloud nor non-cloud). A future edit that widened
        // both poles to fire on the same variant, or shrank both
        // poles to miss a variant, fails here before drifting
        // through any per-polarity consumer site. Cardinality
        // sub-pin: exactly 2 cells satisfy is_cloud_secret_manager
        // and exactly 5 satisfy is_non_cloud_secret_manager,
        // summing to `SecretClientKind::ALL.len() == 7` — the
        // partition covers the seven-way axis without overlap or
        // gap. Idiom-peer of
        // `secret_backend_kind_is_cloud_secret_manager_and_is_non_cloud_secret_manager_form_binary_partition`
        // (commit `5d7cd4c`) at the config-author-backend altitude.
        let mut cloud_count = 0usize;
        let mut non_cloud_count = 0usize;
        for &kind in SecretClientKind::ALL {
            let cloud = u8::from(kind.is_cloud_secret_manager());
            let non_cloud = u8::from(kind.is_non_cloud_secret_manager());
            assert_eq!(
                cloud + non_cloud,
                1,
                "compound-polarity siblings failed strict binary partition on {kind:?} \
                 (is_cloud={cloud}, is_non_cloud={non_cloud})",
            );
            cloud_count += cloud as usize;
            non_cloud_count += non_cloud as usize;
        }
        assert_eq!(
            cloud_count, 2,
            "expected exactly 2 cloud-Secret-Manager cells"
        );
        assert_eq!(
            non_cloud_count, 5,
            "expected exactly 5 non-cloud-Secret-Manager cells",
        );
        assert_eq!(
            cloud_count + non_cloud_count,
            SecretClientKind::ALL.len(),
            "compound-polarity partition failed to cover SecretClientKind::ALL",
        );
    }

    #[test]
    fn secret_client_kind_is_non_cloud_secret_manager_is_const_callable() {
        // Compile-time weld between the const-fn constructors on
        // `SecretClientKind::ALL` and the const-fn
        // `is_non_cloud_secret_manager` predicate: a direct `const`
        // binding fires on the five non-cloud cells and only those.
        // Mirror of the primary-pole const-callability pin
        // `secret_client_kind_is_cloud_secret_manager_is_const_callable`
        // on the complement side, keeping the whole compound-polarity
        // sibling pair const-callable end-to-end. Matches the same
        // const-callability weld the peer complement siblings
        // `SecretBackendKind::is_non_cloud_secret_manager` (commit
        // `5d7cd4c`), `SecretBackend::is_non_cloud_secret_manager`
        // (commit `9a76f5f`), and
        // `SecretSource::is_non_cloud_secret_manager` (commit
        // `658f0c7`) carry at their altitudes — no `static`
        // workaround needed here because `SecretClientKind` is
        // `Copy` and admits a direct `const` binding.
        const MEM_IS_NON_CLOUD: bool = SecretClientKind::Mem.is_non_cloud_secret_manager();
        const COMMAND_IS_NON_CLOUD: bool = SecretClientKind::Command.is_non_cloud_secret_manager();
        const AKEYLESS_IS_NON_CLOUD: bool =
            SecretClientKind::Akeyless.is_non_cloud_secret_manager();
        const AWS_IS_NON_CLOUD: bool =
            SecretClientKind::AwsSecretsManager.is_non_cloud_secret_manager();
        const OP_CONNECT_IS_NON_CLOUD: bool =
            SecretClientKind::OpConnect.is_non_cloud_secret_manager();
        const VAULT_IS_NON_CLOUD: bool = SecretClientKind::Vault.is_non_cloud_secret_manager();
        const GCP_IS_NON_CLOUD: bool =
            SecretClientKind::GcpSecretManager.is_non_cloud_secret_manager();
        assert!(MEM_IS_NON_CLOUD);
        assert!(COMMAND_IS_NON_CLOUD);
        assert!(AKEYLESS_IS_NON_CLOUD);
        assert!(!AWS_IS_NON_CLOUD);
        assert!(OP_CONNECT_IS_NON_CLOUD);
        assert!(VAULT_IS_NON_CLOUD);
        assert!(!GCP_IS_NON_CLOUD);
    }

    #[test]
    fn secret_client_kind_is_non_cloud_secret_manager_agrees_with_secret_backend_kind_pointwise_on_shared_arms()
     {
        // Cross-altitude complement-pole weld: the runtime-client
        // altitude and the config-author backend-kind altitude both
        // classify the SAME upstream backends under the non-cloud
        // complement pole through the natural pairings that share
        // a cross-altitude peer:
        //
        //   client.is_non_cloud_secret_manager() ==
        //     backend.is_non_cloud_secret_manager()
        //
        // for (Command, Command), (Akeyless, Akeyless),
        // (OpConnect, Op), and (Vault, Vault). A future edit that
        // re-scoped the complement at either altitude without
        // extending the other (moving Vault onto the cloud pole on
        // one side alone, say) diverges here before drifting
        // through any consumer that reasons about the two altitudes
        // as one pole. Complement-side mirror of
        // `secret_client_kind_is_cloud_secret_manager_agrees_with_secret_backend_kind_pointwise_on_shared_arms`
        // on the two hyperscaler arms.
        use crate::secret::SecretBackendKind;
        assert_eq!(
            SecretClientKind::Command.is_non_cloud_secret_manager(),
            SecretBackendKind::Command.is_non_cloud_secret_manager(),
            "runtime-client / config-author non-cloud agreement drifted on the Command arm",
        );
        assert_eq!(
            SecretClientKind::Akeyless.is_non_cloud_secret_manager(),
            SecretBackendKind::Akeyless.is_non_cloud_secret_manager(),
            "runtime-client / config-author non-cloud agreement drifted on the Akeyless arm",
        );
        assert_eq!(
            SecretClientKind::OpConnect.is_non_cloud_secret_manager(),
            SecretBackendKind::Op.is_non_cloud_secret_manager(),
            "runtime-client / config-author non-cloud agreement drifted on the Op / OpConnect arm",
        );
        assert_eq!(
            SecretClientKind::Vault.is_non_cloud_secret_manager(),
            SecretBackendKind::Vault.is_non_cloud_secret_manager(),
            "runtime-client / config-author non-cloud agreement drifted on the Vault arm",
        );
        // The pins above are not vacuous only if the complement
        // fires on both altitudes for all four shared arms.
        assert!(SecretClientKind::Command.is_non_cloud_secret_manager());
        assert!(SecretClientKind::Akeyless.is_non_cloud_secret_manager());
        assert!(SecretClientKind::OpConnect.is_non_cloud_secret_manager());
        assert!(SecretClientKind::Vault.is_non_cloud_secret_manager());
    }

    // ---- SecretClientKind CLOUD_SECRET_MANAGER / NON_CLOUD_SECRET_MANAGER
    //
    // The compound-polarity meta-partition of `SecretClientKind::ALL`
    // lifted from the boolean predicate altitude (`is_cloud_secret_manager`
    // / `is_non_cloud_secret_manager`) onto the static-slice altitude,
    // mirroring the same lift `SecretBackendKind::CLOUD_SECRET_MANAGER`
    // / `SecretBackendKind::NON_CLOUD_SECRET_MANAGER` shipped for the
    // eight-way config-author backend axis at commit `04e0f5d`. Six
    // pins below weld the six load-bearing invariants of the pair on
    // the seven-way runtime-client axis.

    #[test]
    fn secret_client_kind_cloud_secret_manager_slice_agrees_with_is_cloud_secret_manager_predicate()
    {
        // Cross-altitude weld: the slice's membership agrees with the
        // boolean predicate one altitude down. Every entry in
        // CLOUD_SECRET_MANAGER satisfies `is_cloud_secret_manager` (and,
        // by the meta-partition, none satisfies
        // `is_non_cloud_secret_manager`); every entry in
        // NON_CLOUD_SECRET_MANAGER satisfies `is_non_cloud_secret_manager`
        // (and none satisfies `is_cloud_secret_manager`). A future edit
        // that reclassified a variant across the polarity on one
        // declaration surface but not the other diverges here rather
        // than silently. Runtime-client-axis idiom-peer of
        // `secret_backend_kind_cloud_secret_manager_slice_agrees_with_is_cloud_secret_manager_predicate`
        // (commit `04e0f5d`) on the config-author backend axis.
        for kind in SecretClientKind::CLOUD_SECRET_MANAGER.iter().copied() {
            assert!(
                kind.is_cloud_secret_manager(),
                "SecretClientKind::CLOUD_SECRET_MANAGER entry {kind:?} must satisfy \
                 is_cloud_secret_manager",
            );
            assert!(
                !kind.is_non_cloud_secret_manager(),
                "SecretClientKind::CLOUD_SECRET_MANAGER entry {kind:?} must NOT satisfy \
                 is_non_cloud_secret_manager",
            );
        }
        for kind in SecretClientKind::NON_CLOUD_SECRET_MANAGER.iter().copied() {
            assert!(
                kind.is_non_cloud_secret_manager(),
                "SecretClientKind::NON_CLOUD_SECRET_MANAGER entry {kind:?} must satisfy \
                 is_non_cloud_secret_manager",
            );
            assert!(
                !kind.is_cloud_secret_manager(),
                "SecretClientKind::NON_CLOUD_SECRET_MANAGER entry {kind:?} must NOT satisfy \
                 is_cloud_secret_manager",
            );
        }
        // Dual direction: every variant outside CLOUD_SECRET_MANAGER
        // must fail is_cloud_secret_manager, and every variant outside
        // NON_CLOUD_SECRET_MANAGER must fail is_non_cloud_secret_manager
        // — swept over ALL. This catches the failure mode where a
        // cloud-Secret-Manager variant is silently dropped from
        // CLOUD_SECRET_MANAGER while still satisfying
        // `is_cloud_secret_manager` at the boolean altitude.
        for kind in SecretClientKind::ALL.iter().copied() {
            let in_cloud = SecretClientKind::CLOUD_SECRET_MANAGER
                .iter()
                .any(|c| *c == kind);
            let in_non_cloud = SecretClientKind::NON_CLOUD_SECRET_MANAGER
                .iter()
                .any(|n| *n == kind);
            assert_eq!(
                in_cloud,
                kind.is_cloud_secret_manager(),
                "CLOUD_SECRET_MANAGER membership must agree with is_cloud_secret_manager on \
                 {kind:?}",
            );
            assert_eq!(
                in_non_cloud,
                kind.is_non_cloud_secret_manager(),
                "NON_CLOUD_SECRET_MANAGER membership must agree with is_non_cloud_secret_manager \
                 on {kind:?}",
            );
        }
    }

    #[test]
    fn secret_client_kind_cloud_and_non_cloud_secret_manager_slices_partition_all() {
        // The two slices are DISJOINT (no variant appears in both),
        // their UNION is exactly ALL (no variant missing from both),
        // and their combined length equals `ALL.len()` (the
        // meta-partition covers the axis without overlap). This is the
        // slice-altitude analogue of the boolean-altitude pin
        // `secret_client_kind_is_cloud_secret_manager_and_is_non_cloud_secret_manager_form_binary_partition`.
        // A future eighth-pole runtime client landing in ALL without
        // being classified onto one of the two slices fails here.
        assert_eq!(
            SecretClientKind::CLOUD_SECRET_MANAGER.len()
                + SecretClientKind::NON_CLOUD_SECRET_MANAGER.len(),
            SecretClientKind::ALL.len(),
            "CLOUD_SECRET_MANAGER and NON_CLOUD_SECRET_MANAGER must together be the same size as \
             ALL",
        );
        for c in SecretClientKind::CLOUD_SECRET_MANAGER.iter().copied() {
            assert!(
                !SecretClientKind::NON_CLOUD_SECRET_MANAGER
                    .iter()
                    .any(|n| *n == c),
                "SecretClientKind::{c:?} must NOT appear in both CLOUD_SECRET_MANAGER and \
                 NON_CLOUD_SECRET_MANAGER",
            );
        }
        for kind in SecretClientKind::ALL.iter().copied() {
            let in_cloud = SecretClientKind::CLOUD_SECRET_MANAGER
                .iter()
                .any(|c| *c == kind);
            let in_non_cloud = SecretClientKind::NON_CLOUD_SECRET_MANAGER
                .iter()
                .any(|n| *n == kind);
            assert!(
                in_cloud || in_non_cloud,
                "SecretClientKind::{kind:?} in ALL must appear in CLOUD_SECRET_MANAGER or \
                 NON_CLOUD_SECRET_MANAGER",
            );
        }
    }

    #[test]
    fn secret_client_kind_cloud_and_non_cloud_secret_manager_slices_preserve_all_order() {
        // The declaration order within each per-half slice matches the
        // relative order of those variants in `SecretClientKind::ALL`
        // — a slice literal cannot silently reorder the meta-partition
        // (which would misalign per-half runtime-client histograms or
        // per-index dashboards keyed on the slice). Idiom analogue of
        // `secret_backend_kind_cloud_and_non_cloud_secret_manager_slices_preserve_all_order`
        // one axis over.
        let cloud_from_all: Vec<SecretClientKind> = SecretClientKind::ALL
            .iter()
            .copied()
            .filter(|k| k.is_cloud_secret_manager())
            .collect();
        let non_cloud_from_all: Vec<SecretClientKind> = SecretClientKind::ALL
            .iter()
            .copied()
            .filter(|k| k.is_non_cloud_secret_manager())
            .collect();
        assert_eq!(
            SecretClientKind::CLOUD_SECRET_MANAGER.to_vec(),
            cloud_from_all,
            "SecretClientKind::CLOUD_SECRET_MANAGER must match ALL's \
             is_cloud_secret_manager-order projection",
        );
        assert_eq!(
            SecretClientKind::NON_CLOUD_SECRET_MANAGER.to_vec(),
            non_cloud_from_all,
            "SecretClientKind::NON_CLOUD_SECRET_MANAGER must match ALL's \
             is_non_cloud_secret_manager-order projection",
        );
    }

    #[test]
    fn secret_client_kind_cloud_secret_manager_slice_has_no_duplicates() {
        // Same set-shape discipline as
        // `secret_client_kind_all_has_no_duplicates`. Sorting on the
        // canonical label decouples this pin from the slice's
        // declaration order (which is welded by the sibling
        // `secret_client_kind_cloud_and_non_cloud_secret_manager_slices_preserve_all_order`).
        let mut labels: Vec<&'static str> = SecretClientKind::CLOUD_SECRET_MANAGER
            .iter()
            .map(|k| k.as_str())
            .collect();
        let original_len = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            original_len,
            "SecretClientKind::CLOUD_SECRET_MANAGER must not list any variant twice",
        );
        // Non-cloud twin of the cloud-half no-duplicates pin.
        let mut labels: Vec<&'static str> = SecretClientKind::NON_CLOUD_SECRET_MANAGER
            .iter()
            .map(|k| k.as_str())
            .collect();
        let original_len = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            original_len,
            "SecretClientKind::NON_CLOUD_SECRET_MANAGER must not list any variant twice",
        );
    }

    #[test]
    fn secret_client_kind_cloud_and_non_cloud_secret_manager_slice_lengths_agree_with_boolean_pole_cardinalities()
     {
        // The slice lengths agree with the boolean-altitude pole
        // cardinalities: `CLOUD_SECRET_MANAGER.len()` equals the number
        // of ALL cells satisfying `is_cloud_secret_manager`, and the
        // same on the non-cloud half. Ties the slice altitude back to
        // the boolean altitude at the length scalar the whole
        // meta-partition is measured by (the same constants `2` and
        // `5` welded by the boolean-altitude partition pin
        // `secret_client_kind_is_cloud_secret_manager_and_is_non_cloud_secret_manager_form_binary_partition`).
        let cloud_boolean_count = SecretClientKind::ALL
            .iter()
            .copied()
            .filter(|k| k.is_cloud_secret_manager())
            .count();
        let non_cloud_boolean_count = SecretClientKind::ALL
            .iter()
            .copied()
            .filter(|k| k.is_non_cloud_secret_manager())
            .count();
        assert_eq!(
            SecretClientKind::CLOUD_SECRET_MANAGER.len(),
            cloud_boolean_count,
            "SecretClientKind::CLOUD_SECRET_MANAGER.len() must equal the \
             is_cloud_secret_manager filter count on ALL",
        );
        assert_eq!(
            SecretClientKind::NON_CLOUD_SECRET_MANAGER.len(),
            non_cloud_boolean_count,
            "SecretClientKind::NON_CLOUD_SECRET_MANAGER.len() must equal the \
             is_non_cloud_secret_manager filter count on ALL",
        );
    }

    #[test]
    fn secret_client_kind_cloud_and_non_cloud_secret_manager_slices_are_const_addressable() {
        // The two slice constants are addressable in const context —
        // a const-fn caller can index into them or take their `len()`
        // without going through a runtime iterator. Idiom-peer of the
        // sibling `secret_client_kind_is_cloud_secret_manager_is_const_callable`
        // pin at the boolean altitude. This weld pins that a
        // hypothetical future edit lifting `CLOUD_SECRET_MANAGER`
        // behind a `pub fn` (rather than `pub const`) — losing
        // const-time addressability — fails here.
        const CLOUD_LEN: usize = SecretClientKind::CLOUD_SECRET_MANAGER.len();
        const NON_CLOUD_LEN: usize = SecretClientKind::NON_CLOUD_SECRET_MANAGER.len();
        assert_eq!(CLOUD_LEN, 2);
        assert_eq!(NON_CLOUD_LEN, 5);
    }

    #[test]
    fn secret_client_kind_cloud_and_non_cloud_secret_manager_slices_agree_pointwise_with_backend_kind_shared_arms()
     {
        // Cross-altitude slice-side weld: the four runtime-client cells
        // that share an upstream vault with a config-author backend
        // (Command, Akeyless, OpConnect ↔ Op, Vault, plus the two
        // cloud-Secret-Manager cells) land on the SAME polarity slice
        // on both axes. This is the slice-altitude analogue of the
        // boolean-altitude pin
        // `secret_client_kind_is_cloud_secret_manager_agrees_with_secret_backend_kind_pointwise_on_shared_arms`
        // and its non-cloud sibling. A future edit that reclassified a
        // shared arm across the polarity on one axis's slice without
        // extending the other's diverges here before drifting through
        // any per-polarity consumer site that treats the two axes as
        // one pole.
        for (client_kind, backend_kind) in [
            (
                SecretClientKind::AwsSecretsManager,
                crate::secret::SecretBackendKind::AwsSecret,
            ),
            (
                SecretClientKind::GcpSecretManager,
                crate::secret::SecretBackendKind::GcpSecret,
            ),
            (
                SecretClientKind::Command,
                crate::secret::SecretBackendKind::Command,
            ),
            (
                SecretClientKind::Akeyless,
                crate::secret::SecretBackendKind::Akeyless,
            ),
            (
                SecretClientKind::OpConnect,
                crate::secret::SecretBackendKind::Op,
            ),
            (
                SecretClientKind::Vault,
                crate::secret::SecretBackendKind::Vault,
            ),
        ] {
            let client_in_cloud = SecretClientKind::CLOUD_SECRET_MANAGER
                .iter()
                .any(|c| *c == client_kind);
            let backend_in_cloud = crate::secret::SecretBackendKind::CLOUD_SECRET_MANAGER
                .iter()
                .any(|c| *c == backend_kind);
            assert_eq!(
                client_in_cloud, backend_in_cloud,
                "runtime-client / config-author CLOUD_SECRET_MANAGER membership drift on the \
                 shared arm ({client_kind:?}, {backend_kind:?})",
            );
            let client_in_non_cloud = SecretClientKind::NON_CLOUD_SECRET_MANAGER
                .iter()
                .any(|n| *n == client_kind);
            let backend_in_non_cloud = crate::secret::SecretBackendKind::NON_CLOUD_SECRET_MANAGER
                .iter()
                .any(|n| *n == backend_kind);
            assert_eq!(
                client_in_non_cloud, backend_in_non_cloud,
                "runtime-client / config-author NON_CLOUD_SECRET_MANAGER membership drift on the \
                 shared arm ({client_kind:?}, {backend_kind:?})",
            );
        }
    }

    // ---- SecretClientKind ONLY_MEM / ONLY_COMMAND / ONLY_AKEYLESS /
    // ONLY_AWS_SECRETS_MANAGER / ONLY_OP_CONNECT / ONLY_VAULT /
    // ONLY_GCP_SECRET_MANAGER identity meta-partition ──────────────────
    //
    // The identity 1/1/1/1/1/1/1 meta-partition of
    // `SecretClientKind::ALL` lifted from the boolean predicate altitude
    // (`is_mem` / `is_command` / … / `is_gcp_secret_manager`) onto the
    // static-slice altitude, mirroring the same lift shipped for the
    // eight-way config-author backend axis at commit `19364e3` on
    // `SecretBackendKind::ONLY_LITERAL` / … / `ONLY_GCP_SECRET`. Six
    // pins weld the load-bearing invariants of the septet on the
    // seven-way runtime-client axis; a seventh pin welds the identity
    // meta-partition to the shipped compound-polarity meta-partition
    // (CLOUD_SECRET_MANAGER / NON_CLOUD_SECRET_MANAGER) at the same
    // altitude on the same axis.

    #[test]
    fn secret_client_kind_identity_slices_agree_with_identity_predicates() {
        // Seven-way agreement pin across the (mem × command × akeyless
        // × aws_secrets_manager × op_connect × vault × gcp_secret_manager)
        // identity meta-partition. Every ONLY_MEM entry satisfies
        // is_mem and none of the six sibling predicates; every
        // ONLY_COMMAND entry satisfies is_command alone; … and so on
        // across all seven halves. Every SecretClientKind::ALL cell
        // agrees on membership under each of the seven boolean
        // predicates. The two independent declaration surfaces (slice
        // literals + boolean predicates) diverge at THIS pin on the
        // first shape where they disagree, before a consumer that
        // reads one altitude but not the other can observe the drift.
        // Septenary peer of
        // `secret_backend_kind_identity_slices_agree_with_identity_predicates`
        // (commit `19364e3`) on the config-author backend-kind axis,
        // one cell narrower.
        for k in SecretClientKind::ONLY_MEM.iter().copied() {
            assert!(k.is_mem(), "ONLY_MEM {k:?} must satisfy is_mem");
            assert!(
                !k.is_command(),
                "ONLY_MEM {k:?} must NOT satisfy is_command"
            );
            assert!(
                !k.is_akeyless(),
                "ONLY_MEM {k:?} must NOT satisfy is_akeyless"
            );
            assert!(
                !k.is_aws_secrets_manager(),
                "ONLY_MEM {k:?} must NOT satisfy is_aws_secrets_manager"
            );
            assert!(
                !k.is_op_connect(),
                "ONLY_MEM {k:?} must NOT satisfy is_op_connect"
            );
            assert!(!k.is_vault(), "ONLY_MEM {k:?} must NOT satisfy is_vault");
            assert!(
                !k.is_gcp_secret_manager(),
                "ONLY_MEM {k:?} must NOT satisfy is_gcp_secret_manager"
            );
        }
        for k in SecretClientKind::ONLY_COMMAND.iter().copied() {
            assert!(k.is_command(), "ONLY_COMMAND {k:?} must satisfy is_command");
            assert!(!k.is_mem(), "ONLY_COMMAND {k:?} must NOT satisfy is_mem");
            assert!(
                !k.is_akeyless(),
                "ONLY_COMMAND {k:?} must NOT satisfy is_akeyless"
            );
            assert!(
                !k.is_aws_secrets_manager(),
                "ONLY_COMMAND {k:?} must NOT satisfy is_aws_secrets_manager"
            );
            assert!(
                !k.is_op_connect(),
                "ONLY_COMMAND {k:?} must NOT satisfy is_op_connect"
            );
            assert!(
                !k.is_vault(),
                "ONLY_COMMAND {k:?} must NOT satisfy is_vault"
            );
            assert!(
                !k.is_gcp_secret_manager(),
                "ONLY_COMMAND {k:?} must NOT satisfy is_gcp_secret_manager"
            );
        }
        for k in SecretClientKind::ONLY_AKEYLESS.iter().copied() {
            assert!(
                k.is_akeyless(),
                "ONLY_AKEYLESS {k:?} must satisfy is_akeyless"
            );
            assert!(!k.is_mem(), "ONLY_AKEYLESS {k:?} must NOT satisfy is_mem");
            assert!(
                !k.is_command(),
                "ONLY_AKEYLESS {k:?} must NOT satisfy is_command"
            );
            assert!(
                !k.is_aws_secrets_manager(),
                "ONLY_AKEYLESS {k:?} must NOT satisfy is_aws_secrets_manager"
            );
            assert!(
                !k.is_op_connect(),
                "ONLY_AKEYLESS {k:?} must NOT satisfy is_op_connect"
            );
            assert!(
                !k.is_vault(),
                "ONLY_AKEYLESS {k:?} must NOT satisfy is_vault"
            );
            assert!(
                !k.is_gcp_secret_manager(),
                "ONLY_AKEYLESS {k:?} must NOT satisfy is_gcp_secret_manager"
            );
        }
        for k in SecretClientKind::ONLY_AWS_SECRETS_MANAGER.iter().copied() {
            assert!(
                k.is_aws_secrets_manager(),
                "ONLY_AWS_SECRETS_MANAGER {k:?} must satisfy is_aws_secrets_manager"
            );
            assert!(
                !k.is_mem(),
                "ONLY_AWS_SECRETS_MANAGER {k:?} must NOT satisfy is_mem"
            );
            assert!(
                !k.is_command(),
                "ONLY_AWS_SECRETS_MANAGER {k:?} must NOT satisfy is_command"
            );
            assert!(
                !k.is_akeyless(),
                "ONLY_AWS_SECRETS_MANAGER {k:?} must NOT satisfy is_akeyless"
            );
            assert!(
                !k.is_op_connect(),
                "ONLY_AWS_SECRETS_MANAGER {k:?} must NOT satisfy is_op_connect"
            );
            assert!(
                !k.is_vault(),
                "ONLY_AWS_SECRETS_MANAGER {k:?} must NOT satisfy is_vault"
            );
            assert!(
                !k.is_gcp_secret_manager(),
                "ONLY_AWS_SECRETS_MANAGER {k:?} must NOT satisfy is_gcp_secret_manager"
            );
        }
        for k in SecretClientKind::ONLY_OP_CONNECT.iter().copied() {
            assert!(
                k.is_op_connect(),
                "ONLY_OP_CONNECT {k:?} must satisfy is_op_connect"
            );
            assert!(!k.is_mem(), "ONLY_OP_CONNECT {k:?} must NOT satisfy is_mem");
            assert!(
                !k.is_command(),
                "ONLY_OP_CONNECT {k:?} must NOT satisfy is_command"
            );
            assert!(
                !k.is_akeyless(),
                "ONLY_OP_CONNECT {k:?} must NOT satisfy is_akeyless"
            );
            assert!(
                !k.is_aws_secrets_manager(),
                "ONLY_OP_CONNECT {k:?} must NOT satisfy is_aws_secrets_manager"
            );
            assert!(
                !k.is_vault(),
                "ONLY_OP_CONNECT {k:?} must NOT satisfy is_vault"
            );
            assert!(
                !k.is_gcp_secret_manager(),
                "ONLY_OP_CONNECT {k:?} must NOT satisfy is_gcp_secret_manager"
            );
        }
        for k in SecretClientKind::ONLY_VAULT.iter().copied() {
            assert!(k.is_vault(), "ONLY_VAULT {k:?} must satisfy is_vault");
            assert!(!k.is_mem(), "ONLY_VAULT {k:?} must NOT satisfy is_mem");
            assert!(
                !k.is_command(),
                "ONLY_VAULT {k:?} must NOT satisfy is_command"
            );
            assert!(
                !k.is_akeyless(),
                "ONLY_VAULT {k:?} must NOT satisfy is_akeyless"
            );
            assert!(
                !k.is_aws_secrets_manager(),
                "ONLY_VAULT {k:?} must NOT satisfy is_aws_secrets_manager"
            );
            assert!(
                !k.is_op_connect(),
                "ONLY_VAULT {k:?} must NOT satisfy is_op_connect"
            );
            assert!(
                !k.is_gcp_secret_manager(),
                "ONLY_VAULT {k:?} must NOT satisfy is_gcp_secret_manager"
            );
        }
        for k in SecretClientKind::ONLY_GCP_SECRET_MANAGER.iter().copied() {
            assert!(
                k.is_gcp_secret_manager(),
                "ONLY_GCP_SECRET_MANAGER {k:?} must satisfy is_gcp_secret_manager"
            );
            assert!(
                !k.is_mem(),
                "ONLY_GCP_SECRET_MANAGER {k:?} must NOT satisfy is_mem"
            );
            assert!(
                !k.is_command(),
                "ONLY_GCP_SECRET_MANAGER {k:?} must NOT satisfy is_command"
            );
            assert!(
                !k.is_akeyless(),
                "ONLY_GCP_SECRET_MANAGER {k:?} must NOT satisfy is_akeyless"
            );
            assert!(
                !k.is_aws_secrets_manager(),
                "ONLY_GCP_SECRET_MANAGER {k:?} must NOT satisfy is_aws_secrets_manager"
            );
            assert!(
                !k.is_op_connect(),
                "ONLY_GCP_SECRET_MANAGER {k:?} must NOT satisfy is_op_connect"
            );
            assert!(
                !k.is_vault(),
                "ONLY_GCP_SECRET_MANAGER {k:?} must NOT satisfy is_vault"
            );
        }
        for k in SecretClientKind::ALL.iter().copied() {
            assert_eq!(
                SecretClientKind::ONLY_MEM.contains(&k),
                k.is_mem(),
                "ONLY_MEM membership must agree with is_mem on {k:?}",
            );
            assert_eq!(
                SecretClientKind::ONLY_COMMAND.contains(&k),
                k.is_command(),
                "ONLY_COMMAND membership must agree with is_command on {k:?}",
            );
            assert_eq!(
                SecretClientKind::ONLY_AKEYLESS.contains(&k),
                k.is_akeyless(),
                "ONLY_AKEYLESS membership must agree with is_akeyless on {k:?}",
            );
            assert_eq!(
                SecretClientKind::ONLY_AWS_SECRETS_MANAGER.contains(&k),
                k.is_aws_secrets_manager(),
                "ONLY_AWS_SECRETS_MANAGER membership must agree with is_aws_secrets_manager \
                 on {k:?}",
            );
            assert_eq!(
                SecretClientKind::ONLY_OP_CONNECT.contains(&k),
                k.is_op_connect(),
                "ONLY_OP_CONNECT membership must agree with is_op_connect on {k:?}",
            );
            assert_eq!(
                SecretClientKind::ONLY_VAULT.contains(&k),
                k.is_vault(),
                "ONLY_VAULT membership must agree with is_vault on {k:?}",
            );
            assert_eq!(
                SecretClientKind::ONLY_GCP_SECRET_MANAGER.contains(&k),
                k.is_gcp_secret_manager(),
                "ONLY_GCP_SECRET_MANAGER membership must agree with is_gcp_secret_manager \
                 on {k:?}",
            );
        }
    }

    #[test]
    fn secret_client_kind_identity_slices_partition_all() {
        // Septenary partition invariant: the seven per-half slices are
        // pairwise-disjoint and their union covers ALL. Direct
        // application of the meta-partition sum law
        // `ONLY_MEM.len() + ONLY_COMMAND.len() + … +
        // ONLY_GCP_SECRET_MANAGER.len() == ALL.len()` at the slice
        // altitude on the seven-way runtime-client axis. Septenary peer
        // of `secret_backend_kind_identity_slices_partition_all` (commit
        // `19364e3`), one cell narrower. A variant landing on two
        // slices or on none breaks the partition here before any
        // consumer that reasons about the polarity as a covering
        // meta-partition observes the drift.
        let identity_slices: [&[SecretClientKind]; 7] = [
            SecretClientKind::ONLY_MEM,
            SecretClientKind::ONLY_COMMAND,
            SecretClientKind::ONLY_AKEYLESS,
            SecretClientKind::ONLY_AWS_SECRETS_MANAGER,
            SecretClientKind::ONLY_OP_CONNECT,
            SecretClientKind::ONLY_VAULT,
            SecretClientKind::ONLY_GCP_SECRET_MANAGER,
        ];
        for (i, left) in identity_slices.iter().enumerate() {
            for right in identity_slices.iter().skip(i + 1) {
                for k in left.iter() {
                    assert!(
                        !right.contains(k),
                        "SecretClientKind::{k:?} appears in more than one identity slice",
                    );
                }
            }
        }
        for k in SecretClientKind::ALL.iter().copied() {
            let held: usize = identity_slices
                .iter()
                .map(|s| usize::from(s.contains(&k)))
                .sum();
            assert_eq!(
                held, 1,
                "SecretClientKind::{k:?} must appear in exactly one identity \
                 slice (found in {held})",
            );
        }
        let sum: usize = identity_slices.iter().map(|s| s.len()).sum();
        assert_eq!(
            sum,
            SecretClientKind::ALL.len(),
            "identity slice lengths must sum to ALL.len()",
        );
    }

    #[test]
    fn secret_client_kind_identity_slices_preserve_all_order() {
        // Order-preservation pin: each per-half slice lists its
        // variants in the SAME relative declaration order they appear
        // in SecretClientKind::ALL — i.e., the slice equals
        // `ALL.iter().filter(polarity).collect()` pointwise. A future
        // edit that permuted any pole (impossible for singleton halves
        // today, but the shape catches a hypothetical multi-cell
        // future variant reshuffle on the same axis) diverges at
        // THIS pin. Septenary peer of
        // `secret_backend_kind_identity_slices_preserve_all_order`
        // (commit `19364e3`) on the config-author backend-kind axis.
        macro_rules! pin {
            ($slice:expr, $predicate:ident) => {{
                let from_all: Vec<SecretClientKind> = SecretClientKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.$predicate())
                    .collect();
                assert_eq!(
                    from_all,
                    $slice.to_vec(),
                    concat!(
                        stringify!($slice),
                        " must be ALL-filtered by ",
                        stringify!($predicate),
                        " in declaration order",
                    ),
                );
            }};
        }
        pin!(SecretClientKind::ONLY_MEM, is_mem);
        pin!(SecretClientKind::ONLY_COMMAND, is_command);
        pin!(SecretClientKind::ONLY_AKEYLESS, is_akeyless);
        pin!(
            SecretClientKind::ONLY_AWS_SECRETS_MANAGER,
            is_aws_secrets_manager
        );
        pin!(SecretClientKind::ONLY_OP_CONNECT, is_op_connect);
        pin!(SecretClientKind::ONLY_VAULT, is_vault);
        pin!(
            SecretClientKind::ONLY_GCP_SECRET_MANAGER,
            is_gcp_secret_manager
        );
    }

    #[test]
    fn secret_client_kind_identity_slices_have_no_duplicates() {
        // No-duplicates pin on all seven per-half slices — the slice
        // literals are declared as sets under the discriminant `Eq`
        // relation. A future edit that accidentally double-lists a
        // variant on one half fails at THIS pin before drifting
        // through any consumer that iterates the slice expecting a
        // set. Septenary peer of
        // `secret_backend_kind_identity_slices_have_no_duplicates`
        // (commit `19364e3`) on the config-author backend-kind axis.
        for slice in [
            SecretClientKind::ONLY_MEM,
            SecretClientKind::ONLY_COMMAND,
            SecretClientKind::ONLY_AKEYLESS,
            SecretClientKind::ONLY_AWS_SECRETS_MANAGER,
            SecretClientKind::ONLY_OP_CONNECT,
            SecretClientKind::ONLY_VAULT,
            SecretClientKind::ONLY_GCP_SECRET_MANAGER,
        ] {
            let mut seen: Vec<SecretClientKind> = Vec::with_capacity(slice.len());
            for k in slice {
                assert!(
                    !seen.contains(k),
                    "SecretClientKind identity slice {slice:?} contains \
                     duplicate entry {k:?}",
                );
                seen.push(*k);
            }
            assert_eq!(seen.len(), slice.len());
        }
    }

    #[test]
    fn secret_client_kind_identity_slice_lengths_agree_with_boolean_pole_cardinalities() {
        // Cardinality-agreement pin: the per-half slice lengths equal
        // the boolean-filter counts on SecretClientKind::ALL — i.e.,
        // `ONLY_MEM.len() == ALL.iter().filter(is_mem).count()` (and
        // symmetric for the six siblings) — the cardinality projection
        // at the slice altitude agrees with the boolean-altitude
        // projection on all seven halves. Concrete positions today:
        // 1 + 1 + 1 + 1 + 1 + 1 + 1 = 7 = ALL. Septenary peer of
        // `secret_backend_kind_identity_slice_lengths_agree_with_boolean_pole_cardinalities`
        // (commit `19364e3`) on the config-author backend-kind axis.
        let counts = [
            (
                "is_mem",
                SecretClientKind::ONLY_MEM.len(),
                SecretClientKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_mem())
                    .count(),
            ),
            (
                "is_command",
                SecretClientKind::ONLY_COMMAND.len(),
                SecretClientKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_command())
                    .count(),
            ),
            (
                "is_akeyless",
                SecretClientKind::ONLY_AKEYLESS.len(),
                SecretClientKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_akeyless())
                    .count(),
            ),
            (
                "is_aws_secrets_manager",
                SecretClientKind::ONLY_AWS_SECRETS_MANAGER.len(),
                SecretClientKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_aws_secrets_manager())
                    .count(),
            ),
            (
                "is_op_connect",
                SecretClientKind::ONLY_OP_CONNECT.len(),
                SecretClientKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_op_connect())
                    .count(),
            ),
            (
                "is_vault",
                SecretClientKind::ONLY_VAULT.len(),
                SecretClientKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_vault())
                    .count(),
            ),
            (
                "is_gcp_secret_manager",
                SecretClientKind::ONLY_GCP_SECRET_MANAGER.len(),
                SecretClientKind::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.is_gcp_secret_manager())
                    .count(),
            ),
        ];
        for (name, slice_len, boolean_count) in counts {
            assert_eq!(
                slice_len, boolean_count,
                "identity slice for {name} must match the {name} count on ALL",
            );
            assert_eq!(
                slice_len, 1,
                "identity slice for {name} must be a singleton",
            );
        }
        assert_eq!(SecretClientKind::ALL.len(), 7);
    }

    #[test]
    fn secret_client_kind_identity_slices_are_const_addressable() {
        // Const-time addressability pin: the seven per-half slices are
        // reachable at const evaluation position (a `const` binding of
        // `.len()`), so a future lift of any constant behind a `pub
        // fn` (which would drop const-callability) fails here before
        // drifting through a downstream `const`-context consumer.
        // Septenary peer of
        // `secret_backend_kind_identity_slices_are_const_addressable`
        // (commit `19364e3`) on the config-author backend-kind axis.
        const ONLY_MEM_LEN: usize = SecretClientKind::ONLY_MEM.len();
        const ONLY_COMMAND_LEN: usize = SecretClientKind::ONLY_COMMAND.len();
        const ONLY_AKEYLESS_LEN: usize = SecretClientKind::ONLY_AKEYLESS.len();
        const ONLY_AWS_SECRETS_MANAGER_LEN: usize =
            SecretClientKind::ONLY_AWS_SECRETS_MANAGER.len();
        const ONLY_OP_CONNECT_LEN: usize = SecretClientKind::ONLY_OP_CONNECT.len();
        const ONLY_VAULT_LEN: usize = SecretClientKind::ONLY_VAULT.len();
        const ONLY_GCP_SECRET_MANAGER_LEN: usize = SecretClientKind::ONLY_GCP_SECRET_MANAGER.len();
        const ALL_LEN: usize = SecretClientKind::ALL.len();
        assert_eq!(ONLY_MEM_LEN, 1);
        assert_eq!(ONLY_COMMAND_LEN, 1);
        assert_eq!(ONLY_AKEYLESS_LEN, 1);
        assert_eq!(ONLY_AWS_SECRETS_MANAGER_LEN, 1);
        assert_eq!(ONLY_OP_CONNECT_LEN, 1);
        assert_eq!(ONLY_VAULT_LEN, 1);
        assert_eq!(ONLY_GCP_SECRET_MANAGER_LEN, 1);
        assert_eq!(
            ONLY_MEM_LEN
                + ONLY_COMMAND_LEN
                + ONLY_AKEYLESS_LEN
                + ONLY_AWS_SECRETS_MANAGER_LEN
                + ONLY_OP_CONNECT_LEN
                + ONLY_VAULT_LEN
                + ONLY_GCP_SECRET_MANAGER_LEN,
            ALL_LEN,
        );
    }

    #[test]
    fn secret_client_kind_identity_slices_agree_with_compound_polarity_slices() {
        // Cross-altitude weld between the identity meta-partition
        // (ONLY_*) and the compound-polarity meta-partition
        // (CLOUD_SECRET_MANAGER / NON_CLOUD_SECRET_MANAGER) on the
        // same runtime-client axis. The union of the two identity
        // singletons in the cloud pole (ONLY_AWS_SECRETS_MANAGER +
        // ONLY_GCP_SECRET_MANAGER) equals CLOUD_SECRET_MANAGER as a
        // set, and the union of the five non-cloud identity singletons
        // equals NON_CLOUD_SECRET_MANAGER as a set. A future
        // rearrangement of one meta-partition without the other (say,
        // moving Vault into the cloud pole without adding it to the
        // identity → compound aggregation) diverges at THIS pin,
        // before drifting through a consumer that materializes one
        // altitude from the other. Septenary peer of
        // `secret_backend_kind_identity_slices_agree_with_compound_polarity_slices`
        // (commit `19364e3`) on the config-author backend-kind axis.
        let cloud_from_identity: Vec<SecretClientKind> = [
            SecretClientKind::ONLY_AWS_SECRETS_MANAGER,
            SecretClientKind::ONLY_GCP_SECRET_MANAGER,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            cloud_from_identity,
            SecretClientKind::CLOUD_SECRET_MANAGER.to_vec(),
            "identity singleton union on the cloud pole must reproduce \
             CLOUD_SECRET_MANAGER in declaration order",
        );
        let non_cloud_from_identity: Vec<SecretClientKind> = [
            SecretClientKind::ONLY_MEM,
            SecretClientKind::ONLY_COMMAND,
            SecretClientKind::ONLY_AKEYLESS,
            SecretClientKind::ONLY_OP_CONNECT,
            SecretClientKind::ONLY_VAULT,
        ]
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
        assert_eq!(
            non_cloud_from_identity,
            SecretClientKind::NON_CLOUD_SECRET_MANAGER.to_vec(),
            "identity singleton union on the non-cloud pole must reproduce \
             NON_CLOUD_SECRET_MANAGER in declaration order",
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
