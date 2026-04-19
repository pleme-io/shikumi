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
//! | 1Password Connect | planned | planned | planned | planned | ❌ | ❌ |
//! | HashiCorp Vault | planned | planned | planned | planned | ⚠️ (engine) | planned |
//! | GCP Secret Manager | planned | planned | planned | planned | ❌ | planned |
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
    Unsupported { backend: &'static str, operation: &'static str },

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
}

/// Which operations a [`SecretClient`] backend supports.
///
/// Queried via [`SecretClient::capabilities`]. Daemons that need
/// write-access can reject read-only clients at startup instead of
/// discovering the limitation at the first `put()` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Read operations always supported — every backend can `get`.
    pub get: bool,
    /// Enumerate secrets by prefix.
    pub list: bool,
    /// Create or update a secret.
    pub put: bool,
    /// Delete a secret.
    pub delete: bool,
    /// Trigger backend-side rotation.
    pub rotate: bool,
    /// Read historical versions.
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
        Err(SecretError::Unsupported {
            backend: self.backend_name(),
            operation: "list",
        })
    }

    /// Create or update a secret.
    async fn put(&self, _name: &str, _value: &str) -> Result<(), SecretError> {
        Err(SecretError::Unsupported {
            backend: self.backend_name(),
            operation: "put",
        })
    }

    /// Delete a secret.
    async fn delete(&self, _name: &str) -> Result<(), SecretError> {
        Err(SecretError::Unsupported {
            backend: self.backend_name(),
            operation: "delete",
        })
    }

    /// Trigger backend-side rotation (re-derives the value; details are
    /// backend-specific).
    async fn rotate(&self, _name: &str) -> Result<(), SecretError> {
        Err(SecretError::Unsupported {
            backend: self.backend_name(),
            operation: "rotate",
        })
    }

    /// Fetch a specific historical version of the secret.
    async fn get_version(
        &self,
        _name: &str,
        _version: &str,
    ) -> Result<String, SecretError> {
        Err(SecretError::Unsupported {
            backend: self.backend_name(),
            operation: "get_version",
        })
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
        let value = versions.last().cloned().ok_or_else(|| SecretError::NotFound {
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

    async fn get_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<String, SecretError> {
        let n: usize = version.parse().map_err(|_| {
            SecretError::Backend(format!(
                "mem version must be an integer, got {version:?}"
            ))
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
        versions
            .get(n - 1)
            .cloned()
            .ok_or_else(|| SecretError::Backend(format!(
                "mem has {} versions for {name}, version {n} out of range",
                versions.len()
            )))
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
            name_map: iter.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
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
        let update_result =
            akeyless_api::apis::v2_api::update_secret_val(&cfg, update).await;
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
                            SecretError::Backend(format!(
                                "akeyless create-secret({name}): {e}"
                            ))
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
            .map_err(|e| {
                SecretError::Backend(format!("akeyless rotate-secret({name}): {e}"))
            })?;
        Ok(())
    }

    async fn get_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<String, SecretError> {
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

        let value = response
            .secret_string()
            .map(str::to_owned)
            .ok_or_else(|| {
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
            metadata.tags.insert(
                "stages".into(),
                response.version_stages().join(","),
            );
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
            let resp = req.send().await.map_err(|e| {
                SecretError::Backend(format!("aws list-secrets: {e}"))
            })?;
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
                if err_str.contains("ResourceNotFoundException")
                    || err_str.contains("not found")
                {
                    self.client
                        .create_secret()
                        .name(name)
                        .secret_string(value)
                        .send()
                        .await
                        .map_err(|e| {
                            SecretError::Backend(format!(
                                "aws create-secret({name}): {e}"
                            ))
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

    async fn get_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<String, SecretError> {
        let response = self
            .client
            .get_secret_value()
            .secret_id(name)
            .version_id(version)
            .send()
            .await
            .map_err(|e| {
                SecretError::Backend(format!(
                    "aws get-secret-value({name}, v={version}): {e}"
                ))
            })?;
        response.secret_string().map(str::to_owned).ok_or_else(|| {
            SecretError::Backend(format!(
                "aws secret {name} v{version} has no SecretString"
            ))
        })
    }
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
        let client = MemClient::with_seed([
            ("prod/jwt", "1"),
            ("prod/api", "2"),
            ("dev/jwt", "3"),
        ]);
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
            Err(SecretError::Unsupported { operation: "put", .. })
        ));
        assert!(matches!(
            client.delete("k").await,
            Err(SecretError::Unsupported { operation: "delete", .. })
        ));
        assert!(matches!(
            client.list(None).await,
            Err(SecretError::Unsupported { operation: "list", .. })
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
        let err = SecretError::NotFound {
            name: "x".into(),
        };
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
}
