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
            .find_map(|item| {
                item.get("id")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            })
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

        let fields = item.get("fields").and_then(|v| v.as_array()).ok_or_else(|| {
            SecretError::Backend(format!("op item {name} has no fields array"))
        })?;
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
                let url = format!(
                    "{}/v1/vaults/{}/items/{}",
                    self.base_url, self.vault_id, id
                );
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
        let url = format!(
            "{}/v1/vaults/{}/items/{}",
            self.base_url, self.vault_id, id
        );
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
// VaultClient — HashiCorp Vault KV v2 via thin reqwest HTTP
// ─────────────────────────────────────────────────────────────────────

/// Native HashiCorp Vault `SecretClient` — KV v2 engine.
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
            .apply_headers(self.http.request(reqwest::Method::from_bytes(b"LIST").unwrap(), &url))
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("vault list: {e}")))?;

        match response.status() {
            reqwest::StatusCode::NOT_FOUND => Ok(Vec::new()),
            s if !s.is_success() => Err(SecretError::Backend(format!(
                "vault list: HTTP {s}"
            ))),
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
        *self.token.write().expect("GcpSecretClient token lock poisoned") = token.into();
    }

    fn auth_header(&self) -> String {
        let guard = self.token.read().expect("GcpSecretClient token lock poisoned");
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
            s if !s.is_success() => Err(SecretError::Backend(format!(
                "gcp get({name}): HTTP {s}"
            ))),
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
                    if let Some(resource_name) =
                        secret.get("name").and_then(|v| v.as_str())
                    {
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
            .map_err(|e| {
                SecretError::Backend(format!("gcp get({name}, v={version}): {e}"))
            })?;
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
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
        assert_eq!(
            base64_decode("aGVsbG8gd29ybGQ=").unwrap(),
            b"hello world"
        );
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
}
