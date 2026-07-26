//! `KubeClusterDiscovery` — the ConfigPlane **DISCOVERED-tier** [`DiscoveryLayer`]
//! that resolves config from the *running* Kubernetes cluster.
//!
//! This is shikumi's slice of the ConfigPlane discovery reach
//! (`theory/CONFIGURATION-MANAGEMENT.md` §IX): a [`DiscoveryLayer`] whose
//! [`discover`][DiscoveryLayer::discover] reads the cluster around the pod —
//! its own namespace/name (downward API), whether a named `Service` resolves
//! (cluster DNS), and named `Secret` keys — and emits them as the partial
//! [`Dict`] the `discovered()` tier merges. It composes into a config exactly
//! like any other layer:
//!
//! ```ignore
//! fn discovered() -> Self {
//!     let env = kanchi::HostClusterEnv;             // or an injected reader
//!     let layer = KubeClusterDiscovery::new(&env)
//!         .namespace_key("pod_namespace")
//!         .service("db_host_name", ClusterServiceDns::new("mysql", "prod"), 3306)
//!         .secret("db_pwd", "db-credentials", "password");
//!     Self::discovered_from_layers(&[&layer])
//! }
//! ```
//!
//! **The seam is [`kanchi::ClusterEnv`].** The layer never talks to a cluster
//! directly — it reads through the trait, so the whole layer is exercised in
//! tests against [`kanchi::MockClusterEnv`] with no cluster and no network, and
//! a real deployment injects [`kanchi::HostClusterEnv`] (env + DNS for real,
//! Secret reads `None`) or the `kube`-feature [`KubeSecretReader`] (a real
//! in-cluster Secret client).
//!
//! **No-guess totality.** Every probe that does not resolve contributes
//! *nothing* — an undetectable namespace / unresolvable service / absent secret
//! is simply omitted, so an off-cluster layer emits an **empty** [`Dict`] and
//! the next config tier shows through. The DISCOVERED tier never fabricates a
//! value.
//!
//! **k8s-client-free by default.** The layer + its tests need only `kanchi`
//! (std-only) via the `kube-discovery` feature. The real Kubernetes API client
//! ([`KubeSecretReader`]) is gated behind the further `kube` feature — the one
//! arm that pulls an HTTP client.

use crate::discovered::DiscoveryLayer;
use figment::value::{Dict, Value};
use kanchi::{ClusterEnv, ClusterServiceDns};

/// One `Service`-DNS probe: emit `key = <fqdn>` iff [`dns`] resolves at [`port`].
struct ServiceProbe {
    key: String,
    dns: ClusterServiceDns,
    port: u16,
}

/// One `Secret`-key probe: emit `key = <secret[secret_key]>` iff present.
struct SecretProbe {
    key: String,
    secret: String,
    secret_key: String,
}

/// A [`DiscoveryLayer`] that maps cluster facts — read through a
/// [`kanchi::ClusterEnv`] seam — into config keys.
///
/// The layer holds a *plan* of what to emit under which config key; nothing is
/// read until [`DiscoveryLayer::discover`] runs, and only the facts that
/// resolve are emitted. The [`kanchi::ClusterEnv`] is borrowed (`&'a dyn`), so
/// a caller wires [`kanchi::HostClusterEnv`], [`kanchi::MockClusterEnv`], or a
/// `kube`-feature reader interchangeably.
pub struct KubeClusterDiscovery<'a> {
    env: &'a dyn ClusterEnv,
    namespace_key: Option<String>,
    pod_name_key: Option<String>,
    services: Vec<ServiceProbe>,
    secrets: Vec<SecretProbe>,
}

impl<'a> KubeClusterDiscovery<'a> {
    /// A new layer over the given cluster-env seam, with an empty plan (an
    /// empty plan emits an empty [`Dict`] — the clean degenerate).
    #[must_use]
    pub fn new(env: &'a dyn ClusterEnv) -> Self {
        Self {
            env,
            namespace_key: None,
            pod_name_key: None,
            services: Vec::new(),
            secrets: Vec::new(),
        }
    }

    /// Emit the pod's namespace ([`ClusterEnv::namespace`]) under `key`.
    #[must_use]
    pub fn namespace_key(mut self, key: impl Into<String>) -> Self {
        self.namespace_key = Some(key.into());
        self
    }

    /// Emit the pod's name ([`ClusterEnv::pod_name`]) under `key`.
    #[must_use]
    pub fn pod_name_key(mut self, key: impl Into<String>) -> Self {
        self.pod_name_key = Some(key.into());
        self
    }

    /// Emit `<dns>.fqdn()` under `key` iff the service resolves at `port`
    /// ([`ClusterEnv::resolve_service`]).
    #[must_use]
    pub fn service(mut self, key: impl Into<String>, dns: ClusterServiceDns, port: u16) -> Self {
        self.services.push(ServiceProbe {
            key: key.into(),
            dns,
            port,
        });
        self
    }

    /// Emit `secret[secret_key]` under `key` iff present
    /// ([`ClusterEnv::read_secret`]).
    #[must_use]
    pub fn secret(
        mut self,
        key: impl Into<String>,
        secret: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        self.secrets.push(SecretProbe {
            key: key.into(),
            secret: secret.into(),
            secret_key: secret_key.into(),
        });
        self
    }
}

impl DiscoveryLayer for KubeClusterDiscovery<'_> {
    fn name(&self) -> &'static str {
        "kube-cluster"
    }

    fn discover(&self) -> Dict {
        let mut d = Dict::new();

        // Downward-API facts.
        if let (Some(key), Some(ns)) = (self.namespace_key.as_ref(), self.env.namespace()) {
            d.insert(key.clone(), Value::from(ns));
        }
        if let (Some(key), Some(name)) = (self.pod_name_key.as_ref(), self.env.pod_name()) {
            d.insert(key.clone(), Value::from(name));
        }

        // Service DNS: a resolvable service contributes its FQDN; an
        // unresolvable one contributes nothing (never a guessed host).
        for probe in &self.services {
            if self.env.resolve_service(&probe.dns, probe.port).is_some() {
                d.insert(probe.key.clone(), Value::from(probe.dns.fqdn()));
            }
        }

        // Secret keys: a present key contributes its value; an absent one
        // contributes nothing.
        for probe in &self.secrets {
            if let Some(value) = self.env.read_secret(&probe.secret, &probe.secret_key) {
                d.insert(probe.key.clone(), Value::from(value));
            }
        }

        d
    }
}

// ── The real in-cluster Kubernetes Secret reader (kube feature) ──────────

/// A **real** in-cluster Kubernetes `Secret` reader behind the
/// [`kanchi::ClusterEnv`] seam: a thin `reqwest`-blocking GET against the
/// Secret API using the pod's service-account bearer token + the projected CA
/// cert, base64-decoding the requested key.
///
/// Delegates namespace / pod-name / service-DNS to [`kanchi::HostClusterEnv`]
/// (the std-only real answers) and adds only the one capability the leaf can't
/// provide: an authenticated Secret read.
///
/// **Tier-honest.** This type is compiled + type-checked, but is proven only
/// structurally and by [`kanchi::MockClusterEnv`] in the layer tests — there is
/// no live cluster in CI. A shadow-first live proof (read a real Secret, diff
/// against the hand-injected value, write nothing) is the ConfigPlane M0 gate.
#[cfg(feature = "kube")]
pub struct KubeSecretReader {
    host: kanchi::HostClusterEnv,
    client: reqwest::blocking::Client,
    api_base: String,
    token: String,
    namespace: String,
}

/// The `https://<host>:<port>` API base — a typed render surface so the URL is
/// never open-coded with `format!()`.
#[cfg(feature = "kube")]
struct ApiBase<'a> {
    host: &'a str,
    port: &'a str,
}

#[cfg(feature = "kube")]
impl std::fmt::Display for ApiBase<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "https://{}:{}", self.host, self.port)
    }
}

/// The `<base>/api/v1/namespaces/<ns>/secrets/<name>` Secret URL — a typed
/// render surface (no `format!()`).
#[cfg(feature = "kube")]
struct SecretUrl<'a> {
    base: &'a str,
    namespace: &'a str,
    name: &'a str,
}

#[cfg(feature = "kube")]
impl std::fmt::Display for SecretUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/api/v1/namespaces/{}/secrets/{}",
            self.base, self.namespace, self.name
        )
    }
}

#[cfg(feature = "kube")]
#[derive(serde::Deserialize)]
struct SecretResponse {
    #[serde(default)]
    data: std::collections::BTreeMap<String, String>,
}

#[cfg(feature = "kube")]
impl KubeSecretReader {
    const TOKEN_FILE: &'static str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    const CA_FILE: &'static str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

    /// Build a reader from the in-cluster service-account context
    /// (`KUBERNETES_SERVICE_HOST`/`_PORT`, the projected token + CA cert).
    /// [`None`] when any part is missing (not in a cluster) — never a guess.
    #[must_use]
    pub fn from_in_cluster() -> Option<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_owned());
        let token = std::fs::read_to_string(Self::TOKEN_FILE).ok()?;
        let ca_pem = std::fs::read(Self::CA_FILE).ok()?;
        let ca = reqwest::Certificate::from_pem(&ca_pem).ok()?;
        let client = reqwest::blocking::Client::builder()
            .add_root_certificate(ca)
            .build()
            .ok()?;
        let namespace = kanchi::pod_namespace().unwrap_or_else(|| "default".to_owned());
        let api_base = ApiBase {
            host: &host,
            port: &port,
        }
        .to_string();
        Some(Self {
            host: kanchi::HostClusterEnv,
            client,
            api_base,
            token: token.trim().to_owned(),
            namespace,
        })
    }

    /// Perform the authenticated GET + base64-decode. [`None`] on any transport
    /// / status / decode failure — a failed read is never a fabricated value.
    fn get_secret_key(&self, secret: &str, key: &str) -> Option<String> {
        use base64::Engine as _;

        let url = SecretUrl {
            base: &self.api_base,
            namespace: &self.namespace,
            name: secret,
        }
        .to_string();
        let resp = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .ok()?
            .error_for_status()
            .ok()?
            .json::<SecretResponse>()
            .ok()?;
        let encoded = resp.data.get(key)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        String::from_utf8(bytes).ok()
    }
}

#[cfg(feature = "kube")]
impl ClusterEnv for KubeSecretReader {
    fn namespace(&self) -> Option<String> {
        self.host.namespace()
    }

    fn pod_name(&self) -> Option<String> {
        self.host.pod_name()
    }

    fn resolve_service(
        &self,
        dns: &ClusterServiceDns,
        port: u16,
    ) -> Option<std::net::SocketAddr> {
        self.host.resolve_service(dns, port)
    }

    fn read_secret(&self, secret: &str, key: &str) -> Option<String> {
        self.get_secret_key(secret, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kanchi::MockClusterEnv;

    fn dns(svc: &str, ns: &str) -> ClusterServiceDns {
        ClusterServiceDns::new(svc, ns)
    }

    #[test]
    fn discovers_downward_api_service_dns_and_secrets_from_the_mock() {
        let db = dns("mysql", "prod");
        let env = MockClusterEnv::new()
            .with_namespace("prod")
            .with_pod_name("auth-0")
            .with_resolvable(&db)
            .with_secret("db-credentials", "password", "s3cr3t");

        let layer = KubeClusterDiscovery::new(&env)
            .namespace_key("pod_namespace")
            .pod_name_key("pod_name")
            .service("db_host_name", db.clone(), 3306)
            .secret("db_pwd", "db-credentials", "password");

        let d = layer.discover();
        assert_eq!(d.get("pod_namespace"), Some(&Value::from("prod")));
        assert_eq!(d.get("pod_name"), Some(&Value::from("auth-0")));
        assert_eq!(
            d.get("db_host_name"),
            Some(&Value::from("mysql.prod.svc.cluster.local")),
        );
        assert_eq!(d.get("db_pwd"), Some(&Value::from("s3cr3t")));
        assert_eq!(d.len(), 4);
    }

    #[test]
    fn unresolvable_service_and_absent_secret_contribute_nothing() {
        // The service is NOT registered resolvable and the secret is absent →
        // both are omitted, never guessed.
        let db = dns("mysql", "prod");
        let env = MockClusterEnv::new().with_namespace("prod");
        let layer = KubeClusterDiscovery::new(&env)
            .namespace_key("pod_namespace")
            .service("db_host_name", db, 3306)
            .secret("db_pwd", "db-credentials", "password");

        let d = layer.discover();
        assert_eq!(d.get("pod_namespace"), Some(&Value::from("prod")));
        assert!(d.get("db_host_name").is_none(), "unresolvable ⇒ omitted");
        assert!(d.get("db_pwd").is_none(), "absent secret ⇒ omitted");
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn off_cluster_env_yields_an_empty_dict() {
        // An empty mock (every answer None) is the off-cluster shape: the whole
        // layer contributes NOTHING — the clean degenerate, so the next config
        // tier shows through untouched.
        let env = MockClusterEnv::new();
        let layer = KubeClusterDiscovery::new(&env)
            .namespace_key("pod_namespace")
            .pod_name_key("pod_name")
            .service("db_host_name", dns("mysql", "prod"), 3306)
            .secret("db_pwd", "db-credentials", "password");

        assert!(layer.discover().is_empty(), "off-cluster ⇒ empty contribution");
    }

    #[test]
    fn empty_plan_emits_nothing_even_when_the_cluster_answers() {
        // No plan entries ⇒ nothing to emit, regardless of what the env knows.
        let env = MockClusterEnv::new()
            .with_namespace("prod")
            .with_secret("s", "k", "v");
        let layer = KubeClusterDiscovery::new(&env);
        assert!(layer.discover().is_empty());
    }

    #[test]
    fn layer_name_is_stable() {
        let env = MockClusterEnv::new();
        assert_eq!(KubeClusterDiscovery::new(&env).name(), "kube-cluster");
    }

    #[test]
    fn composes_through_discovered_from_layers_into_a_config() {
        use crate::TieredConfig;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
        struct SvcCfg {
            pod_namespace: String,
            db_host_name: String,
            metrics_port: u32,
        }
        impl TieredConfig for SvcCfg {
            fn bare() -> Self {
                Self::default()
            }
            fn prescribed_default() -> Self {
                Self::default()
            }
        }
        // We can't hold the layer inside discovered() (it borrows env), so this
        // test drives the same seam the trait's discovered() would use.
        let db = dns("mysql", "prod");
        let env = MockClusterEnv::new()
            .with_namespace("prod")
            .with_resolvable(&db);
        let layer = KubeClusterDiscovery::new(&env)
            .namespace_key("pod_namespace")
            .service("db_host_name", db, 3306);

        let cfg = SvcCfg::discovered_from_layers(&[&layer]);
        assert_eq!(cfg.pod_namespace, "prod");
        assert_eq!(cfg.db_host_name, "mysql.prod.svc.cluster.local");
        // metrics_port the layer never set stays at the bare floor.
        assert_eq!(cfg.metrics_port, 0);
    }
}
