# RFC 0001 — Native vault SDKs via forge-gen + OpenAPI

**Status:** Draft
**Author:** Session of 2026-04-19, building on `shikumi::secret::{op, sops, akeyless, vault, aws_secret, gcp_secret}`
**Related:** `pleme-io/akeyless-api` (existing 604-endpoint generated SDK), `pleme-io/forge-gen` (unified codegen CLI)

## Summary

shikumi::secret currently shells out to the reference CLI for each
vault backend. This RFC proposes replacing the CLI fallbacks with
native HTTP clients auto-generated from each vendor's OpenAPI /
Swagger spec via forge-gen.

pleme-io already has the template: `akeyless-api` is a 604-endpoint
Rust SDK generated from Akeyless's OpenAPI spec. Apply the same pattern
to 1Password Connect, HashiCorp Vault, AWS Secrets Manager, and GCP
Secret Manager.

## Motivation

Shelling out to CLIs works but has real drawbacks that compound at
scale:

- **Process-spawn overhead.** `op read` cold-start is ~150 ms. Native
  HTTP is ~5 ms. A daemon pulling 30 secrets at startup pays 4.5 s vs
  150 ms — difference between "K8s readiness probe times out" and
  "pod Ready in time."
- **No connection pooling.** Every `sops -d <file>` + `jq` re-spawns
  two processes. Native HTTP client keeps one `reqwest::Client` for
  the lifetime of the daemon.
- **Error surface is unstructured.** Stderr strings instead of typed
  error variants; can't match on "auth expired" vs "secret not found."
- **MFA / biometric prompts** interfere with daemon-context runs
  (systemd, launchd, K8s pods). Native APIs with programmatic auth
  (service accounts, machine identity) sidestep this entirely.
- **Rotation.** Native clients can subscribe to webhook / watch
  endpoints and hot-reload secrets; CLI invocation is point-in-time.
- **Nix closure size.** Shelling out means the daemon's runtime image
  needs `op`, `sops`, `aws`, `gcloud`, `vault`, `akeyless` CLIs on
  PATH. That's hundreds of MiB; native clients are compiled into the
  binary.

CLIs remain a useful escape hatch (local dev, SOPS which is
fundamentally file-based, MFA-enforced policies). Keep `resolve_command`
and the per-backend CLI helpers; layer native clients alongside.

## Proposal

For each vault backend with a public OpenAPI / Swagger spec, generate
a Rust SDK crate via forge-gen, then add a feature-gated native
resolver alongside the CLI resolver.

### Generated SDKs

| Backend | OpenAPI source | Generated crate | Status |
|---|---|---|---|
| Akeyless | <https://api.akeyless.io/openapi.json> | `akeyless-api` | ✅ shipped (604 endpoints, 1334 types) |
| 1Password Connect | <https://developer.1password.com/docs/connect/connect-api-reference/> | `op-connect-api` | not yet |
| HashiCorp Vault | <https://developer.hashicorp.com/vault/api-docs> (OpenAPI endpoint: `GET /v1/sys/internal/specs/openapi`) | `vault-api` | not yet |
| AWS Secrets Manager | aws-sdk-rust / Smithy (not OpenAPI but has equivalent specs) | `aws-sdk-secretsmanager` on crates.io | use upstream |
| GCP Secret Manager | Google Discovery API: <https://secretmanager.googleapis.com/$discovery/rest> | `gcp-secretmanager-api` | not yet |

**AWS is special:** AWS's SDKs are generated from Smithy models, not
OpenAPI. The official `aws-sdk-secretsmanager` crate on crates.io is
what we want — no need to regenerate. shikumi would depend on it
behind a feature gate.

### shikumi::secret integration shape

Every backend gets three knobs:

```rust
// Existing (always available):
pub fn resolve_op(reference: &str) -> Result<String, ShikumiError>;
// Native (feature-gated):
#[cfg(feature = "op-native")]
pub async fn resolve_op_native(
    client: &OpConnectClient,
    reference: &str,
) -> Result<String, ShikumiError>;
// Unified (auto-picks native if feature enabled, CLI otherwise):
pub fn resolve_op_auto(reference: &str) -> Result<String, ShikumiError>;
```

`SecretSource` dispatch stays the same; only the implementation under
`resolve` changes based on what features are enabled.

### Feature flags

```toml
[features]
default = []
# Native HTTP clients — each enables a generated SDK dep
op-native       = ["dep:op-connect-api"]
vault-native    = ["dep:vault-api"]
aws-native      = ["dep:aws-sdk-secretsmanager", "dep:aws-config"]
gcp-native      = ["dep:gcp-secretmanager-api"]
akeyless-native = ["dep:akeyless-api"]
# Umbrella: all vault backends, native
native-all      = ["op-native", "vault-native", "aws-native", "gcp-native", "akeyless-native"]
# Lisp config support (existing)
lisp            = ["dep:tatara-lisp"]
```

Daemons opt into only the backends they need. A K8s-only deployment
might enable `vault-native` + `aws-native`; a developer laptop might
prefer the CLI fallbacks and leave features off.

### Auth plumbing

Each native client needs a tokenized auth path:

| Backend | Primary auth | Service-account auth |
|---|---|---|
| 1Password Connect | API token in `OP_CONNECT_TOKEN` | 1Password Service Account |
| Vault | `VAULT_TOKEN` env / approle login | Kubernetes auth method (pod identity) |
| AWS | Standard credential chain | IRSA / IMDSv2 |
| GCP | ADC | Workload Identity (GKE) |
| Akeyless | Auth method token | AWS/GCP/Azure IAM auth method |

shikumi would expose a `SecretClientConfig` struct that daemons
construct from env/config:

```rust
pub struct SecretClientConfig {
    pub op_connect:      Option<OpConnectConfig>,
    pub vault:           Option<VaultConfig>,
    pub aws:             Option<aws_config::SdkConfig>,
    pub gcp_project:     Option<String>,
    pub akeyless_token:  Option<String>,
}
```

`resolve(&source, &client_config)` becomes the native entry point;
the existing `resolve(&source)` stays for CLI-only callers.

## Non-goals

- Replacing the CLI resolvers. They remain the zero-auth, zero-config
  developer path. Enable native clients in production; keep CLIs for
  local dev and the SOPS case (which is file-based, not an API).
- Generating SOPS — SOPS is a file-crypto tool, not an HTTP service.
  The CLI resolver stays as-is.
- Building a vault abstraction layer in shikumi. shikumi::secret
  stays thin — it knows about backends by name; each backend has its
  native SDK as a crate.

## Migration path

1. **Stand up the three missing SDKs** via forge-gen:
   - `pleme-io/op-connect-api` — from 1Password's OpenAPI spec
   - `pleme-io/vault-api` — from a live Vault's `/v1/sys/internal/specs/openapi`
     endpoint or the community's
     [openapi-vault-spec](https://github.com/hashicorp/vault/tree/main/openapi)
   - `pleme-io/gcp-secretmanager-api` — from Google's Discovery document

2. **Add feature-gated native resolvers** in shikumi::secret:
   - `resolve_op_native`, `resolve_vault_native`, `resolve_aws_secret_native`,
     `resolve_gcp_secret_native`, `resolve_akeyless_native`.
   - Each returns `async fn` — shikumi gets a minimal tokio dep when
     any native feature is on.

3. **Unified `resolve_auto`** — picks native when feature is on,
   CLI otherwise. Keeps the public API stable.

4. **Migrate `akeyless` first** since `akeyless-api` already exists
   and proves the pattern. Measure p50/p99 latency delta.

5. **Document** the `native-*` feature flags in shikumi's CLAUDE.md
   and migration guide for downstream daemons.

## Open questions

1. **Auth plumbing**: should `SecretClientConfig` live in shikumi, or
   in a new `shikumi-clients` crate that handles all the vendor SDKs?
   Separate crate avoids pulling aws-sdk + gcp-api + vault-api into
   shikumi's dep graph for consumers that don't need any of them.

2. **Async contract**: shikumi's current resolve functions are sync
   (CLI-bound). Native clients are async. Do we expose `resolve_auto`
   as sync (blocking on a lightweight runtime) or async (push the
   choice to the caller)? Leaning async — modern daemons are already
   in tokio.

3. **Error taxonomy**: native SDKs have typed errors
   (`VaultError::PermissionDenied`, `AwsError::ResourceNotFoundException`,
   etc.). Should `ShikumiError` expose per-backend error variants, or
   flatten everything into `ShikumiError::Parse(String)`? Leaning
   structured — `ShikumiError::Vault(VaultError)` etc. so callers can
   match on auth failures for retry logic.

4. **Caching**: native clients make pooled HTTP cheap. Should shikumi
   optionally cache resolved secrets in-memory with a TTL? Useful for
   daemon hot paths that re-resolve the same secret per request (GraphQL
   resolvers, etc.). Risk: stale-secret window on rotation. Counter:
   add a `refresh_hint` trait method so secrets that got rotated push
   a cache bust.

5. **AWS Smithy vs OpenAPI**: aws-sdk-secretsmanager is already
   generated from Smithy by the AWS team. We don't regenerate — we
   depend. That breaks the forge-gen pattern for AWS. Either (a) ship
   a thin wrapper crate that re-exports aws-sdk-secretsmanager, or
   (b) let shikumi depend directly on aws-sdk-secretsmanager under
   the `aws-native` feature. Leaning (b) — less indirection.
