//! Tests for [`crate::github`]. Every case that touches the process
//! environment uses a variable name no other test uses, so the suite stays
//! correct under the default parallel test runner.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::*;

/// A throwaway RSA-2048 App keypair `(private PKCS#1 PEM, public PKCS#1 PEM)`,
/// generated once per test process. Generated rather than committed: a
/// private key in the tree is credential material to every scanner and
/// hook downstream, whatever its comment says.
fn test_keypair() -> &'static (String, String) {
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
    static PAIR: OnceLock<(String, String)> = OnceLock::new();
    PAIR.get_or_init(|| {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let private = key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string();
        let public = key.to_public_key().to_pkcs1_pem(LineEnding::LF).unwrap();
        (private, public)
    })
}

fn test_key_pem() -> &'static str {
    &test_keypair().0
}

/// 2027-01-01T00:00:00Z.
const NOW: u64 = 1_798_761_600;
const ONE_HOUR_LATER: &str = "2027-01-01T01:00:00Z";

fn env_source(var: &str) -> GithubAuth {
    GithubAuth::Token(SecretSource::Backend(SecretBackend::Env(var.to_owned())))
}

fn file_source(path: impl Into<PathBuf>) -> GithubAuth {
    GithubAuth::Token(SecretSource::Backend(SecretBackend::File(path.into())))
}

fn set_env(var: &str, value: &str) {
    // SAFETY: every test owns a distinct variable name, so no other thread
    // reads or writes this one concurrently.
    unsafe { std::env::set_var(var, value) };
}

// ── serde shape ───────────────────────────────────────────────────────

const CHAIN_YAML: &str = r"
github_auth:
  chain:
    - token: { env: TEND_GITHUB_TOKEN }
    - gh_cli: { host: github.com }
    - token: { file: ~/.config/github/token }
    - app: { app_id: 123, owner: pleme-io, private_key: { file: /run/secrets/app.pem } }
";

#[derive(Debug, Serialize, Deserialize)]
struct Wrapper {
    github_auth: GithubAuth,
}

#[test]
fn the_documented_yaml_parses_to_the_documented_chain() {
    let parsed: Wrapper = serde_yaml::from_str(CHAIN_YAML).unwrap();
    let GithubAuth::Chain(items) = &parsed.github_auth else {
        panic!("expected chain, got {:?}", parsed.github_auth);
    };
    assert_eq!(items.len(), 4);
    assert!(matches!(
        &items[0],
        GithubAuth::Token(SecretSource::Backend(SecretBackend::Env(v))) if v == "TEND_GITHUB_TOKEN"
    ));
    assert!(matches!(&items[1], GithubAuth::GhCli { host } if host == "github.com"));
    assert!(matches!(
        &items[2],
        GithubAuth::Token(SecretSource::Backend(SecretBackend::File(p)))
            if p == Path::new("~/.config/github/token")
    ));
    let GithubAuth::App(app) = &items[3] else {
        panic!("expected app, got {:?}", items[3]);
    };
    assert!(matches!(app.app_id, GithubId::Number(123)));
    assert_eq!(app.owner.as_deref(), Some("pleme-io"));
    assert!(app.installation_id.is_none());
    assert_eq!(app.api_url, DEFAULT_GITHUB_API_URL);
    assert_eq!(app.refresh_before_secs, DEFAULT_REFRESH_BEFORE_SECS);
    assert!(matches!(
        &app.private_key,
        SecretSource::Backend(SecretBackend::File(p)) if p == Path::new("/run/secrets/app.pem")
    ));
}

#[test]
fn the_documented_yaml_round_trips() {
    let parsed: Wrapper = serde_yaml::from_str(CHAIN_YAML).unwrap();
    let emitted = serde_yaml::to_string(&parsed).unwrap();
    let reparsed: Wrapper = serde_yaml::from_str(&emitted).unwrap();
    assert_eq!(
        serde_json::to_value(&parsed).unwrap(),
        serde_json::to_value(&reparsed).unwrap(),
        "YAML round-trip changed the value; emitted:\n{emitted}"
    );
}

#[test]
fn every_variant_serializes_externally_tagged_snake_case() {
    use serde_json::json;
    assert_eq!(
        serde_json::to_value(env_source("X")).unwrap(),
        json!({ "token": { "env": "X" } })
    );
    assert_eq!(
        serde_json::to_value(file_source("~/t")).unwrap(),
        json!({ "token": { "file": "~/t" } })
    );
    assert_eq!(
        serde_json::to_value(GithubAuth::GhCli {
            host: "ghe.example".into()
        })
        .unwrap(),
        json!({ "gh_cli": { "host": "ghe.example" } })
    );
    let app = GithubApp::new(7, SecretSource::Backend(SecretBackend::Env("PEM".into())))
        .with_installation_id(9);
    assert_eq!(
        serde_json::to_value(GithubAuth::App(app)).unwrap(),
        json!({ "app": {
            "app_id": 7,
            "private_key": { "env": "PEM" },
            "installation_id": 9,
            "api_url": DEFAULT_GITHUB_API_URL,
            "refresh_before_secs": DEFAULT_REFRESH_BEFORE_SECS,
        }})
    );
    assert_eq!(
        serde_json::to_value(GithubAuth::Chain(vec![])).unwrap(),
        json!({ "chain": [] })
    );
}

#[test]
fn gh_cli_host_defaults_to_github_com() {
    let auth: GithubAuth = serde_yaml::from_str("gh_cli: {}").unwrap();
    assert!(matches!(auth, GithubAuth::GhCli { host } if host == DEFAULT_GITHUB_HOST));
}

#[test]
fn app_ids_accept_a_secret_source() {
    let auth: GithubAuth = serde_yaml::from_str(
        "app: { app_id: { file: /run/secrets/app-id }, installation_id: { env: INST }, private_key: { env: PEM } }",
    )
    .unwrap();
    let GithubAuth::App(app) = auth else { panic!() };
    assert!(matches!(
        app.app_id,
        GithubId::Source(SecretSource::Backend(SecretBackend::File(_)))
    ));
    assert!(matches!(
        app.installation_id,
        Some(GithubId::Source(SecretSource::Backend(SecretBackend::Env(
            _
        ))))
    ));
}

#[test]
fn app_rejects_unknown_fields() {
    let err = serde_yaml::from_str::<GithubAuth>(
        "app: { app_id: 1, private_key: { env: PEM }, installation: 3 }",
    )
    .unwrap_err();
    assert!(err.to_string().contains("installation"), "{err}");
}

// ── schema ────────────────────────────────────────────────────────────

#[test]
fn json_schema_names_every_variant_and_field_with_descriptions() {
    let schema = schemars::schema_for!(GithubAuth).to_value();
    let text = serde_json::to_string(&schema).unwrap();
    for needle in [
        "\"token\"",
        "\"gh_cli\"",
        "\"app\"",
        "\"chain\"",
        "\"app_id\"",
        "\"private_key\"",
        "\"installation_id\"",
        "\"owner\"",
        "\"api_url\"",
        "\"refresh_before_secs\"",
        "\"env\"",
        "\"file\"",
        "\"sops\"",
    ] {
        assert!(text.contains(needle), "schema lacks {needle}: {text}");
    }
    // Doc comments become descriptions — the generated nix options and
    // Helm values schema read them.
    assert!(
        text.contains("first that yields a non-empty token wins"),
        "{text}"
    );
    assert!(text.contains("gh auth token --hostname"), "{text}");
    assert_eq!(
        schema["$defs"]["GithubApp"]["properties"]["api_url"]["default"],
        DEFAULT_GITHUB_API_URL
    );
    assert_eq!(
        schema["$defs"]["GithubApp"]["properties"]["refresh_before_secs"]["default"],
        DEFAULT_REFRESH_BEFORE_SECS
    );
    assert_eq!(
        schema["$defs"]["GithubApp"]["additionalProperties"],
        serde_json::Value::Bool(false)
    );
}

// ── chain semantics ───────────────────────────────────────────────────

#[test]
fn chain_falls_through_failed_sources_and_records_the_winner() {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "ghp_fromfile0123456789\n").unwrap();
    set_env("SHIKUMI_GH_TEST_FALLTHROUGH_EMPTY", "   ");

    let chain = GithubAuth::Chain(vec![
        env_source("SHIKUMI_GH_TEST_FALLTHROUGH_UNSET"),
        env_source("SHIKUMI_GH_TEST_FALLTHROUGH_EMPTY"),
        file_source(&token_file),
        env_source("SHIKUMI_GH_TEST_FALLTHROUGH_NEVER_REACHED"),
    ]);
    let token = GithubAuthResolver::new().resolve(&chain).unwrap();

    assert_eq!(token.expose_for_header(), "ghp_fromfile0123456789");
    let p = token.provenance();
    assert_eq!(p.chain_path, vec![2]);
    assert_eq!(p.kind, GithubAuthKind::Token);
    assert_eq!(p.secret_backend, Some(SecretBackendKind::File));
    assert!(p.description.contains(&token_file.display().to_string()));
    assert!(token.expires_at().is_none());
}

#[test]
fn chain_takes_the_first_source_in_order() {
    set_env("SHIKUMI_GH_TEST_ORDER_A", "ghp_first");
    set_env("SHIKUMI_GH_TEST_ORDER_B", "ghp_second");
    let resolver = GithubAuthResolver::new();
    let ab = GithubAuth::Chain(vec![
        env_source("SHIKUMI_GH_TEST_ORDER_A"),
        env_source("SHIKUMI_GH_TEST_ORDER_B"),
    ]);
    let ba = GithubAuth::Chain(vec![
        env_source("SHIKUMI_GH_TEST_ORDER_B"),
        env_source("SHIKUMI_GH_TEST_ORDER_A"),
    ]);
    assert_eq!(
        resolver.resolve(&ab).unwrap().expose_for_header(),
        "ghp_first"
    );
    assert_eq!(
        resolver.resolve(&ba).unwrap().expose_for_header(),
        "ghp_second"
    );
}

#[test]
fn nested_chains_record_the_full_index_path() {
    set_env("SHIKUMI_GH_TEST_NESTED", "ghp_nested");
    let chain = GithubAuth::Chain(vec![
        env_source("SHIKUMI_GH_TEST_NESTED_UNSET"),
        GithubAuth::Chain(vec![
            env_source("SHIKUMI_GH_TEST_NESTED_UNSET_2"),
            env_source("SHIKUMI_GH_TEST_NESTED"),
        ]),
    ]);
    let token = GithubAuthResolver::new().resolve(&chain).unwrap();
    assert_eq!(token.provenance().chain_path, vec![1, 1]);
    assert!(token.provenance().to_string().ends_with("(chain[1][1])"));
}

#[test]
fn an_exhausted_chain_names_every_source_and_why_it_failed() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent-token");
    let empty = dir.path().join("empty-token");
    std::fs::write(&empty, "\n").unwrap();
    set_env("SHIKUMI_GH_TEST_EXHAUST_EMPTY", "");

    let chain = GithubAuth::Chain(vec![
        env_source("SHIKUMI_GH_TEST_EXHAUST_UNSET"),
        env_source("SHIKUMI_GH_TEST_EXHAUST_EMPTY"),
        file_source(&missing),
        file_source(&empty),
        GithubAuth::GhCli {
            host: "github.com".into(),
        },
    ]);
    let resolver = GithubAuthResolver::new().with_gh_program(dir.path().join("no-such-gh-binary"));
    let err = resolver.resolve(&chain).unwrap_err();
    let GithubAuthError::Chain { failures } = &err else {
        panic!("expected Chain, got {err:?}");
    };
    assert_eq!(failures.len(), 5);
    assert_eq!(
        failures.iter().map(|f| f.index).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );

    let text = err.to_string();
    assert!(
        text.starts_with("no GitHub token from any of 5 sources:"),
        "{text}"
    );
    for needle in [
        "SHIKUMI_GH_TEST_EXHAUST_UNSET is not set",
        "SHIKUMI_GH_TEST_EXHAUST_EMPTY is set but empty",
        &format!("{} could not be read", missing.display()),
        &format!("{} is empty", empty.display()),
        "auth token --hostname github.com` failed: could not run",
    ] {
        assert!(
            text.contains(needle),
            "chain error lacks {needle:?}:\n{text}"
        );
    }
}

#[test]
fn an_empty_chain_says_so() {
    let err = GithubAuthResolver::new()
        .resolve(&GithubAuth::Chain(vec![]))
        .unwrap_err();
    assert_eq!(err.to_string(), "no GitHub token: the chain is empty");
}

#[test]
fn file_tokens_are_re_read_on_every_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    let auth = file_source(&path);
    let resolver = GithubAuthResolver::new();
    std::fs::write(&path, "ghp_before\n").unwrap();
    assert_eq!(
        resolver.resolve(&auth).unwrap().expose_for_header(),
        "ghp_before"
    );
    std::fs::write(&path, "ghp_rotated\n").unwrap();
    assert_eq!(
        resolver.resolve(&auth).unwrap().expose_for_header(),
        "ghp_rotated"
    );
}

#[test]
fn default_chain_is_the_fleet_order() {
    let GithubAuth::Chain(items) = GithubAuth::default_chain("my-tool") else {
        panic!()
    };
    let described: Vec<String> = items.iter().map(GithubAuth::describe).collect();
    assert_eq!(
        described,
        vec![
            "token from env MY_TOOL_GITHUB_TOKEN",
            "token from env GITHUB_TOKEN",
            "token from env GH_TOKEN",
            "gh auth token --hostname github.com",
            "token from file ~/.config/github/token",
        ]
    );
    let GithubAuth::Chain(no_prefix) = GithubAuth::default_chain("") else {
        panic!()
    };
    assert_eq!(no_prefix.len(), 4);
}

// ── gh CLI ────────────────────────────────────────────────────────────

/// Write an executable fake `gh` into `dir` that prints `token` for
/// `auth token --hostname github.com` and fails otherwise.
fn fake_gh(dir: &Path, token: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("gh");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\n\
             if [ \"$1 $2 $3 $4\" = \"auth token --hostname github.com\" ]; then\n\
             \x20 printf '%s\\n' '{token}'\n\
             else\n\
             \x20 echo \"no oauth token for $4\" >&2; exit 4\n\
             fi\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn gh_cli_reads_the_token_gh_holds() {
    let dir = tempfile::tempdir().unwrap();
    let resolver = GithubAuthResolver::new().with_gh_program(fake_gh(dir.path(), "gho_fromgh"));
    let token = resolver
        .resolve(&GithubAuth::GhCli {
            host: "github.com".into(),
        })
        .unwrap();
    assert_eq!(token.expose_for_header(), "gho_fromgh");
    assert_eq!(token.provenance().kind, GithubAuthKind::GhCli);
    assert_eq!(token.provenance().secret_backend, None);
}

#[test]
fn gh_cli_failure_carries_its_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let resolver = GithubAuthResolver::new().with_gh_program(fake_gh(dir.path(), "unused"));
    let err = resolver
        .resolve(&GithubAuth::GhCli {
            host: "ghe.example".into(),
        })
        .unwrap_err();
    let text = err.to_string();
    assert!(matches!(err, GithubAuthError::GhCli { .. }));
    assert!(text.contains("no oauth token for ghe.example"), "{text}");
}

// ── GitHub App ────────────────────────────────────────────────────────

/// A recording stand-in for api.github.com.
struct FakeGithub {
    installations: Vec<(u64, &'static str)>,
    expires_at: &'static str,
    requests: Mutex<Vec<GithubHttpRequest>>,
    mints: AtomicUsize,
}

impl FakeGithub {
    fn new(installations: Vec<(u64, &'static str)>) -> Arc<Self> {
        Arc::new(Self {
            installations,
            expires_at: ONE_HOUR_LATER,
            requests: Mutex::new(Vec::new()),
            mints: AtomicUsize::new(0),
        })
    }

    fn requests(&self) -> Vec<GithubHttpRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl GithubHttp for FakeGithub {
    fn send(&self, request: &GithubHttpRequest) -> Result<GithubHttpResponse, String> {
        self.requests.lock().unwrap().push(request.clone());
        let path = request
            .url
            .strip_prefix("https://api.github.test")
            .ok_or_else(|| format!("unexpected host in {}", request.url))?;
        let ok = |body: serde_json::Value| {
            Ok(GithubHttpResponse {
                status: 200,
                body: body.to_string(),
            })
        };
        match (request.method, path) {
            (GithubHttpMethod::Get, p) if p.starts_with("/app/installations?") => ok(
                serde_json::Value::Array(
                    self.installations
                        .iter()
                        .map(|(id, login)| serde_json::json!({ "id": id, "account": { "login": login } }))
                        .collect(),
                ),
            ),
            (GithubHttpMethod::Post, p) if p.ends_with("/access_tokens") => {
                let id: u64 = p
                    .trim_start_matches("/app/installations/")
                    .trim_end_matches("/access_tokens")
                    .parse()
                    .map_err(|_| format!("bad path {p}"))?;
                if !self.installations.iter().any(|(i, _)| *i == id) {
                    return Ok(GithubHttpResponse {
                        status: 404,
                        body: r#"{"message":"Not Found"}"#.into(),
                    });
                }
                let n = self.mints.fetch_add(1, Ordering::SeqCst) + 1;
                ok(serde_json::json!({
                    "token": format!("ghs_minted{n}_for_{id}"),
                    "expires_at": self.expires_at,
                }))
            }
            _ => Err(format!("unexpected request {request:?}")),
        }
    }
}

fn test_app() -> GithubApp {
    GithubApp::new(
        123,
        SecretSource::Backend(SecretBackend::Literal(test_key_pem().to_owned())),
    )
    .with_api_url("https://api.github.test")
}

fn resolver_at(fake: &Arc<FakeGithub>, clock: &Arc<AtomicU64>) -> GithubAuthResolver {
    let clock = Arc::clone(clock);
    GithubAuthResolver::new()
        .with_http(Arc::clone(fake) as Arc<dyn GithubHttp>)
        .with_clock(move || clock.load(Ordering::SeqCst))
}

fn decode_claims(jwt: &str) -> serde_json::Value {
    let key = jsonwebtoken::DecodingKey::from_rsa_pem(test_keypair().1.as_bytes()).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<serde_json::Value>(jwt, &key, &validation)
        .expect("JWT must verify against the App's public key")
        .claims
}

#[test]
fn app_mints_an_installation_token_found_by_owner() {
    let fake = FakeGithub::new(vec![(7, "someone-else"), (42, "Pleme-IO")]);
    let clock = Arc::new(AtomicU64::new(NOW));
    let resolver = resolver_at(&fake, &clock);

    let token = resolver
        .resolve(&GithubAuth::App(test_app().with_owner("pleme-io")))
        .unwrap();

    assert_eq!(token.expose_for_header(), "ghs_minted1_for_42");
    assert_eq!(token.provenance().kind, GithubAuthKind::App);
    assert_eq!(
        token.expires_at(),
        Some(UNIX_EPOCH + Duration::from_secs(NOW + 3600))
    );

    let requests = fake.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(requests[0].method, GithubHttpMethod::Get);
    assert_eq!(
        requests[0].url,
        "https://api.github.test/app/installations?per_page=100&page=1"
    );
    assert_eq!(requests[1].method, GithubHttpMethod::Post);
    assert_eq!(
        requests[1].url,
        "https://api.github.test/app/installations/42/access_tokens"
    );

    for request in &requests {
        let claims = decode_claims(&request.bearer);
        assert_eq!(claims["iss"], "123");
        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        assert_eq!(iat, NOW - 60, "iat is backdated 60 s");
        assert!(exp > NOW && exp - NOW <= 600, "exp is at most 10 min out");
        assert!(exp - iat <= 660);
    }
}

#[test]
fn app_with_installation_id_skips_the_lookup() {
    let fake = FakeGithub::new(vec![(42, "pleme-io")]);
    let clock = Arc::new(AtomicU64::new(NOW));
    let token = resolver_at(&fake, &clock)
        .resolve(&GithubAuth::App(test_app().with_installation_id(42)))
        .unwrap();
    assert_eq!(token.expose_for_header(), "ghs_minted1_for_42");
    assert_eq!(fake.requests().len(), 1);
}

#[test]
fn app_tokens_are_cached_until_the_refresh_window() {
    let fake = FakeGithub::new(vec![(42, "pleme-io")]);
    let clock = Arc::new(AtomicU64::new(NOW));
    let resolver = resolver_at(&fake, &clock);
    let auth = GithubAuth::App(test_app().with_installation_id(42));

    assert_eq!(
        resolver.resolve(&auth).unwrap().expose_for_header(),
        "ghs_minted1_for_42"
    );
    // 54 min in: 6 min left > 5 min refresh window — still cached.
    clock.store(NOW + 54 * 60, Ordering::SeqCst);
    assert_eq!(
        resolver.resolve(&auth).unwrap().expose_for_header(),
        "ghs_minted1_for_42"
    );
    assert_eq!(fake.mints.load(Ordering::SeqCst), 1);
    // 56 min in: 4 min left — re-minted.
    clock.store(NOW + 56 * 60, Ordering::SeqCst);
    assert_eq!(
        resolver.resolve(&auth).unwrap().expose_for_header(),
        "ghs_minted2_for_42"
    );
    assert_eq!(fake.mints.load(Ordering::SeqCst), 2);
}

#[test]
fn app_without_owner_or_id_uses_the_sole_installation_or_refuses() {
    let clock = Arc::new(AtomicU64::new(NOW));
    let sole = FakeGithub::new(vec![(5, "only-one")]);
    let token = resolver_at(&sole, &clock)
        .resolve(&GithubAuth::App(test_app()))
        .unwrap();
    assert_eq!(token.expose_for_header(), "ghs_minted1_for_5");

    let many = FakeGithub::new(vec![(5, "a"), (6, "b")]);
    let err = resolver_at(&many, &clock)
        .resolve(&GithubAuth::App(test_app()))
        .unwrap_err();
    assert!(
        matches!(err, GithubAuthError::InstallationAmbiguous { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("a, b"), "{err}");
}

#[test]
fn app_on_an_uninstalled_owner_lists_where_it_is_installed() {
    let fake = FakeGithub::new(vec![(7, "acme"), (8, "globex")]);
    let clock = Arc::new(AtomicU64::new(NOW));
    let err = resolver_at(&fake, &clock)
        .resolve(&GithubAuth::App(test_app().with_owner("pleme-io")))
        .unwrap_err();
    let text = err.to_string();
    assert!(matches!(err, GithubAuthError::InstallationNotFound { .. }));
    assert!(
        text.contains("\"pleme-io\"") && text.contains("acme, globex"),
        "{text}"
    );
}

#[test]
fn app_http_errors_carry_status_and_body() {
    let fake = FakeGithub::new(vec![(42, "pleme-io")]);
    let clock = Arc::new(AtomicU64::new(NOW));
    let err = resolver_at(&fake, &clock)
        .resolve(&GithubAuth::App(test_app().with_installation_id(999)))
        .unwrap_err();
    let GithubAuthError::AppHttp { status, reason, .. } = &err else {
        panic!("expected AppHttp, got {err:?}");
    };
    assert_eq!(*status, Some(404));
    assert!(reason.contains("Not Found"), "{reason}");
}

#[test]
fn app_id_and_key_can_come_from_files() {
    let dir = tempfile::tempdir().unwrap();
    let id_file = dir.path().join("app-id");
    let key_file = dir.path().join("app.pem");
    std::fs::write(&id_file, "123\n").unwrap();
    std::fs::write(&key_file, test_key_pem()).unwrap();
    let app = GithubApp {
        app_id: GithubId::Source(SecretSource::Backend(SecretBackend::File(id_file))),
        private_key: SecretSource::Backend(SecretBackend::File(key_file)),
        installation_id: Some(GithubId::Number(42)),
        owner: None,
        api_url: "https://api.github.test/".into(),
        refresh_before_secs: 300,
    };
    let fake = FakeGithub::new(vec![(42, "pleme-io")]);
    let clock = Arc::new(AtomicU64::new(NOW));
    resolver_at(&fake, &clock)
        .resolve(&GithubAuth::App(app))
        .unwrap();
    let requests = fake.requests();
    assert_eq!(decode_claims(&requests[0].bearer)["iss"], "123");
    assert_eq!(
        requests[0].url, "https://api.github.test/app/installations/42/access_tokens",
        "a trailing slash on api_url must not double up"
    );
}

#[test]
fn a_bad_private_key_is_a_typed_error() {
    let err = sign_app_jwt(1, "not a pem", NOW).unwrap_err();
    assert!(
        matches!(err, GithubAuthError::AppKey { app_id: 1, .. }),
        "{err}"
    );
}

#[test]
fn a_failing_app_in_a_chain_falls_through_to_the_next_source() {
    set_env("SHIKUMI_GH_TEST_APP_FALLBACK", "ghp_fallback");
    let fake = FakeGithub::new(vec![]);
    let clock = Arc::new(AtomicU64::new(NOW));
    let chain = GithubAuth::Chain(vec![
        GithubAuth::App(test_app().with_owner("pleme-io")),
        env_source("SHIKUMI_GH_TEST_APP_FALLBACK"),
    ]);
    let token = resolver_at(&fake, &clock).resolve(&chain).unwrap();
    assert_eq!(token.expose_for_header(), "ghp_fallback");
    assert_eq!(token.provenance().chain_path, vec![1]);
}

/// The real `reqwest` transport against a loopback HTTP server: proves the
/// headers and paths the fake above only asserts, on the wire.
#[test]
fn app_minting_over_real_http() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut headers = Vec::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let line = line.trim_end().to_owned();
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().unwrap();
                    }
                    headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
                }
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            let response_body = if request_line.starts_with("GET /app/installations?") {
                r#"[{"id":42,"account":{"login":"pleme-io"}}]"#.to_owned()
            } else {
                format!(r#"{{"token":"ghs_overhttp","expires_at":"{ONE_HOUR_LATER}"}}"#)
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            )
            .unwrap();
            seen.push((request_line.trim_end().to_owned(), headers));
        }
        seen
    });

    let resolver = GithubAuthResolver::new().with_clock(|| NOW);
    let app = test_app().with_api_url(base).with_owner("pleme-io");
    let token = resolver.resolve(&GithubAuth::App(app)).unwrap();
    assert_eq!(token.expose_for_header(), "ghs_overhttp");

    let seen = server.join().unwrap();
    assert_eq!(
        seen[0].0,
        "GET /app/installations?per_page=100&page=1 HTTP/1.1"
    );
    assert_eq!(
        seen[1].0,
        "POST /app/installations/42/access_tokens HTTP/1.1"
    );
    for (_, headers) in &seen {
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let auth = header("authorization");
        let jwt = auth.strip_prefix("Bearer ").expect("bearer JWT");
        assert_eq!(decode_claims(jwt)["iss"], "123");
        assert_eq!(header("accept"), "application/vnd.github+json");
        assert!(header("user-agent").starts_with("shikumi/"));
    }
}

// ── renderers and redaction ───────────────────────────────────────────

fn literal_token(raw: &str) -> GithubToken {
    GithubAuthResolver::new()
        .resolve(&GithubAuth::Token(SecretSource::Literal(raw.to_owned())))
        .unwrap()
}

#[test]
fn renderers_produce_each_sink_shape() {
    let token = literal_token("ghp_abc123");
    assert_eq!(token.authorization_header(), "Bearer ghp_abc123");
    assert_eq!(
        token.nix_access_tokens_line(),
        "access-tokens = github.com=ghp_abc123"
    );
    assert_eq!(
        token.env_pairs(),
        [
            ("GH_TOKEN", "ghp_abc123".to_owned()),
            ("GITHUB_TOKEN", "ghp_abc123".to_owned())
        ]
    );
    let header = token.git_extraheader();
    let encoded = header.strip_prefix("AUTHORIZATION: basic ").unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    assert_eq!(decoded, b"x-access-token:ghp_abc123");
    assert_eq!(
        token.git_config_env("github.com"),
        vec![
            ("GIT_CONFIG_COUNT".to_owned(), "1".to_owned()),
            (
                "GIT_CONFIG_KEY_0".to_owned(),
                "http.https://github.com/.extraheader".to_owned()
            ),
            ("GIT_CONFIG_VALUE_0".to_owned(), header),
        ]
    );
}

#[test]
fn debug_and_display_never_print_the_token() {
    let raw = "ghp_SUPERSECRETVALUE1234567890";
    let token = literal_token(raw);
    let debug = format!("{token:?}");
    let display = token.to_string();
    for rendered in [&debug, &display] {
        assert!(!rendered.contains("SUPERSECRET"), "leaked: {rendered}");
    }
    assert!(debug.contains("ghp_****(30 chars)"), "{debug}");
    assert!(
        display.starts_with("ghp_****(30 chars) via token from literal"),
        "{display}"
    );
}

#[test]
fn an_unprefixed_token_fingerprint_reveals_no_characters() {
    let token = literal_token("0123456789abcdef0123456789abcdef01234567");
    assert_eq!(token.redacted(), "****(40 chars)");
}

#[test]
fn http_request_debug_redacts_the_jwt() {
    let request = GithubHttpRequest {
        method: GithubHttpMethod::Get,
        url: "https://api.github.test/app/installations".into(),
        bearer: "eyJ.secret.jwt".into(),
        body: None,
    };
    assert!(!format!("{request:?}").contains("eyJ"));
}

#[test]
fn source_descriptions_never_include_a_literal() {
    let auth = GithubAuth::Token(SecretSource::Backend(SecretBackend::Literal(
        "ghp_inline_secret".into(),
    )));
    assert_eq!(auth.describe(), "token from literal");
    let auth = GithubAuth::Token(SecretSource::Literal("ghp_inline_secret".into()));
    assert_eq!(auth.describe(), "token from literal");
}

#[test]
fn a_whitespace_only_token_is_refused() {
    let err = GithubAuthResolver::new()
        .resolve(&GithubAuth::Token(SecretSource::Literal("  \n".into())))
        .unwrap_err();
    assert!(matches!(err, GithubAuthError::Empty { .. }), "{err}");
}

// ── timestamps ────────────────────────────────────────────────────────

#[test]
fn github_timestamps_parse_to_unix_seconds() {
    assert_eq!(parse_github_timestamp("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(
        parse_github_timestamp("2000-03-01T00:00:00Z"),
        Some(951_868_800)
    );
    assert_eq!(parse_github_timestamp("2027-01-01T00:00:00Z"), Some(NOW));
    assert_eq!(
        parse_github_timestamp("2027-01-01T01:00:00.123Z"),
        Some(NOW + 3600)
    );
    assert_eq!(parse_github_timestamp("2027-01-01T00:00:00+02:00"), None);
    assert_eq!(parse_github_timestamp("2027-13-01T00:00:00Z"), None);
    assert_eq!(parse_github_timestamp("garbage"), None);
}

#[test]
fn github_auth_kind_labels_match_serde_tags() {
    let samples = [
        env_source("X"),
        GithubAuth::GhCli { host: "h".into() },
        GithubAuth::App(test_app()),
        GithubAuth::Chain(vec![]),
    ];
    let kinds: Vec<GithubAuthKind> = samples.iter().map(GithubAuth::kind).collect();
    assert_eq!(kinds, GithubAuthKind::ALL);
    for sample in &samples {
        let value = serde_json::to_value(sample).unwrap();
        let tag = value.as_object().unwrap().keys().next().unwrap().clone();
        assert_eq!(tag, sample.kind().as_str());
    }
}
