//! CLI as a partial layer — end-to-end proof of the default config ↔ CLI
//! association (`shikumi::cli::ConfigArgs`): discovered file, `--config`
//! merge-overrides, env, a typed flag overlay and `--set`, folded in typed
//! precedence with per-leaf provenance and strict, attributed refusal.
//!
//! Every test uses its own app name, so its `<APP>_CONFIG` discovery
//! override and `<APP>_*` env layer cannot see another test's variables.
#![cfg(feature = "cli")]

use std::path::{Path, PathBuf};

use clap::Parser;
use serde::{Deserialize, Serialize};
use shikumi::cli::{ConfigArgs, ConfigShowCommand, OutputFormat, TierArg};
use shikumi::{
    ConfigSource, LayerError, NoFlags, OverlaySlot, ProgressiveLayer, ProgressiveResolution,
    SetAssignment, TieredConfig,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Sample {
    name: String,
    tags: Vec<String>,
    daemon: Daemon,
    github: Github,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Daemon {
    interval: u64,
    verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Github {
    token_file: Option<PathBuf>,
}

impl TieredConfig for Sample {
    fn bare() -> Self {
        Self {
            name: String::new(),
            tags: Vec::new(),
            daemon: Daemon {
                interval: 0,
                verbose: false,
            },
            github: Github { token_file: None },
        }
    }

    fn prescribed_default() -> Self {
        Self {
            name: "sample".into(),
            tags: vec!["default".into()],
            daemon: Daemon {
                interval: 60,
                verbose: false,
            },
            github: Github { token_file: None },
        }
    }
}

/// The binary's own flags: every field an `Option`, shaped like the
/// config paths it overrides (`--github-token-file` → `github.token_file`).
#[derive(Debug, Default, Serialize)]
struct Flags {
    name: Option<String>,
    github: GithubFlags,
}

#[derive(Debug, Default, Serialize)]
struct GithubFlags {
    token_file: Option<PathBuf>,
}

fn write(dir: &Path, file: &str, yaml: &str) -> PathBuf {
    let p = dir.join(file);
    std::fs::write(&p, yaml).unwrap();
    p
}

fn set(args: &[&str]) -> Vec<SetAssignment> {
    args.iter().map(|a| a.parse().unwrap()).collect()
}

fn source_at(r: &ProgressiveResolution<Sample>, path: &[&str]) -> ConfigSource {
    r.provenance()
        .provenance_of(path)
        .unwrap_or_else(|| panic!("no provenance at {path:?}"))
        .source()
        .clone()
}

/// Point `<APP>_CONFIG` at `path` (the discovery override) for this app.
fn discover(prefix: &str, path: &Path) {
    // SAFETY: each test owns a distinct `<APP>_` prefix, so no other
    // thread reads or writes this variable.
    unsafe { std::env::set_var(format!("{prefix}CONFIG"), path) };
}

fn env(key: &str, value: &str) {
    // SAFETY: as in `discover` — the key carries the test's own prefix.
    unsafe { std::env::set_var(key, value) };
}

#[test]
fn absent_flags_do_not_clobber_file_values() {
    let dir = tempfile::tempdir().unwrap();
    let file = write(
        dir.path(),
        "a.yaml",
        "name: from-file\ngithub:\n  token_file: /etc/tok\n",
    );
    discover("SHIKUMI_CLI_T1_", &file);
    let r = ConfigArgs::default()
        .resolve::<Sample>("shikumi-cli-t1", &Flags::default())
        .unwrap();
    assert_eq!(r.value().name, "from-file");
    assert_eq!(r.value().github.token_file, Some(PathBuf::from("/etc/tok")));
    assert_eq!(source_at(&r, &["name"]), ConfigSource::File(file.clone()));
    assert_eq!(
        source_at(&r, &["github", "token_file"]),
        ConfigSource::File(file)
    );
    // Untouched leaves keep the computed tiers.
    assert_eq!(r.value().daemon.interval, 60);
    assert_eq!(
        source_at(&r, &["daemon", "interval"]),
        ConfigSource::Defaults
    );
}

#[test]
fn config_override_merges_over_the_discovered_file() {
    let dir = tempfile::tempdir().unwrap();
    let discovered = write(
        dir.path(),
        "app.yaml",
        "name: discovered\ndaemon:\n  interval: 100\n  verbose: true\n",
    );
    let over = write(dir.path(), "over.yaml", "daemon:\n  interval: 200\n");
    discover("SHIKUMI_CLI_T2_", &discovered);
    let args = ConfigArgs {
        config: vec![over.clone()],
        set: vec![],
    };
    let r = args
        .resolve::<Sample>("shikumi-cli-t2", &NoFlags::default())
        .unwrap();
    assert_eq!(r.value().daemon.interval, 200, "override beats discovered");
    assert!(r.value().daemon.verbose, "sibling from discovered survives");
    assert_eq!(r.value().name, "discovered", "merge, not replace");
    assert_eq!(
        source_at(&r, &["daemon", "interval"]),
        ConfigSource::File(over)
    );
    assert_eq!(
        source_at(&r, &["daemon", "verbose"]),
        ConfigSource::File(discovered)
    );
}

#[test]
fn later_config_override_wins() {
    let dir = tempfile::tempdir().unwrap();
    let first = write(dir.path(), "1.yaml", "name: first\n");
    let second = write(dir.path(), "2.yaml", "name: second\n");
    let args = ConfigArgs {
        config: vec![first, second.clone()],
        set: vec![],
    };
    let r = args
        .resolve::<Sample>("shikumi-cli-t3", &NoFlags::default())
        .unwrap();
    assert_eq!(r.value().name, "second");
    assert_eq!(source_at(&r, &["name"]), ConfigSource::File(second));
}

#[test]
fn env_beats_config_override() {
    let dir = tempfile::tempdir().unwrap();
    let over = write(dir.path(), "over.yaml", "daemon:\n  interval: 200\n");
    env("SHIKUMI_CLI_T4_DAEMON__INTERVAL", "300");
    let args = ConfigArgs {
        config: vec![over],
        set: vec![],
    };
    let r = args
        .resolve::<Sample>("shikumi-cli-t4", &NoFlags::default())
        .unwrap();
    assert_eq!(r.value().daemon.interval, 300);
    assert_eq!(
        source_at(&r, &["daemon", "interval"]),
        ConfigSource::Env("SHIKUMI_CLI_T4_".into())
    );
}

#[test]
fn typed_overlay_beats_env() {
    env("SHIKUMI_CLI_T5_NAME", "from-env");
    let flags = Flags {
        name: Some("from-flag".into()),
        github: GithubFlags {
            token_file: Some("/run/token".into()),
        },
    };
    let r = ConfigArgs::default()
        .resolve::<Sample>("shikumi-cli-t5", &flags)
        .unwrap();
    assert_eq!(r.value().name, "from-flag");
    assert_eq!(
        r.value().github.token_file,
        Some(PathBuf::from("/run/token"))
    );
    assert_eq!(source_at(&r, &["name"]), ConfigSource::Cli("flags".into()));
    assert_eq!(
        source_at(&r, &["github", "token_file"]),
        ConfigSource::Cli("flags".into())
    );
}

#[test]
fn set_beats_every_other_layer() {
    let dir = tempfile::tempdir().unwrap();
    let discovered = write(dir.path(), "app.yaml", "name: discovered\n");
    let over = write(dir.path(), "over.yaml", "name: override\n");
    discover("SHIKUMI_CLI_T6_", &discovered);
    env("SHIKUMI_CLI_T6_NAME", "env");
    let flags = Flags {
        name: Some("flag".into()),
        ..Flags::default()
    };
    let args = ConfigArgs {
        config: vec![over],
        set: set(&["name=set", "daemon.interval=999", "daemon.verbose=true"]),
    };
    let r = args.resolve::<Sample>("shikumi-cli-t6", &flags).unwrap();
    assert_eq!(r.value().name, "set");
    assert_eq!(r.value().daemon.interval, 999, "YAML scalar parsed as int");
    assert!(r.value().daemon.verbose, "YAML scalar parsed as bool");
    for path in [
        &["name"][..],
        &["daemon", "interval"],
        &["daemon", "verbose"],
    ] {
        assert_eq!(source_at(&r, path), ConfigSource::Cli("--set".into()));
    }
}

#[test]
fn lists_replace_rather_than_append() {
    let dir = tempfile::tempdir().unwrap();
    let discovered = write(dir.path(), "app.yaml", "tags: [a, b]\n");
    let over = write(dir.path(), "over.yaml", "tags: [c]\n");
    discover("SHIKUMI_CLI_T7_", &discovered);
    let args = ConfigArgs {
        config: vec![over.clone()],
        set: vec![],
    };
    let r = args
        .resolve::<Sample>("shikumi-cli-t7", &NoFlags::default())
        .unwrap();
    assert_eq!(r.value().tags, vec!["c".to_owned()]);
    assert_eq!(source_at(&r, &["tags"]), ConfigSource::File(over));

    let args = ConfigArgs {
        config: vec![],
        set: set(&["tags=[x, y, z]"]),
    };
    let r = args
        .resolve::<Sample>("shikumi-cli-t7", &NoFlags::default())
        .unwrap();
    assert_eq!(r.value().tags, ["x", "y", "z"]);
}

#[test]
fn unknown_key_via_set_is_refused_naming_the_source() {
    let args = ConfigArgs {
        config: vec![],
        set: set(&["daemon.intervall=5"]),
    };
    let err = args
        .resolve::<Sample>("shikumi-cli-t8", &NoFlags::default())
        .unwrap_err();
    assert!(
        matches!(&err, LayerError::UnknownKey { path, .. } if path == "daemon.intervall"),
        "{err:?}"
    );
    assert_eq!(
        err.origin().map(|p| p.source().clone()),
        Some(ConfigSource::Cli("--set".into()))
    );
    let msg = err.to_string();
    assert!(msg.contains("daemon.intervall"), "{msg}");
    assert!(msg.contains("--set"), "{msg}");
}

#[test]
fn unknown_key_in_a_config_file_names_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let over = write(dir.path(), "over.yaml", "nmae: typo\n");
    let args = ConfigArgs {
        config: vec![over.clone()],
        set: vec![],
    };
    let err = args
        .resolve::<Sample>("shikumi-cli-t9", &NoFlags::default())
        .unwrap_err();
    assert_eq!(err.path(), Some("nmae"));
    assert_eq!(
        err.origin().map(|p| p.source().clone()),
        Some(ConfigSource::File(over))
    );
}

#[test]
fn ill_typed_env_value_is_refused_naming_env() {
    env("SHIKUMI_CLI_T10_DAEMON__INTERVAL", "soon");
    let err = ConfigArgs::default()
        .resolve::<Sample>("shikumi-cli-t10", &NoFlags::default())
        .unwrap_err();
    assert!(matches!(err, LayerError::Invalid { .. }), "{err:?}");
    assert_eq!(err.path(), Some("daemon.interval"));
    assert_eq!(
        err.origin().map(|p| p.source().clone()),
        Some(ConfigSource::Env("SHIKUMI_CLI_T10_".into()))
    );
}

#[test]
fn missing_config_override_file_is_an_error() {
    let args = ConfigArgs {
        config: vec![PathBuf::from("/nonexistent/shikumi-cli-t11.yaml")],
        set: vec![],
    };
    let err = args
        .resolve::<Sample>("shikumi-cli-t11", &NoFlags::default())
        .unwrap_err();
    assert!(matches!(err, LayerError::File { .. }), "{err:?}");
}

#[test]
fn precedence_is_typed_not_positional() {
    let dir = tempfile::tempdir().unwrap();
    let discovered = write(dir.path(), "app.yaml", "name: discovered\n");
    let over = write(dir.path(), "over.yaml", "name: override\n");
    let mut layers = vec![
        ProgressiveLayer::set(&set(&["daemon.interval=7"])),
        ProgressiveLayer::cli(&Flags {
            name: Some("flag".into()),
            ..Flags::default()
        })
        .unwrap(),
        ProgressiveLayer::try_from_config_override(&over).unwrap(),
        ProgressiveLayer::try_from_file(&discovered).unwrap(),
    ];
    assert_eq!(
        layers
            .iter()
            .map(ProgressiveLayer::slot)
            .collect::<Vec<_>>(),
        [
            OverlaySlot::CliSet,
            OverlaySlot::CliFlags,
            OverlaySlot::ConfigOverride,
            OverlaySlot::File
        ]
    );
    let forward = Sample::try_resolve_progressive_with(&layers).unwrap();
    layers.reverse();
    let reversed = Sample::try_resolve_progressive_with(&layers).unwrap();
    assert_eq!(forward, reversed);
    assert_eq!(forward.value().name, "flag");
    assert_eq!(forward.value().daemon.interval, 7);
}

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    config: ConfigArgs,
}

#[test]
fn clap_surface_parses_repeatable_config_and_set() {
    let cli = Cli::try_parse_from([
        "app",
        "--config",
        "/a.yaml",
        "--config",
        "/b.yaml",
        "--set",
        "daemon.interval=300",
        "--set",
        "name=x",
    ])
    .unwrap();
    assert_eq!(
        cli.config.config,
        [PathBuf::from("/a.yaml"), PathBuf::from("/b.yaml")]
    );
    assert_eq!(cli.config.set.len(), 2);
    assert_eq!(cli.config.set[0].path(), ["daemon", "interval"]);
    // A malformed `--set` is refused at the argv boundary.
    assert!(Cli::try_parse_from(["app", "--set", "=1"]).is_err());
    assert!(Cli::try_parse_from(["app", "--set", "novalue"]).is_err());
}

#[test]
fn config_show_effective_renders_the_fold_with_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let discovered = write(dir.path(), "app.yaml", "name: discovered\n");
    discover("SHIKUMI_CLI_T14_", &discovered);
    let args = ConfigArgs {
        config: vec![],
        set: set(&["daemon.interval=42"]),
    };
    let r = args
        .resolve::<Sample>("shikumi-cli-t14", &NoFlags::default())
        .unwrap();
    let show = ConfigShowCommand {
        tier: TierArg::Env,
        path: None,
        format: OutputFormat::Json,
        diff: None,
        effective: true,
        provenance: true,
    };
    let rendered = show.render_effective(&r).unwrap();
    let rows: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(rows["name"]["value"], "discovered");
    assert_eq!(
        rows["name"]["source"],
        format!("file({})", discovered.display())
    );
    assert_eq!(rows["daemon.interval"]["value"], 42);
    assert_eq!(rows["daemon.interval"]["source"], "cli(--set)");
    assert_eq!(rows["daemon.interval"]["tier"], "custom");

    let plain = ConfigShowCommand {
        provenance: false,
        format: OutputFormat::Yaml,
        ..show
    };
    let yaml = plain.render_effective(&r).unwrap();
    let back: Sample = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(&back, r.value());
}
