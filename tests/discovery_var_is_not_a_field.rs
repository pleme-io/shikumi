//! The discovery variable must not be read as a field.
//!
//! ── ★ THE BUG THIS PINS (2026-08-29) ───────────────────────────────────
//!
//! shikumi documents two conventions that collided:
//!
//!   ConfigDiscovery::new(app).env_override("<APP>_CONFIG")   // find the file
//!   ConfigStore::load(path, "<APP>_")                        // override fields
//!
//! The env layer maps `<PREFIX><FIELD>` onto fields, so `<APP>_CONFIG` was
//! read as a field named `config`. No consumer declares one, and every fleet
//! consumer sets `deny_unknown_fields` — so the ENTIRE load was refused and
//! the caller silently fell back to its prescribed tier.
//!
//! **The documented way to point an app at a config file was the one way to
//! guarantee it ignored the file.** Live in omoya, mukae and annai; latent in
//! all three because it fires only when someone actually uses the override.
//!
//! Found by RUNNING a daemon (annai's first `dig` timed out because the
//! fallback binds :53), never by reading any of the three copies.

use std::io::Write as _;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Probe {
    listen: String,
    retries: u32,
}

impl Default for Probe {
    fn default() -> Self {
        Self { listen: "127.0.0.1:53".into(), retries: 1 }
    }
}

fn write_config(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("probe.yaml");
    let mut f = std::fs::File::create(&p).expect("create");
    writeln!(f, "listen: \"0.0.0.0:5353\"\nretries: 7").expect("write");
    p
}

#[test]
fn the_discovery_variable_does_not_refuse_the_whole_load() {
    // THE regression. With SHIKUMI_PROBE_CONFIG set — which is exactly what
    // an operator does to point the app at a file — the load must SUCCEED and
    // return the file's values, not fall back to Default.
    let dir = std::env::temp_dir().join("shikumi-discovery-probe");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = write_config(&dir);

    // SAFETY: single-threaded test process; no other thread reads the env.
    unsafe {
        std::env::set_var("SHIKUMI_PROBE_CONFIG", path.display().to_string());
    }

    let store = shikumi::ConfigStore::<Probe>::load(&path, "SHIKUMI_PROBE_")
        .expect("the discovery variable must not refuse the load");
    let got = Probe::clone(&store.get());

    assert_eq!(got.listen, "0.0.0.0:5353", "file value was not applied");
    assert_eq!(got.retries, 7);
    assert_ne!(got, Probe::default(), "silently fell back to the default tier");

    unsafe {
        std::env::remove_var("SHIKUMI_PROBE_CONFIG");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_env_layer_still_supplies_fields_the_file_omits() {
    // The fix must not buy safety by disabling the env layer wholesale. Only
    // the reserved `config` key is ignored; every real field still resolves.
    //
    // ★ NOTE THE PRECEDENCE, which is shikumi's and predates this fix: the
    // chain is env THEN file, and figment's later merge wins — so the FILE
    // beats env, and the env layer supplies what the file omits. The name
    // "field-override prefix" reads the other way round and is worth knowing
    // before debugging why an exported variable "did nothing".
    let dir = std::env::temp_dir().join("shikumi-discovery-probe-2");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("probe.yaml");
    // Deliberately omits `retries`, so the env layer is the only source for it.
    let mut f = std::fs::File::create(&path).expect("create");
    writeln!(f, "listen: \"0.0.0.0:5353\"").expect("write");
    drop(f);

    // SAFETY: single-threaded test process.
    unsafe {
        std::env::set_var("SHIKUMI_PROBE2_RETRIES", "42");
    }
    let store = shikumi::ConfigStore::<Probe>::load(&path, "SHIKUMI_PROBE2_").expect("load");
    let got = Probe::clone(&store.get());
    assert_eq!(got.retries, 42, "env layer stopped supplying omitted fields");
    assert_eq!(got.listen, "0.0.0.0:5353", "file value lost");

    unsafe {
        std::env::remove_var("SHIKUMI_PROBE2_RETRIES");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
