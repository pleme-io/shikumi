# Shikumi (仕組み) — Config Discovery, Hot-Reload, and ArcSwap Store

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before non-trivial changes.


<!-- Blackmatter alignment: pillars 2 -->
<!-- See ~/code/github/pleme-io/BLACKMATTER.md for pillar definitions. -->

## Blackmatter pillars upheld

- **Pillar 2** (Configuration): Shikumi IS Pillar 2. Every service, tool, daemon in pleme-io discovers config via `ConfigDiscovery::new("app")`, loads strongly-typed structs via `ConfigStore::<T>::load`, hot-reloads through ArcSwap. No ad-hoc env parsing, no HashMap configs.

## Destination — shikumi is ConfigPlane's default resolver

New shikumi work aims at one destination: shikumi FULLY SUPPORTS the
**ConfigPlane** default-config behavior by default. ConfigPlane is the reusable
pleme-io configuration control plane (surface + API + tool; the fleet
control-plane cluster is the first consumer) — one central authority
owns/discovers/reconciles config for services *and* per-tick controllers and
pushes/syncs it down, while each component resolves its own slice the shikumi
progressive-discovery way. Three pieces —
(a) + (b) are now **shipped**, (c) remains destination (tier-honest: a
`Result::Err` is mitigation, not a guarantee):

**(a) `resolve_progressive` — the sealed fold. SHIPPED (v0.1.180).** The
`TieredConfig` tier selector (`tiered.rs`) and the `ProviderChain` figment fold
(`provider.rs`) are fused into ONE canonical sealed fold in `ClosedAxis`
precedence order, every resolved value carrying a typed
`Provenance { tier, source }`:

```text
bare → discovered[kanchi] → prescribed_default → file → env → runtime
```

`resolve_progressive` / `resolve_progressive_with` (computed tiers + injected
overlays) shipped in v0.1.180; `resolve_progressive_full(file, env_prefix)` is
the end-to-end fusion — it reads the file + env tiers through `ProviderChain`
and folds them with `Provenance::file` / `Provenance::env`. Tier-honest seal
grades in `docs/PROGRESSIVE-DISCOVERY-VERIFICATION.md` (precedence-order +
discovery-totality truly-unrep; provenance construction-complete with a
path-keyed side-map ceiling — file/env/runtime share the `Custom` tier rank and
are told apart by `Provenance::source`, not tier). `resolve_progressive` is the
default entry for every new config.

**(b) kanchi runtime-discovery layers (the DISCOVERED tier). SHIPPED (layer +
seam; real Secret client mock-proven).** `KubeClusterDiscovery`
(`kube_discovery.rs`, `kube-discovery` feature) is a `DiscoveryLayer` whose
`discover()` reads the *running cluster* through the `kanchi::ClusterEnv` seam:
downward API (`POD_NAMESPACE`/`POD_NAME`), service DNS (`db_host_name` /
`auth_dns_internal` — resolvable ⇒ emit the FQDN), and named `Secret` keys
(`db_pwd` / DEK / `uam-shared-key`). kanchi's `src/cluster.rs` owns the probes +
the `ClusterEnv` trait (std-only: `HostClusterEnv` real for env/DNS, `None` for
secrets; `MockClusterEnv` the test double). The layer is fully exercised against
the mock (empty `Dict` off-cluster = the clean degenerate); the **real**
in-cluster Secret client (`KubeSecretReader`, `kube` feature — reqwest-blocking
GET + SA token + CA cert + base64) is compiled + type-checked but **proven only
structurally + by mock — no live cluster in CI** (`pending-configplane`: the
shadow-first live proof is the M0 gate). The MySQL `Service` / per-svc S3
buckets are expressible via the generic `service()`/`secret()` plan, not
hard-coded. `kanchi` is an INTERIM git rev-pin (Cargo.toml) until it merges +
auto-releases.

**(c) central-authority + hot-reload-broadcast.** shikumi is the *per-component*
resolver + hot-reload store (`ConfigStore` ArcSwap + `ConfigWatcher`); ConfigPlane
pushes/syncs config down and broadcasts reloads. `ConfigStore` has NO
central/broadcast mode today (per-process only) — the broadcast-subscribe surface
is shikumi's slice of that pattern.

**M0:** one service comes up on a dev cluster resolving `db_host_name` /
`auth_dns_internal` / S3 / `metrics_port` from the cluster with ZERO hand-injected
env — shadow-first, golden-conf-gated.

**Shipped today** (what the above fuse/extend, never replace): `ConfigDiscovery` ·
`ProviderChain` (incl. `with_discovered`) · `ConfigStore<T>` ArcSwap hot-reload ·
`ConfigWatcher` · the `TieredConfig` selector · the `DiscoveryLayer` trait +
`compose` · kanchi host/env/cloud probes.

**Canonical:** [`theory/CONFIGURATION-MANAGEMENT.md`](https://github.com/pleme-io/theory/blob/main/CONFIGURATION-MANAGEMENT.md)
(fleet config shape; the sealed fold + `Provenance{tier,source}` are named there).
**Operator handle:** the `configplane` skill. Standing rule: a shikumi PR toward
this destination advances a tier or leaves a `pending-configplane:` note.

## Build & Test

```bash
cargo build                                   # compile
cargo test --all-features --no-fail-fast      # the gate CI runs
```

### Test counts — MEASURED, not remembered

The count below is re-derivable; do not hand-edit it. Reproduce with:

```bash
cargo test --lib --all-features -- --list | grep -c ': test$'
```

Measured 2026-08-16 on `aarch64-darwin` (`cargo test`, exit 0, zero failures):

| target | `cargo test` (default features) | `cargo test --all-features` |
|---|---|---|
| lib unit tests (`src/`) | 7,603 | **9,993** |
| `tests/dispatcher_registration.rs` | 7 | 7 |
| doctests | — | 21 collected · 12 run · 9 ignored |
| **executed total** | **7,610** | **10,012** |

> **The 2026-07-27 figures this replaced were stale by ~3,400** — they read
> 6,437 / 6,489 / 6,508, and the ~500 commits of hotswap conversion cells
> since had never moved them. That is the direction of drift this file warns
> about everywhere else: a count that is too LOW reads as merely modest, so
> nobody re-reads it as wrong. Re-derive rather than trust; the reproducer is
> right above.

Three things this table exists to stop:

1. **The stale-count tell.** Until this edit the line above read
   `77 unit tests + 1 doc-test`. That number was written 2026-03-15 (`6fedc77`)
   and never revisited, while `CLAUDE.md` itself was edited as recently as
   2026-07-09 — an **84×** understatement, the worst found in a 95-repo fleet
   sweep. Across four repos checked that day a wrong test count was a reliable
   tell for a suite that no longer *compiled*; shikumi is the benign case
   (compiles, 0 failures), and that is a measurement, not a default.
2. **`--all-targets` excludes doctests.** `cargo test --all-targets` reports
   6,489 + 7 and silently omits all 18 doctests. Both legs must be run, or
   counted separately, to state a total.
3. **Default features skip 52 lib tests + 2 doctests.** The `cli`, `hotswap`,
   `kube-discovery`/`kube` and `lisp` arms — i.e. the newest, least-proven
   ConfigPlane code — are exactly what a bare `cargo test` drops. That is why
   the gate runs `--all-features`, matching substrate `cargo-ci.yml`'s own
   default `test-args` and the measured reason behind it.

`cargo build --all-features` and `cargo build --all-features --tests` both
finish at **zero warnings** on the `rustc` side (measured 2026-09-03). The
last surviving one — `dead_code` on `ValueHelpers::{to_i128,to_bool}` in
`src/lisp_provider.rs` — closed by deleting the two shadowed trait methods:
figment's `Value` already exposes inherent `to_i128` (`value.rs:261`) and
`to_bool` (generated by `conversion_fn!` at `value.rs:222`), so
inherent-method resolution wins at `Value::to_i128` / `Value::to_bool` and
the trait methods were unreachable at every call site. A new
`figment_value_carries_inherent_to_i128_and_to_bool` test pins the
invariant so a future figment upgrade that removes either inherent fails
at the pin before the six call sites at lines 321 / 322 / 355 / 356 /
380 / 381 do. `cargo clippy -- -D warnings` is still **not** wired into CI
— the crate sets `[lints.clippy] pedantic = "warn"`, and no clippy was
available on this workstation to measure the real pedantic count first.
Wiring an unmeasured `-D warnings` gate would still be a guess; the
pedantic-tier burn-down needs its own measured pass
(`pending-shikumi-clippy` — narrowed from "one warning + pedantic" to
"pedantic only" by this change).

## CI

| workflow | reusable | what it actually verifies |
|---|---|---|
| `ci.yml` | — | `cargo fmt --check` + `cargo test --workspace --all-features --no-fail-fast` on push + PR. **The only thing that runs a test.** |
| `auto-release.yml` | substrate `cargo-auto-release.yml` | bump · commit · tag · publish to crates.io. **Zero test steps.** |
| `gen-spec.yml` | substrate `reusable-gen-spec.yml` | `Cargo.gen.lock` delta freshness. Never compiles or tests the crate. |

`ci.yml` landed 2026-07-27. Before it this repo — which ~90 fleet repos depend
on — had **no test CI at all**: a crate could be published to crates.io by
`auto-release.yml` with a suite nothing had run.

**Why `ci.yml` is not the 2-line substrate `cargo-ci.yml` shim.** Four blockers,
each measured rather than assumed; the full write-up with reproducing commands
is in `ci.yml`'s own header. Recheck them before rewriting it — if they have
closed, delete the job in favour of the shim:

1. `cargo-ci.yml@main` on GitHub is still the pre-`1d2b971` version (no
   cargo-test leg, no zero-check gate).
2. `nix flake check` here builds exactly one check —
   `nix eval .#checks.aarch64-darwin --apply builtins.attrNames` → `["gen-confirm"]`
   — which is the freshness gate `gen-spec.yml` already runs. The crate is never
   compiled by it.
3. **`substrate.rust.library`'s `shape` argument is inert.** It is declared at
   `mk-rust-tool-flake.nix:30` and never read again, so this flake is built by
   the *tool* builder, not `library.nix`. shikumi is therefore neither of the
   two categories the fleet checks-rollout assumed: it inherits neither
   `library.nix`'s new `checks.tests` nor the one-line `checks = forEachSystem …`
   forward that direct importers need. On the tool path `checks.tests` is
   deliberately absent for the `lockfile` buildMode (substrate's own
   `pending-rust-test-check: lockfile-dev-deps`).
4. **This repo's only devShell cannot be entered**, so any `nix develop`-based
   gate is red on arrival. Pure → devenv's "could not determine the current
   directory"; `--impure` → `languages.rust.channel` demands an
   `inputs.rust-overlay` this flake never declares. The second is a real missing
   input, so `--impure` alone does not fix it (`pending-shikumi-devshell`).

## Architecture

Shikumi extracts ayatsuri's configuration patterns into a reusable library
for Nix-managed desktop applications. Four modules, each independently testable:

### Module Map

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `discovery.rs` | XDG config file discovery with env override | `ConfigDiscovery`, `Format` |
| `provider.rs` | Figment provider chain builder | `ProviderChain` |
| `store.rs` | ArcSwap hot-reload store | `ConfigStore<T>` |
| `watcher.rs` | Symlink-aware file watcher | `ConfigWatcher`, `symlink_target` |
| `tiered.rs` | Tiered progressive-discovery resolution (the default) | `TieredConfig`, `ConfigTier`, `resolve_progressive`, `resolve_progressive_full`, `Provenance`, `ProgressiveResolution`, `ConfigDiff` |
| `discovered.rs` | Per-leaf attributed deep-merge fold (kanchi discovery composition) | `discovered_from_layers`, `deep_merge_attributed`, `LayerAttribution` |
| `kube_discovery.rs` (`kube-discovery` feat) | ConfigPlane DISCOVERED-tier cluster `DiscoveryLayer` over the `kanchi::ClusterEnv` seam | `KubeClusterDiscovery`, `KubeSecretReader` (`kube` feat) |
| `error.rs` | Error types | `ShikumiError` |

### Config Discovery Precedence

1. Environment variable override (e.g. `$TOBIRA_CONFIG`)
2. `$XDG_CONFIG_HOME/{app}/{app}.yaml` → `.yml` → `.toml`
3. `$HOME/.config/{app}/{app}.yaml` → `.yml` → `.toml`
4. Legacy: `$HOME/.{app}`, `$HOME/.{app}.toml`

### Provider Chain Layering

```
Serde defaults → Environment variables (PREFIX_) → Config file (YAML/TOML)
```

Later layers override earlier ones. File format auto-detected by extension.

### Tiered Progressive-Discovery Resolution (the default)

The fleet config default (per `theory/CONFIGURATION-MANAGEMENT.md` Primitive 5)
is the sealed fold `bare() → discovered()[kanchi] → prescribed_default() → file
→ env → runtime`, resolved in typed `ConfigTier` `ClosedAxis` precedence order:

```rust
let ProgressiveResolution { value, provenance } = MyConfig::resolve_progressive();
```

Every effective value carries a typed `Provenance { tier, source }`. Wire the
`discovered()` tier declaratively from kanchi axes — `fn discovered() -> Self {
Self::discovered_from_layers(&[&WindowLayer, &FontLayer]) }` — never a hand-rolled
struct literal. Tier-honest seal grades (precedence-order + discovery-totality
truly-unrep; provenance construction-complete with a side-map ceiling) live in
[`docs/PROGRESSIVE-DISCOVERY-VERIFICATION.md`](./docs/PROGRESSIVE-DISCOVERY-VERIFICATION.md).
The legacy single-tier `resolve_tier` / `resolve_from_env` path is preserved.

### Symlink-Aware Watching

Nix-darwin writes configs as symlinks into the Nix store. On rebuild, the
symlink target changes but the symlink path stays the same:

- **Symlinks**: `PollWatcher` with `follow_symlinks(true)`, 3s poll interval
- **Regular files**: `RecommendedWatcher` (FSEvents/inotify), instant notification
- **Remove events**: Ignored (nix does unlink + symlink atomically)

### Consumers

- **ayatsuri** — window manager (future migration from inline config)
- **tobira** — app launcher
- Any Nix-managed desktop app that needs hot-reloadable YAML/TOML config


## Advanced Discovery Methods

### `discover_all()`

Returns all config files found across the entire search hierarchy, not just the
first match. Useful when you need to merge configs from multiple locations:

```rust
let discovery = ConfigDiscovery::new("myapp");
let all_paths = discovery.discover_all();
// Returns: [~/.config/myapp/myapp.yaml, /etc/myapp/myapp.yaml, ...]
```

### `load_merged()`

Loads and merges all discovered config files in precedence order (most specific
wins). Layered on top of `discover_all()`:

```rust
let config: MyConfig = ConfigDiscovery::new("myapp").load_merged()?;
// Merges: defaults <- /etc/myapp.yaml <- ~/.config/myapp/myapp.yaml <- env vars
```

### `hierarchical()`

Discovers configs with directory-hierarchical override support. Walks from the
current directory upward, merging configs at each level:

```rust
let config: MyConfig = ConfigDiscovery::new("myapp").hierarchical()?;
// Merges: ~/.config/myapp.yaml <- ~/code/myapp.yaml <- ~/code/org/myapp.yaml <- ./myapp.yaml
```

This is the pattern used by CLAUDE.md discovery -- each directory level can
override settings from parent directories.

## Testing Principles

- All modules are pure Rust with no platform dependencies
- Tests use `tempfile` for filesystem operations
- Environment variable tests clean up after themselves
- Watcher tests may be timing-sensitive on CI; non-deterministic assertions
  are soft (don't hard-fail on missing events)
