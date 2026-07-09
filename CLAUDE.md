# Shikumi (仕組み) — Config Discovery, Hot-Reload, and ArcSwap Store

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before non-trivial changes.


<!-- Blackmatter alignment: pillars 2 -->
<!-- See ~/code/github/pleme-io/BLACKMATTER.md for pillar definitions. -->

## Blackmatter pillars upheld

- **Pillar 2** (Configuration): Shikumi IS Pillar 2. Every service, tool, daemon in pleme-io discovers config via `ConfigDiscovery::new("app")`, loads strongly-typed structs via `ConfigStore::<T>::load`, hot-reloads through ArcSwap. No ad-hoc env parsing, no HashMap configs.

## Destination — shikumi is ConfigPlane's default resolver (named, not shipped)

New shikumi work aims at one destination: shikumi FULLY SUPPORTS the
**ConfigPlane** default-config behavior by default. ConfigPlane is the reusable
pleme-io configuration control plane (surface + API + tool; camelot the first
consumer) — one central authority owns/discovers/reconciles config for services
*and* per-tick controllers and pushes/syncs it down, while each component
resolves its own slice the shikumi progressive-discovery way. Three pieces, all
NAMED-not-shipped (a `Result::Err` is mitigation, not a guarantee):

**(a) `resolve_progressive` — the sealed fold.** Fuse today's two separate
pieces — the `TieredConfig` tier selector (`tiered.rs`) and the `ProviderChain`
figment fold (`provider.rs`, incl. `with_discovered`) — into ONE canonical
sealed fold in `ClosedAxis` precedence order, every resolved value carrying a
typed `Provenance { tier, source }`:

```text
bare → discovered[kanchi] → prescribed_default → file → env → runtime
```

Today neither exists: selector and fold are unfused, and per-value
`Provenance{tier,source}` is absent (`FormatProvenance` = format origin;
`compose_with_provenance` = intra-discovered layer attribution — not whole-chain).
`resolve_progressive` becomes the default entry for every new config.

**(b) kanchi runtime-discovery layers (the DISCOVERED tier).** New
`DiscoveryLayer` impls (`discovered.rs`) whose `discover()` reads the *running
cluster* via new kanchi probes: k8s downward API (`POD_NAMESPACE`/`POD_NAME`),
service DNS (peer / `db_host_name` / `auth_dns_internal`), k8s `Secret` reads
(DEK / db_pwd / uam-shared-key), the MySQL `Service`, per-svc S3 buckets. Today
kanchi carries only host + env/cloud-classification probes (screen/DPR/RAM,
`in_cluster` / cgroup-limit, OS/arch) — no cluster-wiring discovery yet.

**(c) central-authority + hot-reload-broadcast.** shikumi is the *per-component*
resolver + hot-reload store (`ConfigStore` ArcSwap + `ConfigWatcher`); ConfigPlane
pushes/syncs config down and broadcasts reloads. `ConfigStore` has NO
central/broadcast mode today (per-process only) — the broadcast-subscribe surface
is shikumi's slice of that pattern.

**M0:** one service comes up on camelot-dev resolving `db_host_name` /
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
cargo build          # compile
cargo test           # 77 unit tests + 1 doc-test
```

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
| `tiered.rs` | Tiered progressive-discovery resolution (the default) | `TieredConfig`, `ConfigTier`, `resolve_progressive`, `Provenance`, `ProgressiveResolution`, `ConfigDiff` |
| `discovered.rs` | Per-leaf attributed deep-merge fold (kanchi discovery composition) | `discovered_from_layers`, `deep_merge_attributed`, `LayerAttribution` |
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
