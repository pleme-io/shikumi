# Shikumi (仕組み) — Config Discovery, Hot-Reload, and ArcSwap Store

<!-- Blackmatter alignment: pillars 2 -->
<!-- See ~/code/github/pleme-io/BLACKMATTER.md for pillar definitions. -->

## Blackmatter pillars upheld

- **Pillar 2** (Configuration): Shikumi IS Pillar 2. Every service, tool, daemon in pleme-io discovers config via `ConfigDiscovery::new("app")`, loads strongly-typed structs via `ConfigStore::<T>::load`, hot-reloads through ArcSwap. No ad-hoc env parsing, no HashMap configs.

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
