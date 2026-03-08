# Shikumi (仕組み) — Config Discovery, Hot-Reload, and ArcSwap Store

## Build & Test

```bash
cargo build          # compile
cargo test           # 26 unit tests + 1 doc-test
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

## Testing Principles

- All modules are pure Rust with no platform dependencies
- Tests use `tempfile` for filesystem operations
- Environment variable tests clean up after themselves
- Watcher tests may be timing-sensitive on CI; non-deterministic assertions
  are soft (don't hard-fail on missing events)
