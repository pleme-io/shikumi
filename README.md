# shikumi

Typed configuration for pleme-io binaries: XDG discovery, a figment provider
chain, a provenance-tracking progressive fold (`bare → discovered →
prescribed_default → file → env → cli`), and an `ArcSwap` hot-reload store.

## CLI as a partial layer

Every binary gets the same config ↔ CLI association by flattening one clap
struct (feature `cli`):

```rust
#[derive(clap::Parser)]
struct Cli {
    #[command(flatten)]
    config: shikumi::cli::ConfigArgs, // --config PATH (repeatable), --set PATH=VALUE (repeatable)
    #[command(flatten)]
    flags: Flags,                     // the binary's own flags, every field an Option
}

let resolved = cli.config.resolve::<MyConfig>("myapp", &cli.flags)?;
```

- `--config FILE` is a merge-override above the discovered file
  (`$MYAPP_CONFIG` or `~/.config/myapp/myapp.yaml`), never a replacement.
- `MYAPP_*` env vars (`__` for nesting) beat `--config`.
- Each typed flag is a partial: an absent flag contributes nothing, a present
  one beats env.
- `--set daemon.interval=300` (value parsed as YAML) beats everything.
- Unknown or ill-typed keys are refused, naming the layer that wrote them.
- `myapp config-show --effective --provenance` prints every leaf with the layer
  that set it.

See `CLAUDE.md` for the full precedence table and the honest limits.
