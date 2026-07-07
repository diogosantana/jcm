# Development and build guide

This document is for contributors and anyone building **jcm** from source. End users who only run a pre-compiled binary should read the [README](../README.md).

## Prerequisites

| Tool | Version |
|------|---------|
| [Rust](https://rustup.rs/) | stable (2024 edition, ≥ 1.85) |
| JDK / JRE | any recent Temurin, OpenJDK, etc. with `java` and `keytool` on `PATH` |

Optional for release packaging:

- `tar` / `zip` for archives
- GitHub Actions (CI is already configured)

No OpenSSL development libraries are required — TLS fetch uses the `rustls` crate.

## Clone and build

```bash
git clone https://github.com/diogosantana/jcm.git
cd jcm
cargo build --release
```

The binary is written to:

```text
target/release/jcm          # Linux / macOS
target/release/jcm.exe      # Windows
```

Run without installing:

```bash
cargo run -- list
cargo run -- inspect https://example.com --graph
cargo run -- add test https://example.com --dry-run --cacerts /path/to/cacerts
```

## Test

```bash
cargo test
cargo clippy --all-targets -- -D warnings   # recommended before PR
cargo fmt --all
```

Integration tests:

| Test | Purpose |
|------|---------|
| `tests/config_parse.rs` | TXT / JSON config parser (library unit, not CLI) |
| `tests/doctor.rs` | `jcm list` and `jcm add --dry-run` smoke tests |
| `src/cert.rs` unit tests | Fingerprint format, `--graph` output |
| `src/keystore.rs` unit tests | `keytool` list parsing, built-in alias protection |

## Project layout

```text
jcm/
  src/
    main.rs          # entry point
    lib.rs           # module exports, constants
    cli.rs           # clap definitions (flags, subcommands)
    commands.rs      # command handlers
    ops.rs           # add / remove planning and execution
    cert.rs          # rustls fetch, chain selection, --graph
    jvm.rs           # JAVA_HOME / cacerts detection
    keystore.rs      # keytool wrapper (list / import / delete / show)
    elevation.rs     # sudo (Unix) / UAC (Windows)
    paths.rs         # alias validation helpers
    platform.rs      # OS helpers, permissions
    temp.rs          # per-run OS temp directory (auto cleanup)
    config.rs        # TXT / JSON parsers (tests only)
    logging.rs       # tracing setup
  examples/
    trust-urls.txt.example   # legacy examples (not used by CLI)
    trust-urls.json.example
  tests/
  docs/
    COMMANDS.md      # command specification
  .github/workflows/ci.yml
```

## Key design points

### Scope

The CLI exposes six subcommands: `add`, `remove`, `list`, `show`, `inspect`. There is no declarative `sync`, no `backup`/`restore`, no `settings.json`, and **no data directory**. Users pass URLs directly to `add`.

### Managed vs original keystore entries

All imports use `--alias-prefix` (default `jcm-`). `remove` only deletes `jcm-*` aliases matching the naming convention. After each mutation, `verify_builtin_aliases_unchanged` checks in memory that every non-`jcm-*` alias present before the operation still exists in the keystore.

### No persistent state

Nothing is written under `~/.jcm`. Alias discovery for `list`, `remove`, and `show` comes directly from `keytool -list`. Temporary PEM files use `std::env::temp_dir()` and are removed when the operation completes.

### TLS fetch

`cert.rs` connects with `rustls` using a permissive verifier (chain harvest only, no trust validation). Certificates are parsed with `x509-parser`; fingerprints use SHA-256.

### Elevation

| Platform | Mechanism |
|----------|-----------|
| Linux / macOS | `sudo -E keytool …` |
| Windows | `runas` crate relaunches the binary with UAC |

Controlled by `--elevate auto|always|never`. Read-only commands never elevate.

### Dry-run

`add --dry-run` and `remove --dry-run` plan mutations without calling `keytool` import/delete. Exit code `3` when changes would occur.

## Local development without admin

```bash
cp "$JAVA_HOME/lib/security/cacerts" /tmp/jcm-cacerts

cargo run -- --cacerts /tmp/jcm-cacerts add my-api https://api.example.com --dry-run

cargo run -- --cacerts /tmp/jcm-cacerts add my-api https://api.example.com
```

## Dependencies (Cargo)

Managed with `cargo add` — see [Cargo.toml](../Cargo.toml). Main crates:

| Crate | Role |
|-------|------|
| `clap` | CLI |
| `rustls` | TLS chain fetch |
| `x509-parser` / `pem` | Certificate parsing |
| `serde` / `serde_json` | Config parser tests |
| `sha2` | Fingerprints |
| `which` | Locate `java` / `keytool` |
| `runas` (Windows) | UAC elevation |
| `libc` (Unix) | Permissions / uid checks |

## CI

GitHub Actions workflow [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on:

- `ubuntu-latest`
- `macos-latest`
- `windows-latest`

Each job executes `cargo test` and `cargo build --release`.

## Release builds (manual)

```bash
# Linux
cargo build --release --target x86_64-unknown-linux-gnu

# macOS Apple Silicon
cargo build --release --target aarch64-apple-darwin

# macOS Intel
cargo build --release --target x86_64-apple-darwin

# Windows
cargo build --release --target x86_64-pc-windows-msvc
```

Cross-compilation may require [cross](https://github.com/cross-rs/cross) or native runners. Attach binaries to GitHub Releases for end-user installation described in the README.

## Adding a new subcommand

1. Add variant to `Commands` in `src/cli.rs`
2. Wire handler in `src/commands.rs` (`run()` match)
3. Add logic in `src/ops.rs` if the command mutates the keystore
4. Document in [COMMANDS.md](COMMANDS.md) and [README](../README.md)
5. Run `cargo test`

## Publishing releases (maintainers)

Releases are automated via [`.github/workflows/release.yml`](../.github/workflows/release.yml) when a version tag is pushed.

1. Ensure [`CHANGELOG.md`](../CHANGELOG.md) has an entry for the version (e.g. `## [0.1.0]`)
2. Ensure `version` in [`Cargo.toml`](../Cargo.toml) matches the tag (without the `v` prefix)
3. Merge changes to `main`
4. Tag and push: `git tag v0.1.0 && git push origin v0.1.0`
5. Verify the Release workflow completes in GitHub Actions
6. Smoke-test artifacts from the [Releases](https://github.com/diogosantana/jcm/releases/latest) page:
   - `jcm --version` prints the expected version
   - `jcm list` runs (requires JDK)
7. Confirm all four archive names match the [README](../README.md) installation table
8. Confirm the GitHub Release body matches the `CHANGELOG.md` section for that version

## Troubleshooting

| Issue | Suggestion |
|-------|------------|
| `cacerts is not writable` | Use `--cacerts` with a writable copy or `--elevate auto` |
| `sudo not found` (CI) | Use `--elevate never` and a writable keystore path |
| `keytool not found` | Set `JAVA_HOME` or install a JDK |
| Alias not found on `remove` | Run `jcm list` to see managed aliases |
| Wrong JVM | Pass `--java-home` or `--cacerts` explicitly |
| Preview before import | `jcm add <alias> <url> --dry-run` |
