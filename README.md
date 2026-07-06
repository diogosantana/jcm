# jcm — Java Cacerts Manager

**jcm** is a cross-platform command-line tool (Windows, Linux, macOS) that imports TLS certificates from HTTPS URLs into the JVM trust store (`cacerts`). It only manages aliases prefixed with `jcm-` and never modifies the JVM's built-in CA entries.

Ideal for local development, corporate CAs, and CI/CD pipelines where Java must trust internal or non-public HTTPS services.

## Features

- **`add`** — fetch a TLS chain from a URL and import into `cacerts` as `jcm-<alias>`
- **`remove`** — delete managed `jcm-*` entries from `cacerts`
- **`list`** — list keystore entries (managed aliases by default)
- **`show`** — certificate details for a `jcm-*` alias in `cacerts`
- **`inspect`** — view a URL's TLS chain without touching the keystore
- **`--dry-run`** on `add` and `remove` — preview changes before applying
- Built-in TLS fetch — **no OpenSSL CLI** required
- Chain selection: **root**, **leaf**, **intermediate**, **full**, or index `0`–`4`
- Privilege elevation when needed: **sudo** (Linux/macOS) or **UAC** (Windows)
- Temporary PEM files under the OS temp directory, removed automatically

## Requirements

| Requirement | Notes |
|-------------|--------|
| **JDK or JRE** | `java` and `keytool` must be on your `PATH` |
| **Writable `cacerts`** or elevation | System JDK paths often need admin rights (see [Elevation](#elevation)) |

No Rust toolchain or OpenSSL installation is needed if you use a [pre-built binary](#installation).

## Installation

Download the latest release for your platform from the **Releases** page of this repository on GitHub.

| OS | Archive |
|----|---------|
| Linux (x86_64) | `jcm-x86_64-unknown-linux-gnu.tar.gz` |
| macOS (Apple Silicon) | `jcm-aarch64-apple-darwin.tar.gz` |
| macOS (Intel) | `jcm-x86_64-apple-darwin.tar.gz` |
| Windows (x86_64) | `jcm-x86_64-pc-windows-msvc.zip` |

Extract the archive and place `jcm` (or `jcm.exe`) on your `PATH`.

Verify:

```bash
jcm --version
jcm list
```

> To build from source, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).  
> Full command reference: [docs/COMMANDS.md](docs/COMMANDS.md).

## Quick start

```bash
# 1. Inspect a URL before importing
jcm inspect https://api.example.com --graph

# 2. Preview the import
jcm add my-api https://api.example.com --dry-run

# 3. Import (may prompt for admin password)
jcm add my-api https://api.example.com

# 4. Confirm in the keystore
jcm list
jcm show my-api

# 5. Remove when no longer needed
jcm remove my-api --dry-run
jcm remove my-api
```

## Chain selection

Use the global `--chain` flag (default: `root`).

| Value | What gets imported into `cacerts` |
|-------|-----------------------------------|
| `root` (default) | Root CA from the chain |
| `leaf` | Server (leaf) certificate |
| `intermediate` | All intermediate CAs |
| `full` | Entire chain sent by the server |
| `0`–`4` | Certificate at that index (0 = leaf) |

```bash
jcm add pinned https://pinned.example.com --chain leaf
jcm inspect https://pinned.example.com --graph --chain root
```

## Commands

| Command | Description |
|---------|-------------|
| `add <alias> <url>` | Import certificate(s) from URL as `jcm-<alias>` |
| `add … --dry-run` | Show import plan without modifying `cacerts` |
| `remove <alias>` | Remove `jcm-<alias>` from `cacerts` |
| `remove … --dry-run` | Show removal plan without modifying `cacerts` |
| `list` | List `jcm-*` entries in `cacerts` |
| `list --all` | List every entry in `cacerts` |
| `show <alias>` | Show `keytool` details for `jcm-<alias>` |
| `inspect <url>` | Inspect TLS certificates for a URL (read-only) |
| `inspect <url> --graph` | Print chain as an indented tree |

### Examples

```bash
jcm inspect https://example.com --graph
jcm add internal-api https://api.internal.example.com --dry-run
jcm add internal-api https://api.internal.example.com --chain root
jcm list
jcm show internal-api
jcm remove internal-api --dry-run
```

## Global options

| Option | Description |
|--------|-------------|
| `--java-home <path>` | JDK installation directory |
| `--cacerts <path>` | Keystore file (overrides `--java-home`) |
| `--store-pass <pass>` | Keystore password (default: `changeit`) |
| `--chain <mode>` | Chain selection for `add` / `inspect` |
| `--alias-prefix <pfx>` | Keystore alias prefix (default: `jcm-`) |
| `--elevate auto\|always\|never` | Privilege elevation for protected `cacerts` |
| `-q` / `-v` | Quiet (errors only) / verbose |

### Environment variables

| Variable | Purpose |
|----------|---------|
| `JAVA_HOME` | JDK used when `--java-home` is omitted |
| `JCM_STORE_PASS` | `cacerts` password |

## Elevation

System `cacerts` files are often owned by root / Administrators.

| OS | Behavior (`--elevate auto`, default) |
|----|----------------------------------------|
| **Linux / macOS** | Prompts for `sudo` when `cacerts` is not writable |
| **Windows** | Re-launches **jcm** with UAC elevation |

Read-only commands (`list`, `show`, `inspect`) never request elevation.

### Work without admin (recommended for local dev)

```bash
cp "$JAVA_HOME/lib/security/cacerts" ~/my-cacerts
jcm add my-api https://api.example.com --cacerts ~/my-cacerts
```

Point your JVM at the copy:

```bash
java -Djavax.net.ssl.trustStore=$HOME/my-cacerts -jar app.jar
```

## Safety

- **Managed aliases only:** imports use the prefix `jcm-` (e.g. `my-api` → keystore `jcm-my-api`).
- **Original CAs are never removed or changed** — `remove` only deletes `jcm-*` entries.
- **Per-operation check:** after each `add`/`remove`, **jcm** verifies that every non-`jcm-*` alias present before the operation is still in the keystore.

## CI/CD

Use a pre-built binary with a writable keystore copy:

```bash
cp "$JAVA_HOME/lib/security/cacerts" "$RUNNER_TEMP/cacerts"

jcm add my-api https://api.example.com \
  --dry-run \
  --cacerts "$RUNNER_TEMP/cacerts" \
  --elevate never

jcm add my-api https://api.example.com \
  --cacerts "$RUNNER_TEMP/cacerts" \
  --elevate never
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Operational error |
| `2` | Validation error |
| `3` | Pending changes (`add --dry-run` or `remove --dry-run`) |

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Development

Building, testing, and contributing: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
