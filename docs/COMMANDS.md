# jcm — command reference

Import TLS certificates from URLs into the JVM `cacerts` keystore under `jcm-*` aliases.

**Subcommands:** `add` · `remove` · `list` · `show` · `inspect`

**jcm** does not create a data directory or persist state. The keystore is the only source of truth. Temporary PEM files are written to the OS temp directory and removed when the command finishes.

---

## Global flags

| Flag | Description |
|------|-------------|
| `-q, --quiet` | Errors only |
| `-v, --verbose` | Verbose output (includes external commands such as `keytool`) |
| `--java-home <path>` | JDK path (or set `JAVA_HOME`) |
| `--cacerts <path>` | Keystore file (default: `$JAVA_HOME/lib/security/cacerts`) |
| `--store-pass <pass>` | Keystore password (default: `changeit`) |
| `--chain <mode>` | Chain selection: `root`, `leaf`, `intermediate`, `full`, `0`–`4` |
| `--alias-prefix <pfx>` | Alias prefix (default: `jcm-`) |
| `--elevate auto\|always\|never` | Elevation for protected `cacerts` |

---

## `add`

Import certificate(s) from a URL into `cacerts`.

```bash
jcm add <alias> <url> [--dry-run]
```

| Flag | Description |
|------|-------------|
| `--dry-run` | Show the plan without modifying `cacerts` (exit `3` if changes would occur) |

**Dry-run example:**

```text
would add api from https://api.example.com (chain=root)
  jcm-api | CN=Example Root CA | AA:BB:CC:...
```

**Behaviour:**

1. Connect to the URL and fetch the TLS certificate chain.
2. Apply `--chain` to select which certificate(s) to import.
3. Create `jcm-<alias>` keystore entries (or variants for `intermediate` / `full`).
4. Write temporary PEM files to `$TMP/jcm-<pid>-<nanos>/` — removed when the command finishes.
5. After import, verify that all non-`jcm-*` aliases present before the operation remain in the keystore.

---

## `remove`

Remove `jcm-*` entries from `cacerts`.

```bash
jcm remove <alias> [--dry-run]
```

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would be removed (exit `3` if removal would occur) |

Resolves keystore aliases by naming convention: `jcm-<alias>`, `jcm-<alias>-0`, `jcm-<alias>-int-0`, etc.

**Dry-run example:**

```text
would remove api
  jcm-api
```

---

## `list`

List entries in `cacerts`.

```bash
jcm list [--all]
```

| Flag | Description |
|------|-------------|
| `--all` | Every keystore entry (default: `jcm-*` only) |

---

## `show`

Show details for an alias in `cacerts`.

```bash
jcm show <alias>
```

Output of `keytool -list -v -alias jcm-<alias>`. For a live TLS chain tree, use `jcm inspect <url> --graph`.

---

## `inspect`

Inspect TLS certificates for a URL (read-only).

```bash
jcm inspect <url> [--graph]
```

Does not modify `cacerts` or write any files to disk (beyond OS temp during TLS fetch internals).

| Flag | Description |
|------|-------------|
| `--graph` | Indented chain tree; highlights certificates selected by `--chain` |

---

## Inline diagnostics

Errors include actionable context:

```text
error: cacerts is not writable: /Library/Java/.../cacerts
hint: run with --elevate auto on add/remove
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Operational error |
| `2` | Validation error |
| `3` | Pending changes (`add --dry-run` or `remove --dry-run`) |

---

## Removed commands

`sync`, `diff`, `status`, `verify`, `export-pem`, `backup`, `restore`, `init`, `doctor`, `config`

Previous versions also wrote state to `~/.jcm/state/default.json` — that is no longer used.
