# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-06

### Added

- Initial release: `add`, `remove`, `list`, `show`, and `inspect` commands
- Cross-platform support for Linux, macOS, and Windows
- Dry-run mode, chain selection, and privilege elevation (sudo / UAC)
- Built-in TLS chain fetch via rustls (no OpenSSL CLI required)
- Managed `jcm-*` alias prefix with built-in CA protection checks
