# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial implementation of keychain API for managing TLS certificates and keys
- Filesystem-based backend (`grisp_keychain_filesystem`) for certificate management
- Support for client certificates and private keys
- Support for trusted certificate authorities (client and server)
- Configurable TLS verification modes (`verify_peer` and `verify_none`)
- Domain-specific server certificate loading
- Callback functions for dynamic certificate loading
- Path specification support for absolute paths and application-relative paths
- Automatic loading of certificates from directories
- Support for PEM format certificates and keys (`.pem` and `.crt` extensions)
- Public API functions:
  - `tls_options/1` - Get TLS options for a specific domain
  - `read_cert/2` - Read primary client certificate in DER format


[Unreleased]: https://github.com/grisp/grisp_keychain/compare/404eb05fcd0654c496caaca6f961142305792d99...HEAD
