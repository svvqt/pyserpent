# Changelog

# Changelog

## [1.2.0] - 2026-03-29

### Breaking Changes
- CBC mode: IV is now automatically prepended to ciphertext in `serpent_cbc_encrypt`.
  Data encrypted with v1.1.0 and earlier is not compatible with `serpent_cbc_decrypt` 
  without migration. See README for migration guide.

### Changed
- `serpent_cbc_encrypt` now accepts `iv=None` and generates a secure random IV automatically.
- `serpent_cbc_decrypt` no longer accepts `iv` parameter — IV is read from the first 16 bytes of ciphertext.

### Security
- Fixed: default IV was `b'\x00' * 16`, which is cryptographically unsafe. IV is now generated via `os.urandom(16)`.

## [1.1.0] - 2026-03-23
### Changed
- Refactor Serpent algorithm.