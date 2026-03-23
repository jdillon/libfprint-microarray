# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-03-23

### Added

- Full libfprint driver for MicroarrayTechnology MAFP (USB 3274:8012) fingerprint sensor
- Enrollment workflow: 6-stage press/lift cycle with template storage to device flash
- Verify (1:1 match) for enrolled fingerprints
- Finger-present detection via GET_IMAGE polling (CMD 0x01)
- Per-enrollment device handshake (CMD 0x23) to reset session state
- Device flash management: bitmap parsing (CMD 0x1F) to track available FID slots
- Template storage (CMD 0x06) and retrieval (CMD 0x66)
- Skip unnecessary flash clears when free FID slots are available
- Full protocol documentation from Windows driver reverse engineering
- MIT license

[1.0.0]: https://github.com/jdillon/libfprint-microarray/releases/tag/v1.0.0
