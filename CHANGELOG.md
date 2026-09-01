# Changelog

This changelog follows the [keep a changelog](https://keepachangelog.com/en/1.1.0/)
format. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `ReqSSRF.attach/2`, which checks every hop of a `Req` request and halts
  it with `ReqSSRF.BlockedError` if the URL may not be fetched.
- Add `ReqSSRF.check/2` and `ReqSSRF.allowed?/2` for validating a single URL,
  and `ReqSSRF.public_address?/1` for a single IP address.

[Unreleased]: https://github.com/scoville/req_ssrf/commits/main
