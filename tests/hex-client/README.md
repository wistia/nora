# Real Mix app smoke

Requires Elixir/OTP, Mix, Python 3, OpenSSL, network access for Hex bootstrap, and
a built Nora binary. Normal Rust CI does not run this live smoke.

```sh
cargo build --locked -p nora-registry --bin nora
python3 tests/hex-client/run.py
# Also test the real S3 backend using a disposable MinIO container:
python3 tests/hex-client/run.py --s3
# A client without native cooldown support:
python3 tests/hex-client/run.py --hex-version 2.2.1 --skip-public
```

`--binary PATH` selects another Nora binary. The fixture app pins Jason 1.4.4 and
asserts JSON decoding before printing success. Every case has a fresh app,
dependency directory and Hex home. Both signature and origin verification remain
enabled; the script prints the effective Hex configuration.

Cases: public cold install/compile/run with a seven-day policy; Nora restart and
fresh-client offline install (including an uncached request proving upstream
access is disabled); one-day-old locked and pinned releases rejected with 403
while client cooldown is disabled; eight-day-old release accepted. A controlled
upstream re-signs the original Jason metadata after changing only publication
timestamps. Only fixture cases explicitly trust the fixture public key, in their
isolated Hex homes. No user-global Hex/Mix configuration is changed.

The S3 option requires Docker, AWS CLI and the specified MinIO image (downloaded
by Docker if absent). It binds MinIO only on localhost, uses test-only credentials,
creates disposable buckets and removes the container afterward. Nora restarts
reuse the bucket to verify persisted signed metadata and tarballs.

Temporary servers/config/caches are cleaned up. Diagnostic server logs and JSON
outcomes are retained under ignored `.state/`. No live service deployment occurs.
See [verification results](VERIFICATION.md).
