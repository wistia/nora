# Test fixtures

`jason.record` is the original gzipped signed package record fetched from
https://repo.hex.pm/packages/jason on 2026-10-26. `jason-1.4.4.tar` is the original
archive from https://repo.hex.pm/tarballs/jason-1.4.4.tar. It is checked against the
signed outer checksum in the Rust tests. Jason is copyright Michał Muskała,
licensed under Apache-2.0; its original license is included in the archive and
copied here as `JASON-LICENSE`.

`test-private.pem` and `test-public.pem` are deliberately public, disposable test
keys generated for these fixtures. They are never a production trust anchor.
They let automated tests construct independently signed timestamps/invalid records
without weakening client signature verification or changing the official key.

Rust protobuf views implement the official Hex specifications:
https://github.com/hexpm/specifications/tree/main/registry
The bundled production key is copied from the official Hex 2.6.0 client:
https://github.com/hexpm/hex/blob/v2.6.0/lib/hex/repo.ex
