# Published `0.2.0-pre.3` compatibility vector

These fixtures were generated with `sl-msg-encrypt = "=0.2.0-pre.3"`
downloaded from the `sl` registry configured in `~/.cargo/config.toml`:

```text
sparse+https://kellnr.silent.sg/api/v1/crates/
```

The registry package checksum recorded in `generator/Cargo.lock` is:

```text
bc42a9a2fdbbe75c4f2030a6c67cccb9deb1b2c731c997c4055e841dcfd98a43
```

The vector contains the receiver's ML-KEM-768 public key and the first
AES-256-GCM encrypted message from party 0 to party 1. The generator decrypts
and verifies the message with the published implementation before writing the
lowercase hexadecimal fixtures.

To regenerate the fixtures from the locked published dependencies, run from
this directory:

```sh
cargo run --manifest-path generator/Cargo.toml --release --locked -- .
```

Expected SHA-256 hashes:

```text
1f686ed7a50310d43712a6df2e43697fc5bca0b4050fc7fb00b2d03cad1c67b5  message.hex
85dbacfba03dcdd2b283377def6c3f4a66e10d00d7c84aa8ff3be9c738bd2b6e  receiver-public-key.hex
```
