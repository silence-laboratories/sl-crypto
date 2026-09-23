# Published `sl-messages 1.3.0-pre.1` compatibility vector

These fixtures were generated with the latest published `sl-messages` version
reported by crates.io:

```toml
sl-messages = { version = "=1.3.0-pre.1", default-features = false, features = ["encrypted"] }
```

The crates.io package checksum recorded in `generator/Cargo.lock` is:

```text
e54aeea5765d7fa65dbe33cd40727518e1e5c8655749c024f76e8ed8fca285af
```

The vector contains deterministic sender and receiver X25519 public keys and a
ChaCha20-Poly1305 encrypted framed message. It exercises the message header,
additional authenticated data, fixed-size body, and variable-size trailer.
The generator decrypts and verifies the message with the published
implementation before writing the lowercase hexadecimal fixtures.

To regenerate the fixtures from the locked published dependencies, run from
this directory:

```sh
cargo run --manifest-path generator/Cargo.toml --release --locked -- .
```

Expected SHA-256 hashes:

```text
116c85f9c9c8c4e82c7a345c992a20f71efec09fcb81e8ff60f1d08170982b92  message.hex
df84e24860d5a2333df79268d77e8b4ac662b0fd8210881b364ca3edb9403bea  receiver-public-key.hex
c66cf0e0bded9f39473016e56147794080dea61a13cd978ccc2ca08b1395b825  sender-public-key.hex
```
