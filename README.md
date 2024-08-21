# sl-crypto

This repo contains libraries:

## sl-paillier

Implemention of Paillier encryption using fixed with big numbers
from crypto-binint crate. This implemenation is slower that kzen-paillier
but it is pure Rust and use constant-time computations.

Also it is GPL/LGPL free.

## sl-mpc-mate

Implementation of new "messaging scheme". Implements message relay or
async coordinator.

Key modules and types:

```rust
message::MsgId
message::Builder::<Signed>::encode(id, ttl, key, payload)
message::builder::<Encrypted>::encode(id, ttl, key, payload)

message::Message::from_buffer(&mut buffer)
message::Message::verify_and_decode()
message::Message::decrypt_and_decode()

coord::Relay
coord::SimpleMessageRelay
```

## sl-oblivious

Base code for DKLs23

## sl-verifiable-enc

Verifiable encryption library

Refer to it's [readme](/crates/sl-verifiable-enc/README.md) for usage



