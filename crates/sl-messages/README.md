# `sl-messages`

Message transport and encoding primitives for MPC-style protocols.

This crate provides:

- `message`: deterministic message IDs (`MsgId`), tags, headers, and message allocation.
- `relay`: async relay abstraction (`Relay`) with in-memory, buffered, and optional mux/websocket backends.
- `signed`: typed signed message verification helpers.
- `encrypted`: encryption scheme abstractions and message builders.
- `setup` (feature-gated): protocol participant setup, round tracking, and abort-message validation.
  Includes `setup::keys` with no-op key/signature types for trusted transports.

## Features

Default features: `fast-ws`, `mux`, `setup`.

- `setup`: protocol-round helpers in `sl_messages::setup`.
- `mux`: relay multiplexer (`relay::mux`) for fan-in/fan-out message routing.
- `fast-ws`: websocket relay (`ws::FastRelay`) based on `fastwebsockets`.
- `simple-relay`: marker feature used by downstream integrations.

## Basic usage

Build a message ID and message bytes:

```rust
use std::time::Duration;
use sl_messages::message::{allocate_message, InstanceId, MessageTag, MsgId};

let instance = InstanceId::from([1u8; 32]);
let sender = [2u8; 32];
let id = MsgId::broadcast(&instance, &sender, MessageTag::tag(1));

let msg = allocate_message(&id, Duration::from_secs(10), 0, b"payload");
assert!(!msg.is_empty());
```

Use the in-memory relay:

```rust
use std::time::Duration;
use sl_messages::{
    message::{allocate_message, InstanceId, MessageTag, MsgId},
    relay::{Relay, SimpleMessageRelay},
};

# #[tokio::main]
# async fn main() {
let relay = SimpleMessageRelay::new();
let mut c1 = relay.connect();
let mut c2 = relay.connect();

let instance = InstanceId::from([3u8; 32]);
let sender = [4u8; 32];
let id = MsgId::broadcast(&instance, &sender, MessageTag::tag(7));

c1.ask(&id, Duration::from_secs(5)).await.unwrap();
c2.send(allocate_message(&id, Duration::from_secs(5), 0, b"hello"))
    .await
    .unwrap();

let received = c1.next().await.unwrap();
assert!(received.len() > 0);
# }
```

## Notes

- `BufferedMsgRelay` adds local buffering and predicate-based waiting (`wait_for`, `wait_for_limited`).
- Cancel safety of buffered waits depends on the cancel-safety guarantees of the wrapped relay implementation.

## License

See [LICENSE](../../LICENSE).
