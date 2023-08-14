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

## sl-oblivious

Base code for DKLs23
