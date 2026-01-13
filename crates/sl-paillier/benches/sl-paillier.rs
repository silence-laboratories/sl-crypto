// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto_bigint::*;

static P: &str = "95779f0de6b61f3db4c53b1b32aa29e2efb52ebedab7968c37cb10917767547963a121d454c8024dc56f22c523da2dff553ad8a1621ad8f0c093ad09561165fce74fdf977ab1b5f57b4cdcce58f449bcce50cd80359ed0ec4083000c091fbb237e52b8237438ea82932ad0ed7d58fae54ea300461755a0dabc41b5e46af4cee1";
static Q: &str = "a80137484b2e0082dbcc520642ea0fcff5652a2367084c052c340b15f0c3ecfeb334024e28e5a982c8971d06f332fc2e91ca985ee37a8e51daa2bae16841b75617a43b52fecea902c5858276ef3ab5282a0635ef34579d5ea2de61bd56f4d7ec26afbcb8ae127c4bc5c0a5799a48d41565a7656fffa056ac3b73ccb3fd0098d1";
static R: &str = "1a8b6c80c0cad628e4146e473d49b90b445d09e9a7934431c5cb3e7a43b162018e50b116ed8a0ebaf4b8907a18ad30edfbf573614ededd1bc763265be3a6eeef307d40c2431fa9970590fecd7c8af25d599b513749f998c1ba7a64caeedb2d5dd034f718b9efdf5cf62b129459134b257cf28c61bbe40fc4c20caec7c58b9fa4fa4aea0e2164a398a3c2a21cd012aee7bba3f502b9b10680a36e615d81ef690346d33c05966415c0bff5e6f856ca2bca5786947cca9adfd8300cbf0d2d6f0d4c848b21f46961443fb4519b8ee2dae018c586afe0ee0f430fde643e423cce0cf56f0a59baf6652b250ef6184ffcf09039d34e0a2e0d95c3b24295929e3db4d5f4";
static M: &str = "1234567890abcdefffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

type SK = sl_paillier::SK2048;
type PK = sl_paillier::PK2048;

fn from_hex<const L: usize>(h: &str) -> Uint<L> {
    let mut res = Uint::<L>::ZERO;

    assert!(h.len() % (8 * 2) == 0); // sequence of whole 64 bit limbs

    let size = h.len() / 16;

    assert!(size <= L);

    if size == L {
        return Uint::<L>::from_be_hex(h);
    }

    let limbs = res.as_words_mut();
    let mut i = size - 1;

    for b in h.as_bytes().chunks(16) {
        let s = std::str::from_utf8(b).unwrap();
        limbs[i] = u64::from_str_radix(s, 16).unwrap();
        i -= 1;
    }

    res
}

fn sl_pk() -> (U2048, PK) {
    let r: U2048 = from_hex(R);
    let p: U1024 = from_hex(P);
    let q: U1024 = from_hex(Q);
    let n = p.mul_wide(&q).into();

    let pk = PK::from_n(&n);

    (r, pk)
}

fn sl_gen_sk(c: &mut Criterion) {
    let p: U1024 = from_hex(P);
    let q: U1024 = from_hex(Q);

    c.bench_function("sl-gen-sk", |b| {
        b.iter(|| black_box(SK::from_pq(&p, &q)))
    });
}

fn sl_encrypt(c: &mut Criterion) {
    let (r, pk) = sl_pk();
    let msg = pk.message(M.as_bytes()).unwrap();

    c.bench_function("sl-encrypt", |b| {
        b.iter(|| {
            black_box(pk.encrypt_with_r(&msg, &r));
        })
    });
}

pub fn sl_add(c: &mut Criterion) {
    let (r, pk) = sl_pk();

    let m: U2048 = from_hex(M);
    let m = pk.into_message(&m).unwrap();

    let ct = pk.encrypt_with_r(&m, &r);

    c.bench_function("sl-add", |b| {
        b.iter(|| {
            black_box(pk.add(&ct, &ct));
        })
    });
}

fn sl_mul(c: &mut Criterion) {
    let (r, pk) = sl_pk();

    let m: U2048 = from_hex(M);
    let m = pk.into_message(&m).unwrap();
    let m2 = pk.into_message(&r).unwrap();
    let c1 = pk.encrypt_with_r(&m, &r);

    c.bench_function("sl-mul", |b| {
        b.iter(|| {
            black_box(pk.mul(&c1, &m2));
        })
    });

    c.bench_function("sl-mul-vartime", |b| {
        b.iter(|| {
            black_box(pk.mul_vartime(&c1, &m2));
        })
    });
}

fn sl_decrypt(c: &mut Criterion) {
    let r: U2048 = from_hex(R);
    let p: U1024 = from_hex(P);
    let q: U1024 = from_hex(Q);

    let sk = SK::from_pq(&p, &q);
    let msg = sk.message(M.as_bytes()).unwrap();
    let ct = sk.encrypt_with_r(&msg, &r);

    c.bench_function("sl-decrypt", |b| {
        b.iter(|| {
            black_box(sk.decrypt(&ct));
        })
    });

    c.bench_function("sl-decrypt-fast", |b| {
        b.iter(|| {
            black_box(sk.decrypt_fast(&ct));
        })
    });
}

criterion_group!(
    sl_benches, sl_gen_sk, sl_encrypt, sl_decrypt, sl_add, sl_mul
);

criterion_main!(sl_benches);
