use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto_bigint::*;
use crypto_primes::prime_with_rng;

use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use sl_primes::gen_prime;

pub fn sl_prime_1024(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0x1234567AA);

    c.bench_function("sl-prime-1024", |b| {
        b.iter(|| {
            let p: U1024 = gen_prime(black_box(&mut rng), black_box(3));
            black_box(&p);
        })
    });
}

pub fn cr_prime_1024(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0x1234567AA);

    c.bench_function("cr-prime-1024", |b| {
        b.iter(|| {
            let p: U1024 = prime_with_rng(black_box(&mut rng), black_box(1024));
            black_box(&p);
        })
    });
}

criterion_group!(sl_benches, sl_prime_1024, cr_prime_1024);

criterion_main!(sl_benches);
