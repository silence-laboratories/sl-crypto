use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    Limb, NonZero, Random, RandomMod, Uint, U1024,
};

use rand_core::CryptoRngCore;

mod primes_2048;

pub use primes_2048::PRIMES;
pub use primes_2048::RECIPROCALS;

fn miller_rabin<const L: usize>(rng: &mut impl CryptoRngCore, n: &Uint<L>, t: usize) -> bool {
    let n1 = n.wrapping_sub(&Uint::ONE);
    let s = n1.trailing_zeros(); // s >= 1
    let r = n1 >> s; //.shr_vartime(s);

    let m = DynResidueParams::new(n);
    let one = DynResidue::one(m);
    let m1 = -one;

    for _ in 0..t {
        let a = Uint::random_mod(rng, &NonZero::new(n1).unwrap());

        let a = DynResidue::new(&a, m);

        let mut y = a.pow(&r);

        if y == one || y == m1 {
            continue;
        }

        for _ in 1..s {
            y = y.square(); // y = y^2 mod N
            if y == one {
                return false;
            }

            if y == m1 {
                continue;
            }
        }

        return false;
    }

    true
}

fn rand_odd_uint<const L: usize>(rng: &mut impl CryptoRngCore) -> Uint<L> {
    let mut r = Uint::<L>::random(rng);

    let b = r.as_words_mut();
    let l = Uint::<L>::LIMBS - 1;

    b[l] |= 1 << (Limb::BITS - 1); // make it big enough
    b[0] |= 1; // and make it odd

    r
}

pub fn gen_prime<const L: usize>(rng: &mut impl CryptoRngCore, t: usize) -> Uint<L> {
    loop {
        let mut p = rand_odd_uint(rng);

        let limit: u16 = {
            let limit = Uint::MAX.wrapping_sub(&p);
            const LIMIT: u16 = u16::MAX / 2;

            if limit < Uint::from_u16(LIMIT) {
                limit.as_words()[0] as u16
            } else {
                LIMIT
            }
        };

        let mut residues = [0u16; 2048];

        for (residue, reciprocal) in residues.iter_mut().zip(&RECIPROCALS) {
            // r = N mod small-prime
            let (_, Limb(r)) = p.ct_div_rem_limb_with_reciprocal(reciprocal);
            *residue = r as u16;
        }

        let mut diff = 0u16;
        let mut incr = 0u16;

        'outer: while incr < limit {
            for (r, p) in residues.iter().zip(&PRIMES) {
                if r.wrapping_add(incr) % *p == 0 {
                    incr += 2;
                    continue 'outer;
                }
            }

            // never overflows because p + limit < Uint::MAX
            p = p.wrapping_add(&Uint::from_u16(incr - diff));

            diff = incr;

            if miller_rabin(rng, &p, t) {
                return p;
            }

            incr += 2;
        }
    }
}

pub fn gen_u1024(rng: &mut impl CryptoRngCore, t: usize) -> U1024 {
    gen_prime(rng, t)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn gen() {
        let mut rng = ChaCha8Rng::seed_from_u64(0x1234567AA);

        for _ in 0..100 {
            let _p = gen_u1024(&mut rng, 3);
            // println!("{p}");
        }
    }
}
