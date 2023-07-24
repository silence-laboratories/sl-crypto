use std::ops::Deref;

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Encoding, NonZero, RandomMod, Split, Uint};
use crypto_bigint::{U1024, U2048, U4096};

use crypto_primes::prime_with_rng;

use rand_core::CryptoRngCore;

// #[cfg(test)]
// #[macro_use(quickcheck)]
// extern crate quickcheck_macros;

pub mod paillier {
    use super::*;

    // print-type-size type: `SK<64, 32, 16>`: 5400 bytes, alignment: 8 bytes
    // print-type-size     field `.phi`: 256 bytes
    // print-type-size     field `.inv_phi`: 256 bytes
    // print-type-size     field `.p`: 128 bytes
    // print-type-size     field `.hp`: 128 bytes
    // print-type-size     field `.q`: 128 bytes
    // print-type-size     field `.hq`: 128 bytes
    // print-type-size     field `.pk`: 2312 bytes
    // print-type-size     field `.pp_params`: 1032 bytes
    // print-type-size     field `.qq_params`: 1032 bytes

    pub type SK2048 = SK<{ U4096::LIMBS }, { U2048::LIMBS }, { U1024::LIMBS }>;
    pub type PK2048 = PK<{ U4096::LIMBS }, { U2048::LIMBS }>;
}

#[derive(Debug, PartialEq)]
pub struct RawPlaintext<const L: usize>(Uint<L>);

#[derive(Debug, PartialEq)]
pub struct RawCiphertext<const L: usize>(Uint<L>);

impl<const L: usize> RawCiphertext<L> {
    pub fn from(c: Uint<L>) -> Self {
        Self(c)
    }
}

impl<const L: usize> Default for RawCiphertext<L> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<const L: usize> Default for RawPlaintext<L> {
    fn default() -> Self {
        Self(Default::default())
    }
}

pub trait IntoRawPlaintext<const L: usize, T> {
    fn into_plaintext(self, msg: T) -> Option<RawPlaintext<L>>;
}

#[derive(Debug, Clone, Copy)]
pub struct PK<const C: usize, const M: usize> {
    n: NonZero<Uint<M>>,
    params: DynResidueParams<C>, // mod N^2
}

#[derive(Debug)]
pub struct SK<const C: usize, const M: usize, const P: usize> {
    pk: PK<C, M>,
    phi: Uint<M>,
    inv_phi: Uint<M>,
    p: Uint<P>,
    hp: Uint<P>,
    q: Uint<P>,
    hq: Uint<P>,
    pinv_q: Uint<P>,
    pp_params: DynResidueParams<M>,
    qq_params: DynResidueParams<M>,
}

impl<const C: usize, const M: usize, const P: usize> SK<C, M, P>
where
    Uint<C>: Split<Output = Uint<M>>,
    Uint<C>: From<(Uint<M>, Uint<M>)>,
    Uint<M>: From<(Uint<P>, Uint<P>)>,
    Uint<M>: Encoding + Split<Output = Uint<P>>,
{
    pub fn gen_pq(rng: &mut impl CryptoRngCore) -> (Uint<P>, Uint<P>) {
        let q = prime_with_rng::<P>(rng, Uint::<P>::BITS);
        let p = prime_with_rng::<P>(rng, Uint::<P>::BITS);

        (p, q)
    }

    pub fn gen(rng: &mut impl CryptoRngCore) -> Self {
        let (p, q) = Self::gen_pq(rng);

        SK::from_pq(&p, &q)
    }

    pub fn from_pq(p: &Uint<P>, q: &Uint<P>) -> Self {
        // N = pq
        let n: Uint<M> = q.mul_wide(p).into();
        let pk = PK::from_n(&n);

        // phi = (q-1)(p-1)
        let phi: Uint<M> = q
            .wrapping_sub(&Uint::ONE)
            .mul_wide(&p.wrapping_sub(&Uint::ONE))
            .into();

        // inv_phi = phi^-1 mod N
        let inv_phi = phi.inv_odd_mod(&pk.n).0;

        let pinv_q = p.inv_odd_mod(q).0;

        let pp: Uint<M> = p.square_wide().into();
        let pp_params = DynResidueParams::new(&pp);
        let hp = Self::h(p, pp_params.modulus(), &n);

        let qq: Uint<M> = q.square_wide().into();
        let qq_params = DynResidueParams::new(&qq);
        let hq = Self::h(q, qq_params.modulus(), &n);

        SK {
            phi,
            inv_phi,
            pk,
            p: *p,
            hp,
            pp_params,
            q: *q,
            pinv_q,
            hq,
            qq_params,
        }
    }

    pub fn public_key(&self) -> PK<C, M> {
        PK {
            n: self.pk.n,
            params: self.pk.params,
        }
    }

    pub fn decrypt(&self, c: &RawCiphertext<C>) -> RawPlaintext<M> {
        let c = DynResidue::new(&c.0, self.params);

        // m = (c^phi mod N^2 - 1) / N
        let m: Uint<M> = c
            .pow_bounded_exp(&self.phi.resize(), Uint::<M>::BITS)
            .retrieve()
            .wrapping_sub(&Uint::ONE)
            .wrapping_div(&self.n.resize::<C>())
            .resize(); // drop top half of the value

        // m = (m * phi^-1) mod N

        // m_mod_n = m mod N
        let m_mod_n = m.const_rem(&self.n).0;

        // (lo, hi) = m_n * phi^-1
        let (lo, hi) = m_mod_n.mul_wide(&self.inv_phi);

        // final reduce by N, variable time by N, but it's public value
        RawPlaintext(Uint::const_rem_wide((lo, hi), &self.n).0)
    }

    pub(crate) fn h(p: &Uint<P>, pp: &Uint<M>, n: &Uint<M>) -> Uint<P> {
        // h = L_p(g^{p-1} mod p^2)^-1 mod p
        //
        // L_p (x) = (x-1) / p
        //
        // n == p*q
        //
        //    (1 + n)^{p-1}  mod p^2
        // =   1 + n(p-1)    mod p^2
        // =   1 - n + np    mod p^2
        // =   1 - n + qp^2  mod p^2
        // =   1 - n         mod p^2
        //

        let n_mod_pp = n.const_rem(pp).0; // should be fast because N and p^2 are close

        Uint::ONE
            .sub_mod(&n_mod_pp, pp)
            .wrapping_sub(&Uint::ONE) // L_p(x) = (x-1)/p
            .wrapping_div(&p.resize()) // FIXME: var time on P
            .inv_odd_mod_bounded(&p.resize(), Uint::<M>::BITS, Uint::<P>::BITS)
            .0
            .resize() // dropping top half of bits
    }

    fn mp(&self, cp: Uint<M>, p: &Uint<P>, hp: &Uint<P>, param: &DynResidueParams<M>) -> Uint<P> {
        // L_p(cp^{p-1} mod p^2) h_p mod p

        let mp: Uint<P> = DynResidue::new(&cp, *param)
            .pow_bounded_exp(&p.wrapping_sub(&Uint::ONE).resize(), Uint::<P>::BITS)
            .retrieve()
            .wrapping_sub(&Uint::ONE) // Lp(x) = (x-1)/p
            .wrapping_div(&p.resize())
            .resize();

        let x: Uint<P> = mp.const_rem(p).0;

        Uint::const_rem_wide(x.mul_wide(hp), p).0
    }

    pub fn decrypt_fast(&self, c: &RawCiphertext<C>) -> RawPlaintext<M> {
        let pp = self.pp_params.modulus();
        let qq = self.qq_params.modulus();

        let (cp, cq) = decompose(&c.0, pp, qq);

        let mp = self.mp(cp, &self.p, &self.hp, &self.pp_params);
        let mq = self.mp(cq, &self.q, &self.hq, &self.qq_params);

        RawPlaintext(recombine(&self.pinv_q, &mp, &mq, &self.p, &self.q))
    }
}

impl<const C: usize, const M: usize, const P: usize> Deref for SK<C, M, P> {
    type Target = PK<C, M>;

    fn deref(&self) -> &Self::Target {
        &self.pk
    }
}

pub fn decompose<const C: usize, const M: usize>(
    c: &Uint<C>,
    p: &Uint<M>,
    q: &Uint<M>,
) -> (Uint<M>, Uint<M>)
where
    Uint<C>: Split<Output = Uint<M>>,
{
    let (hi, lo) = c.split();

    let cp: Uint<M> = Uint::const_rem_wide((lo, hi), p).0;
    let cq: Uint<M> = Uint::const_rem_wide((lo, hi), q).0;

    (cp, cq)
}

// Algo 14.71 with Note 14.75 (i)
pub fn recombine<const M: usize, const P: usize>(
    c_2: &Uint<P>,
    v_1: &Uint<P>,
    v_2: &Uint<P>,
    p: &Uint<P>,
    q: &Uint<P>,
) -> Uint<M>
where
    Uint<M>: From<(Uint<P>, Uint<P>)>,
{
    // C_2 = p^-1 mod q
    // let c_2 = p.inv_odd_mod(q).0;

    // d = (v_2 - v_1) mod q
    let d = v_2.sub_mod(v_1, q);

    // u = (v_2 - v_1) C_2 mod q
    let u: Uint<P> = Uint::const_rem_wide(d.mul_wide(&c_2), q).0;

    // x = v_1 + u p
    Uint::from(u.mul_wide(p)).wrapping_add(&v_1.resize())
}

impl<const C: usize, const M: usize> PK<C, M>
where
    Uint<C>: From<(Uint<M>, Uint<M>)>,
    Uint<M>: Encoding,
{
    pub fn from_n(n: &Uint<M>) -> Self {
        // We generate N as half of L, so hi part of n.square_wide() is zero
        let nn = n.square_wide().into();
        let params = DynResidueParams::new(&nn);

        Self {
            n: NonZero::new(*n).unwrap(),
            params,
        }
    }

    pub fn get_n(&self) -> &Uint<M> {
        &self.n
    }

    pub fn get_nn(&self) -> &Uint<C> {
        self.params.modulus()
    }

    pub fn gen_r(&self, rng: &mut impl CryptoRngCore) -> Uint<M> {
        loop {
            let r = Uint::random_mod(rng, &self.n);

            if !r.eq(&Uint::ZERO) {
                break r;
            }
        }
    }

    pub fn message(&self, bytes: &[u8]) -> Option<RawPlaintext<M>> {
        let size = std::cmp::min(Uint::<M>::BYTES, bytes.len());

        let mut buf = Uint::<M>::default().to_le_bytes();

        buf.as_mut()[..size].copy_from_slice(&bytes[..size]);

        let m = Uint::<M>::from_le_slice(buf.as_ref());

        self.into_message(&m)
    }

    pub fn into_message(&self, m: &Uint<M>) -> Option<RawPlaintext<M>> {
        m.lt(&self.n).then_some(RawPlaintext(*m))
    }

    pub fn encrypt(&self, m: &RawPlaintext<M>, rng: &mut impl CryptoRngCore) -> RawCiphertext<C> {
        let r = self.gen_r(rng);
        self.encrypt_with_r(m, &r)
    }

    pub fn encrypt_with_r(&self, m: &RawPlaintext<M>, r: &Uint<M>) -> RawCiphertext<C> {
        let r = DynResidue::new(&r.resize(), self.params);

        // r^N mod N^2
        let r_pow_n = r.pow_bounded_exp(&self.n.resize(), Uint::<M>::BITS);

        //
        // g == (1 + N)
        //
        // 0 <= m < N
        //
        // (1+ N)^m mod N^2 = 1 + m*N mod N^2
        //
        // 1 + m*N <= 1 + N^2 - N < N^2
        //
        let g_pow_m = DynResidue::new(
            &Uint::<C>::from(m.0.mul_wide(&self.n)).wrapping_add(&Uint::ONE),
            self.params,
        );

        // c = g^m * r^N mod N^2
        let c = g_pow_m.mul(&r_pow_n);

        RawCiphertext(c.retrieve())
    }

    pub fn add(&self, c_1: &RawCiphertext<C>, c_2: &RawCiphertext<C>) -> RawCiphertext<C> {
        // c_1 * c_2 mod N^2
        let c_1 = DynResidue::new(&c_1.0, self.params);
        let c_2 = DynResidue::new(&c_2.0, self.params);

        RawCiphertext(c_1.mul(&c_2).retrieve())
    }

    pub fn mul(&self, c: &RawCiphertext<C>, m: &RawPlaintext<M>) -> RawCiphertext<C> {
        // c = c^m mod N^2
        let c = DynResidue::new(&c.0, self.params)
            .pow_bounded_exp(&m.0.resize(), Uint::<M>::BITS)
            .retrieve();

        RawCiphertext(c)
    }

    pub fn mul_vartime(&self, c: &RawCiphertext<C>, m: &RawPlaintext<M>) -> RawCiphertext<C> {
        let bits = m.0.bits_vartime();

        // c = c^m mod N^2
        let c = DynResidue::new(&c.0, self.params)
            .pow_bounded_exp(&m.0.resize(), bits)
            .retrieve();

        RawCiphertext(c)
    }
}

// #[cfg(test)]
// #[macro_use(quickcheck)]
// extern crate quickcheck_macros;

#[cfg(test)]
mod tests {

    use quickcheck::quickcheck;

    use super::*;
    use crypto_bigint::{U1024, U2048, U4096};
    use rand;

    static P: &str = "95779f0de6b61f3db4c53b1b32aa29e2efb52ebedab7968c37cb10917767547963a121d454c8024dc56f22c523da2dff553ad8a1621ad8f0c093ad09561165fce74fdf977ab1b5f57b4cdcce58f449bcce50cd80359ed0ec4083000c091fbb237e52b8237438ea82932ad0ed7d58fae54ea300461755a0dabc41b5e46af4cee1";
    static Q: &str = "a80137484b2e0082dbcc520642ea0fcff5652a2367084c052c340b15f0c3ecfeb334024e28e5a982c8971d06f332fc2e91ca985ee37a8e51daa2bae16841b75617a43b52fecea902c5858276ef3ab5282a0635ef34579d5ea2de61bd56f4d7ec26afbcb8ae127c4bc5c0a5799a48d41565a7656fffa056ac3b73ccb3fd0098d1";
    static R: &str = "1a8b6c80c0cad628e4146e473d49b90b445d09e9a7934431c5cb3e7a43b162018e50b116ed8a0ebaf4b8907a18ad30edfbf573614ededd1bc763265be3a6eeef307d40c2431fa9970590fecd7c8af25d599b513749f998c1ba7a64caeedb2d5dd034f718b9efdf5cf62b129459134b257cf28c61bbe40fc4c20caec7c58b9fa4fa4aea0e2164a398a3c2a21cd012aee7bba3f502b9b10680a36e615d81ef690346d33c05966415c0bff5e6f856ca2bca5786947cca9adfd8300cbf0d2d6f0d4c848b21f46961443fb4519b8ee2dae018c586afe0ee0f430fde643e423cce0cf56f0a59baf6652b250ef6184ffcf09039d34e0a2e0d95c3b24295929e3db4d5f4";

    lazy_static::lazy_static! {
        static ref SK: paillier::SK2048 = {
            let p: U1024 = from_hex(P);
            let q: U1024 = from_hex(Q);

            paillier::SK2048::from_pq(&p, &q)
        };

        static ref RU: U2048 = from_hex(R);
    }

    fn from_hex<const L: usize>(h: &str) -> Uint<L> {
        let mut r = Uint::<L>::ZERO;

        assert!(h != "");

        let total = (h.len() + 15) / 16; // round up

        let head = h.len() % 16;

        assert!(total <= L);

        if head == 0 && total == L {
            return Uint::<L>::from_be_hex(h);
        }

        let mut h = h.as_bytes();
        let mut i = total - 1;

        let limbs = r.as_words_mut();

        if head != 0 {
            let b = &h[..head];
            let s = std::str::from_utf8(b).unwrap();

            limbs[i] = u64::from_str_radix(s, 16).unwrap();
            i = i - 1;
            h = &h[head..];
        }

        for b in h.chunks(16) {
            let s = std::str::from_utf8(b).unwrap();
            limbs[i] = u64::from_str_radix(s, 16).unwrap();
            i = i - 1;
        }

        r
    }

    #[test]
    fn add() {
        fn prop(x: u64, y: u64) -> bool {
            let mx = SK.into_message(&Uint::from_u64(x)).unwrap();
            let my = SK.into_message(&Uint::from_u64(y)).unwrap();

            let c1 = SK.encrypt_with_r(&mx, &RU);
            let c2 = SK.encrypt_with_r(&my, &RU);

            let c3 = SK.add(&c1, &c2);

            let mr = SK.decrypt_fast(&c3);

            mr == RawPlaintext(Uint::from_u64(x).wrapping_add(&Uint::from_u64(y)))
        }

        quickcheck(prop as fn(u64, u64) -> bool)
    }

    #[test]
    fn mul() {
        fn prop(x: u64, y: u64) -> bool {
            let mx = SK.into_message(&Uint::from_u64(x)).unwrap();

            let c1 = SK.encrypt_with_r(&mx, &RU);

            let c3 = SK.mul(&c1, &RawPlaintext(Uint::from_u64(y)));

            let mr = SK.decrypt_fast(&c3);

            mr == RawPlaintext(Uint::from_u64(x).wrapping_mul(&Uint::from_u64(y)))
        }

        quickcheck(prop as fn(u64, u64) -> bool)
    }

    #[test]
    fn big() {
        let n = SK.get_n();
        let m = n.wrapping_sub(&Uint::ONE);

        let m = SK.into_message(&m).unwrap();

        let c = SK.encrypt_with_r(&m, &n.wrapping_sub(&Uint::ONE));

        let d = SK.decrypt(&c);

        assert_eq!(m, d);

        let d = SK.decrypt_fast(&c);

        assert_eq!(m, d);
    }

    #[test]
    fn decrypt() {
        let mut rng = rand::thread_rng();

        let r = SK.gen_r(&mut rng); // random R

        // check that decrypt(encrypt(0)) == 0
        let m = SK.into_message(&Uint::ZERO).unwrap();
        let c = SK.encrypt_with_r(&m, &r);
        let d = SK.decrypt(&c);

        assert_eq!(d, m);

        let d = SK.decrypt_fast(&c);

        assert_eq!(d, m);

        // now test random M in range [1 ..N)
        for _ in 0..20 {
            let m = SK.gen_r(&mut rng);
            let m = SK.into_message(&m).unwrap();

            let c = SK.encrypt_with_r(&m, &r);
            let d = SK.decrypt(&c);

            assert_eq!(d, m);

            let d = SK.decrypt_fast(&c);

            assert_eq!(d, m);
        }
    }

    #[test]
    fn small() {
        // numbers from handbook
        const P: u8 = 11;
        const Q: u8 = 17;
        const M: u8 = 175;
        const R: u8 = 83;
        const N: u8 = P * Q;

        let pk = paillier::PK2048::from_n(&N.into());

        let m = pk.message(&[M]).unwrap();

        let c = pk.encrypt_with_r(&m, &R.into());

        assert_eq!(c, RawCiphertext::from(U4096::from_u64(23911u64)));

        let sk = paillier::SK2048::from_pq(&11u8.into(), &17u8.into());

        assert_eq!(sk.decrypt(&c), m);
        assert_eq!(sk.decrypt_fast(&c), m);

        let c2 = pk.add(&c, &c);

        let m2 = (M as u32 + M as u32) % (N as u32);

        assert_eq!(sk.decrypt(&c2), pk.message(&[m2 as u8]).unwrap());
        assert_eq!(sk.decrypt_fast(&c2), pk.message(&[m2 as u8]).unwrap());

        let c3 = pk.mul(&c, &pk.message(&[3u8]).unwrap());

        let m3 = ((M as u32) * 3) % (N as u32);

        assert_eq!(sk.decrypt(&c3), pk.message(&[m3 as u8]).unwrap());
    }

    #[test]
    #[ignore]
    fn gen() {
        let mut rng = rand::thread_rng();

        let (p, q) = paillier::SK2048::gen_pq(&mut rng);

        let sk = paillier::SK2048::from_pq(&p, &q);

        let r: U2048 = sk.gen_r(&mut rng);

        println!("P {p:x}");
        println!("Q {q:x}");
        println!("R {r:x}");
        println!("N {}", sk.get_n());
    }
}
