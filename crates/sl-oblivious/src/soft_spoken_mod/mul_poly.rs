///     Multiplies `a` and `b` in the finite field of order 2^128
///     modulo the irreducible polynomial f(x) = 1 + x + x^2 + x^7 + x^128

///     https://link.springer.com/book/10.1007/b97644
///     multiplication part: Algorithm 2.34, "Right-to-left comb method for polynomial multiplication"
///     reduction part: variant of the idea of Figure 2.9
pub fn binary_field_multiply_gf_2_128(a_data: [u8; 16], b_data: [u8; 16]) -> [u8; 16] {
    const W: usize = 8;
    const T: usize = 16;
    let mut c = [0u8; T * 2];
    let mut a = [0u8; T];
    let mut b = [0u8; T + 1];
    a[..16].copy_from_slice(&a_data[..16]);
    b[..16].copy_from_slice(&b_data[..16]);

    for k in 0..W {
        for j in 0..T {
            let mask = if (a[j] >> k) & 0x01 == 1 { 0xFF } else { 0x00 };
            for i in 0..T + 1 {
                c[j + i] ^= b[i] & mask;
            }
        }
        for i in (1..=T).rev() {
            b[i] = (b[i] << 1) | (b[i - 1] >> 7);
        }
        b[0] <<= 1
    }
    for i in (T..=2 * T - 1).rev() {
        c[i - 16] ^= c[i];
        c[i - 16] ^= c[i] << 1;
        c[i - 15] ^= c[i] >> 7;
        c[i - 16] ^= c[i] << 2;
        c[i - 15] ^= c[i] >> 6;
        c[i - 16] ^= c[i] << 7;
        c[i - 15] ^= c[i] >> 1;
    }

    c[..16].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    // Test based on fermat's little theorem
    #[test]
    fn test_mul_128() {
        for _ in 0..10 {
            let rand_num = rand::random::<[u8; 16]>();
            let mut temp = rand_num;

            for _ in 0..128 {
                temp = super::binary_field_multiply_gf_2_128(temp, temp);
            }

            assert_eq!(temp, rand_num);
        }
    }
}
