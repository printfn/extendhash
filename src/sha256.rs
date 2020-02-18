#[derive(Clone)]
struct SHA256 {
    h: [u32; 8],
}

#[cfg(feature = "std")]
impl SHA256 {
    fn apply_chunk(&mut self, chunk: &[u8]) {
        assert_eq!(chunk.len(), 64);

        let k: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut a: u32 = self.h[0];
        let mut b: u32 = self.h[1];
        let mut c: u32 = self.h[2];
        let mut d: u32 = self.h[3];
        let mut e: u32 = self.h[4];
        let mut f: u32 = self.h[5];
        let mut g: u32 = self.h[6];
        let mut h: u32 = self.h[7];

        let mut w: [u32; 64] = [0; 64];
        for i in 0..64 {
            if i < 16 {
                w[i] = u32::from_be_bytes([
                    chunk[4 * i + 0],
                    chunk[4 * i + 1],
                    chunk[4 * i + 2],
                    chunk[4 * i + 3],
                ]);
            } else {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
        }

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }

    fn hash_from_data(&self) -> [u8; 32] {
        let a = self.h[0].to_be_bytes();
        let b = self.h[1].to_be_bytes();
        let c = self.h[2].to_be_bytes();
        let d = self.h[3].to_be_bytes();
        let e = self.h[4].to_be_bytes();
        let f = self.h[5].to_be_bytes();
        let g = self.h[6].to_be_bytes();
        let h = self.h[7].to_be_bytes();
        [
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1],
            d[2], d[3], e[0], e[1], e[2], e[3], f[0], f[1], f[2], f[3], g[0], g[1], g[2], g[3],
            h[0], h[1], h[2], h[3],
        ]
    }
}

/// Compute the SHA-256 padding for the given input length.
///
/// # Arguments
///
/// * `input_length` - The length of the input length. This value
///     is needed to determine the padding length, and to embed
///     the length in the last 8 bytes of padding.
///
/// # Returns
///
/// This function returns SHA-256 padding for the given input size.
/// This padding has a length you can determine by calling
/// `sha256::padding_length_for_input_length`.
///
/// # Example
///
/// ```
/// # use extendhash::sha256;
/// let data = "This string will be hashed.";
/// let padding = sha256::padding_for_length(data.len());
/// assert_eq!(data.len() + padding.len(), 64);
/// for (i, p) in padding.iter().enumerate() {
///     match i {
///         0       => 0b1000_0000,
///         1..=28  => 0b0000_0000,
///         29      => data.len() as u8 * 8,
///         30..=36 => 0b0000_0000,
///         _       => unreachable!("Invalid padding length")
///     };
/// }
/// ```
#[cfg(feature = "std")]
pub fn padding_for_length(input_length: usize) -> Vec<u8> {
    let padding_length = padding_length_for_input_length(input_length);
    let mut result = Vec::<u8>::with_capacity(padding_length);
    result.push(0b1000_0000);
    for _ in 0..(padding_length - 9) {
        result.push(0b0000_0000);
    }
    result.extend_from_slice(&(input_length as u64).wrapping_mul(8).to_be_bytes());
    result
}

/// Compute the SHA-256 padding length (in bytes) for the
/// given input length.
///
/// The result is always between 9 and 72 (inclusive).
///
/// # Arguments
///
/// * `input_length` - The length of the input length. This value
///     is used because the amount of padding is always such that the
///     total padded string is a multiple of 64 bytes.
///
/// # Returns
///
/// This function returns the amount of padding required for the given
/// input length.
///
/// # Example
///
/// ```
/// # use extendhash::sha256;
/// let data = "This string will be hashed.";
/// let padding_length =
///     sha256::padding_length_for_input_length(data.len());
/// assert_eq!(data.len() + padding_length, 64);
/// ```
pub fn padding_length_for_input_length(input_length: usize) -> usize {
    if input_length % 64 <= 55 {
        64 - input_length % 64
    } else {
        128 - input_length % 64
    }
}

/// Compute the SHA-256 hash of the input data
///
/// # Arguments
///
/// * `input` - The input data to be hashed - this could be a
///     UTF-8 string or any other binary data.
///
/// # Returns
///
/// This function returns the computed SHA-256 hash.
///
/// # Example
///
/// ```
/// # use extendhash::sha256;
/// let secret_data = "input string".as_bytes();
/// let hash = sha256::compute_hash(secret_data);
/// assert_eq!(hash, [
///     0xf2, 0x3f, 0x47, 0x81, 0xd6, 0x81, 0x4e, 0xbe,
///     0x34, 0x9c, 0x6b, 0x23, 0x0c, 0x1f, 0x70, 0x07,
///     0x14, 0xf4, 0xf7, 0x0f, 0x73, 0x50, 0x22, 0xbd,
///     0x4b, 0x1f, 0xb6, 0x94, 0x21, 0x85, 0x99, 0x93]);
/// ```
#[cfg(feature = "std")]
pub fn compute_hash(input: &[u8]) -> [u8; 32] {
    let mut sha256 = SHA256 {
        h: [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ],
    };

    let mut data = Vec::<u8>::new();
    data.extend_from_slice(input);
    data.extend_from_slice(padding_for_length(input.len()).as_slice());
    assert_eq!(data.len() % 64, 0);
    for chunk in data.chunks_exact(64) {
        sha256.apply_chunk(chunk);
    }

    sha256.hash_from_data()
}

/// Calculate a SHA-256 hash extension.
///
/// # Arguments
///
/// * `hash` - The SHA-256 hash of some previous (unknown) data
/// * `length` - The length of the unknown data (without any
///       added padding)
/// * `additional_input` - Additional input to be
///       included in the new hash.
///
/// # Returns
///
/// This function returns the SHA-256 hash of the concatenation of
/// the original unknown data, its padding, and the `additional_input`.
/// You can see the included (intermediate) padding by
/// calling `sha256::padding_for_length`.
///
/// # Example
///
/// ```
/// # use extendhash::sha256;
/// let secret_data = "This is a secret!".as_bytes();
/// let hash = sha256::compute_hash(secret_data);
/// let secret_data_length = secret_data.len();
///
/// // Now we try computing a hash extension, assuming that
/// // `secret_data` is not available. We only need `hash`
/// // and `secret_data_length`.
/// let appended_message = "Appended message.".as_bytes();
/// let combined_hash = sha256::extend_hash(
///     hash, secret_data_length, appended_message);
///
/// // Now we verify that `combined_hash` matches the
/// // concatenation (note the intermediate padding):
/// let mut combined_data = Vec::<u8>::new();
/// combined_data.extend_from_slice(secret_data);
/// let padding = sha256::padding_for_length(secret_data_length);
/// combined_data.extend_from_slice(padding.as_slice());
/// combined_data.extend_from_slice(appended_message);
/// assert_eq!(
///     combined_hash,
///     sha256::compute_hash(combined_data.as_slice()));
/// ```
#[cfg(feature = "std")]
pub fn extend_hash(hash: [u8; 32], length: usize, additional_input: &[u8]) -> [u8; 32] {
    let mut sha256 = SHA256 {
        h: [
            u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]),
            u32::from_be_bytes([hash[4], hash[5], hash[6], hash[7]]),
            u32::from_be_bytes([hash[8], hash[9], hash[10], hash[11]]),
            u32::from_be_bytes([hash[12], hash[13], hash[14], hash[15]]),
            u32::from_be_bytes([hash[16], hash[17], hash[18], hash[19]]),
            u32::from_be_bytes([hash[20], hash[21], hash[22], hash[23]]),
            u32::from_be_bytes([hash[24], hash[25], hash[26], hash[27]]),
            u32::from_be_bytes([hash[28], hash[29], hash[30], hash[31]]),
        ],
    };

    let len = length + padding_length_for_input_length(length) + additional_input.len();

    let mut data = Vec::<u8>::new();
    data.extend_from_slice(additional_input);
    data.extend_from_slice(padding_for_length(len).as_slice());
    assert_eq!(data.len() % 64, 0);

    for chunk in data.chunks_exact(64) {
        sha256.apply_chunk(chunk);
    }

    sha256.hash_from_data()
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use crate::sha256;

    #[test]
    fn empty_hash() {
        assert_eq!(
            sha256::compute_hash(&[]),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn a_test() {
        assert_eq!(
            sha256::compute_hash("a".as_bytes()),
            [
                0xca, 0x97, 0x81, 0x12, 0xca, 0x1b, 0xbd, 0xca, 0xfa, 0xc2, 0x31, 0xb3, 0x9a, 0x23,
                0xdc, 0x4d, 0xa7, 0x86, 0xef, 0xf8, 0x14, 0x7c, 0x4e, 0x72, 0xb9, 0x80, 0x77, 0x85,
                0xaf, 0xee, 0x48, 0xbb
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test() {
        let s = "The quick brown fox jumps over the lazy dog";
        assert_eq!(
            sha256::compute_hash(s.as_bytes()),
            [
                0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08,
                0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf,
                0x37, 0xc9, 0xe5, 0x92
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test_2() {
        let s = "The quick brown fox jumps over the lazy cog";
        assert_eq!(
            sha256::compute_hash(s.as_bytes()),
            [
                0xe4, 0xc4, 0xd8, 0xf3, 0xbf, 0x76, 0xb6, 0x92, 0xde, 0x79, 0x1a, 0x17, 0x3e, 0x05,
                0x32, 0x11, 0x50, 0xf7, 0xa3, 0x45, 0xb4, 0x64, 0x84, 0xfe, 0x42, 0x7f, 0x6a, 0xcc,
                0x7e, 0xcc, 0x81, 0xbe
            ]
        );
    }

    #[test]
    fn abc_test() {
        let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                 abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            sha256::compute_hash(s.as_bytes()),
            [
                0xdb, 0x4b, 0xfc, 0xbd, 0x4d, 0xa0, 0xcd, 0x85, 0xa6, 0x0c, 0x3c, 0x37, 0xd3, 0xfb,
                0xd8, 0x80, 0x5c, 0x77, 0xf1, 0x5f, 0xc6, 0xb1, 0xfd, 0xfe, 0x61, 0x4e, 0xe0, 0xa7,
                0xc8, 0xfd, 0xb4, 0xc0
            ]
        );
    }

    #[test]
    fn long_test() {
        let mut input = String::new();
        for _ in 0..40000 {
            input.push_str("aaaaaaaaaaaaaaaaaaaaaaaaa");
        }
        assert_eq!(input.len(), 1_000_000);
        assert_eq!(
            sha256::compute_hash(input.as_bytes()),
            [
                0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
                0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
                0xc7, 0x11, 0x2c, 0xd0
            ]
        );
    }

    #[test]
    fn padding_length_tests() {
        assert_eq!(sha256::padding_length_for_input_length(0), 64);
        assert_eq!(sha256::padding_length_for_input_length(1), 63);
        assert_eq!(sha256::padding_length_for_input_length(2), 62);
        assert_eq!(sha256::padding_length_for_input_length(3), 61);
        assert_eq!(sha256::padding_length_for_input_length(4), 60);

        assert_eq!(sha256::padding_length_for_input_length(50), 14);
        assert_eq!(sha256::padding_length_for_input_length(54), 10);
        assert_eq!(sha256::padding_length_for_input_length(55), 9);
        assert_eq!(sha256::padding_length_for_input_length(56), 64 + 8);
        assert_eq!(sha256::padding_length_for_input_length(57), 64 + 7);
        assert_eq!(sha256::padding_length_for_input_length(62), 64 + 2);
        assert_eq!(sha256::padding_length_for_input_length(63), 64 + 1);
        assert_eq!(sha256::padding_length_for_input_length(64), 64);
        assert_eq!(sha256::padding_length_for_input_length(128), 64);
        assert_eq!(sha256::padding_length_for_input_length(64 * 100000), 64);
    }

    #[test]
    fn test_hash_ext() {
        let secret = "count=10&lat=37.351&user_id=1&\
                      long=-119.827&waffle=eggo"
            .as_bytes();
        let hash = sha256::compute_hash(secret);

        let appended_str = "&waffle=liege".as_bytes();
        let combined_hash = sha256::extend_hash(hash, secret.len(), appended_str);

        let mut concatenation = Vec::<u8>::new();
        concatenation.extend_from_slice(secret);
        let padding = sha256::padding_for_length(secret.len());
        concatenation.extend_from_slice(padding.as_slice());
        concatenation.extend_from_slice(appended_str);
        assert_eq!(
            combined_hash,
            sha256::compute_hash(concatenation.as_slice())
        );
    }
}
