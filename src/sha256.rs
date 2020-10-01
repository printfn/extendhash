use alloc::vec::Vec;

#[derive(Copy, Clone)]
struct SHA256 {
    h: [u32; 8],
}

impl SHA256 {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    const fn padding_value_at_idx(input_length: usize, idx: usize) -> u8 {
        let padding_length = Self::padding_length_for_input_length(input_length);
        if idx == 0 {
            0b1000_0000
        } else if idx <= padding_length - 9 {
            0
        } else {
            let offset = idx + 8 - padding_length;
            let bytes = (input_length as u64).wrapping_mul(8).to_be_bytes();
            bytes[offset]
        }
    }

    const fn apply_chunk(self, chunk: [u8; 64]) -> Self {
        let mut w = [0_u32; 64];
        {
            let mut i = 0;
            while i < 64 {
                if i < 16 {
                    w[i] = u32::from_be_bytes([
                        chunk[4 * i],
                        chunk[4 * i + 1],
                        chunk[4 * i + 2],
                        chunk[4 * i + 3],
                    ]);
                } else {
                    let s0 =
                        w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                    let s1 =
                        w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                    w[i] = w[i - 16]
                        .wrapping_add(s0)
                        .wrapping_add(w[i - 7])
                        .wrapping_add(s1);
                }
                i += 1;
            }
        }

        let mut h = self.h;

        let mut i = 0;
        while i < 64 {
            let current_w = w[i];
            let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
            let ch = (h[4] & h[5]) ^ ((!h[4]) & h[6]);
            let temp1 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(current_w);
            let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
            let maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            let temp2 = s0.wrapping_add(maj);

            h[7] = h[6];
            h[6] = h[5];
            h[5] = h[4];
            h[4] = h[3].wrapping_add(temp1);
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[0];
            h[0] = temp1.wrapping_add(temp2);

            i += 1;
        }

        Self {
            h: [
                self.h[0].wrapping_add(h[0]),
                self.h[1].wrapping_add(h[1]),
                self.h[2].wrapping_add(h[2]),
                self.h[3].wrapping_add(h[3]),
                self.h[4].wrapping_add(h[4]),
                self.h[5].wrapping_add(h[5]),
                self.h[6].wrapping_add(h[6]),
                self.h[7].wrapping_add(h[7]),
            ],
        }
    }

    const fn get_num_chunks(data_length: usize) -> usize {
        (data_length + Self::padding_length_for_input_length(data_length)) / 64
    }

    const fn get_chunk(data: &[u8], data_len: usize, chunk_idx: usize) -> [u8; 64] {
        let mut chunk = [0; 64];
        let mut i = 0;
        while i < 64 {
            if chunk_idx * 64 + i < data.len() {
                chunk[i] = data[chunk_idx * 64 + i];
            } else {
                let padding_len = Self::padding_length_for_input_length(data_len);
                let index_into_padding = chunk_idx * 64 + i - data.len();
                if index_into_padding < padding_len {
                    chunk[i] = Self::padding_value_at_idx(data_len, index_into_padding);
                } else {
                    // error
                    let _ = chunk[i + 100000];
                }
            }
            i += 1;
        }
        chunk
    }

    const fn hash_from_data(self) -> [u8; 32] {
        let h = [
            self.h[0].to_be_bytes(),
            self.h[1].to_be_bytes(),
            self.h[2].to_be_bytes(),
            self.h[3].to_be_bytes(),
            self.h[4].to_be_bytes(),
            self.h[5].to_be_bytes(),
            self.h[6].to_be_bytes(),
            self.h[7].to_be_bytes(),
        ];
        [
            h[0][0], h[0][1], h[0][2], h[0][3], h[1][0], h[1][1], h[1][2], h[1][3], h[2][0],
            h[2][1], h[2][2], h[2][3], h[3][0], h[3][1], h[3][2], h[3][3], h[4][0], h[4][1],
            h[4][2], h[4][3], h[5][0], h[5][1], h[5][2], h[5][3], h[6][0], h[6][1], h[6][2],
            h[6][3], h[7][0], h[7][1], h[7][2], h[7][3],
        ]
    }

    const fn padding_length_for_input_length(input_length: usize) -> usize {
        if input_length % 64 <= 55 {
            64 - input_length % 64
        } else {
            128 - input_length % 64
        }
    }

    const fn new() -> Self {
        Self {
            h: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
        }
    }

    const fn from(hash: [u8; 32]) -> Self {
        Self {
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
        }
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
#[must_use]
pub fn padding_for_length(input_length: usize) -> Vec<u8> {
    let padding_length = padding_length_for_input_length(input_length);
    let mut result = Vec::with_capacity(padding_length);
    for i in 0..padding_length {
        result.push(SHA256::padding_value_at_idx(input_length, i));
    }
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
#[must_use]
pub const fn padding_length_for_input_length(input_length: usize) -> usize {
    SHA256::padding_length_for_input_length(input_length)
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
#[must_use]
pub const fn compute_hash(input: &[u8]) -> [u8; 32] {
    let num_chunks = SHA256::get_num_chunks(input.len());
    let mut sha256 = SHA256::new();
    let mut i = 0;
    while i < num_chunks {
        let chunk = SHA256::get_chunk(input, input.len(), i);
        sha256 = sha256.apply_chunk(chunk);
        i += 1;
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
#[must_use]
pub const fn extend_hash(hash: [u8; 32], length: usize, additional_input: &[u8]) -> [u8; 32] {
    let len = length + padding_length_for_input_length(length) + additional_input.len();
    let num_chunks = (additional_input.len() + padding_length_for_input_length(len)) / 64;
    let mut sha256 = SHA256::from(hash);
    let mut i = 0;
    while i < num_chunks {
        let chunk = SHA256::get_chunk(additional_input, len, i);
        sha256 = sha256.apply_chunk(chunk);
        i += 1;
    }
    sha256.hash_from_data()
}

#[cfg(test)]
mod tests {
    use crate::sha256;
    use alloc::vec::Vec;

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
            sha256::compute_hash(b"a"),
            [
                0xca, 0x97, 0x81, 0x12, 0xca, 0x1b, 0xbd, 0xca, 0xfa, 0xc2, 0x31, 0xb3, 0x9a, 0x23,
                0xdc, 0x4d, 0xa7, 0x86, 0xef, 0xf8, 0x14, 0x7c, 0x4e, 0x72, 0xb9, 0x80, 0x77, 0x85,
                0xaf, 0xee, 0x48, 0xbb
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test() {
        let s = b"The quick brown fox jumps over the lazy dog";
        assert_eq!(
            sha256::compute_hash(s),
            [
                0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08,
                0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf,
                0x37, 0xc9, 0xe5, 0x92
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test_2() {
        let s = b"The quick brown fox jumps over the lazy cog";
        assert_eq!(
            sha256::compute_hash(s),
            [
                0xe4, 0xc4, 0xd8, 0xf3, 0xbf, 0x76, 0xb6, 0x92, 0xde, 0x79, 0x1a, 0x17, 0x3e, 0x05,
                0x32, 0x11, 0x50, 0xf7, 0xa3, 0x45, 0xb4, 0x64, 0x84, 0xfe, 0x42, 0x7f, 0x6a, 0xcc,
                0x7e, 0xcc, 0x81, 0xbe
            ]
        );
    }

    #[test]
    fn abc_test() {
        let s = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                  abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            sha256::compute_hash(s),
            [
                0xdb, 0x4b, 0xfc, 0xbd, 0x4d, 0xa0, 0xcd, 0x85, 0xa6, 0x0c, 0x3c, 0x37, 0xd3, 0xfb,
                0xd8, 0x80, 0x5c, 0x77, 0xf1, 0x5f, 0xc6, 0xb1, 0xfd, 0xfe, 0x61, 0x4e, 0xe0, 0xa7,
                0xc8, 0xfd, 0xb4, 0xc0
            ]
        );
    }

    #[test]
    fn long_test() {
        assert_eq!(
            sha256::compute_hash(&*alloc::vec![b'a'; 1_000_000].into_boxed_slice()),
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
        assert_eq!(sha256::padding_length_for_input_length(64 * 100_000), 64);
    }

    #[test]
    fn test_hash_ext() {
        let secret = b"count=10&lat=37.351&user_id=1&\
                       long=-119.827&waffle=eggo";
        let hash = sha256::compute_hash(secret);

        let appended_str = b"&waffle=liege";
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
