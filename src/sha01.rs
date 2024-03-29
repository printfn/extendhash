// This file contains shared code for SHA-0 and SHA-1.
use alloc::vec::Vec;

#[derive(Copy, Clone)]
struct Sha1 {
    h: [u32; 5],
}

#[derive(Copy, Clone)]
pub(crate) enum HashType {
    Sha0,
    Sha1,
}

impl Sha1 {
    const fn apply_chunk(self, chunk: [u8; 64], hash_type: HashType) -> Self {
        let mut w = [0_u32; 80];
        {
            let mut i = 0;
            while i < 80 {
                if i < 16 {
                    w[i] = u32::from_be_bytes([
                        chunk[4 * i],
                        chunk[4 * i + 1],
                        chunk[4 * i + 2],
                        chunk[4 * i + 3],
                    ]);
                } else {
                    let rotate_amount = match hash_type {
                        HashType::Sha0 => 0,
                        HashType::Sha1 => 1,
                    };
                    w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(rotate_amount);
                }
                i += 1;
            }
        }

        let mut h = self.h;

        {
            let mut idx = 0;
            while idx < 80 {
                let current_w = w[idx];

                let (f, k) = match idx {
                    0..=19 => ((h[1] & h[2]) | ((!h[1]) & h[3]), 0x5a82_7999),
                    20..=39 => (h[1] ^ h[2] ^ h[3], 0x6ed9_eba1),
                    40..=59 => ((h[1] & h[2]) | (h[1] & h[3]) | (h[2] & h[3]), 0x8f1b_bcdc),
                    _ => (h[1] ^ h[2] ^ h[3], 0xca62_c1d6),
                };

                let temp = h[0]
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(h[4])
                    .wrapping_add(k)
                    .wrapping_add(current_w);

                h[4] = h[3];
                h[3] = h[2];
                h[2] = h[1].rotate_left(30);
                h[1] = h[0];
                h[0] = temp;

                idx += 1;
            }
        }

        Self {
            h: [
                self.h[0].wrapping_add(h[0]),
                self.h[1].wrapping_add(h[1]),
                self.h[2].wrapping_add(h[2]),
                self.h[3].wrapping_add(h[3]),
                self.h[4].wrapping_add(h[4]),
            ],
        }
    }

    const fn hash_from_data(self) -> [u8; 20] {
        let h = [
            self.h[0].to_be_bytes(),
            self.h[1].to_be_bytes(),
            self.h[2].to_be_bytes(),
            self.h[3].to_be_bytes(),
            self.h[4].to_be_bytes(),
        ];
        [
            h[0][0], h[0][1], h[0][2], h[0][3], h[1][0], h[1][1], h[1][2], h[1][3], h[2][0],
            h[2][1], h[2][2], h[2][3], h[3][0], h[3][1], h[3][2], h[3][3], h[4][0], h[4][1],
            h[4][2], h[4][3],
        ]
    }

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
                    panic!("unreachable: internal error");
                }
            }
            i += 1;
        }
        chunk
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
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
        }
    }

    const fn from(hash: [u8; 20]) -> Self {
        Self {
            h: [
                u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]),
                u32::from_be_bytes([hash[4], hash[5], hash[6], hash[7]]),
                u32::from_be_bytes([hash[8], hash[9], hash[10], hash[11]]),
                u32::from_be_bytes([hash[12], hash[13], hash[14], hash[15]]),
                u32::from_be_bytes([hash[16], hash[17], hash[18], hash[19]]),
            ],
        }
    }
}

/// Compute the SHA-0/SHA-1 padding for the given input length.
///
/// # Arguments
///
/// * `input_length` - The length of the input length. This value is
///     needed to determine the padding length, and to embed the
///     length in the last 8 bytes of padding.
///
/// # Returns
///
/// This function returns SHA-0/SHA-1 padding for the given input size.
/// This padding has a length you can determine by calling
/// `sha01::padding_length_for_input_length`.
pub(crate) fn padding_for_length(input_length: usize) -> Vec<u8> {
    let padding_length = padding_length_for_input_length(input_length);
    let mut result = Vec::with_capacity(padding_length);
    for i in 0..padding_length {
        result.push(Sha1::padding_value_at_idx(input_length, i));
    }
    result
}

/// Compute the SHA-0/SHA-1 padding length (in bytes) for the given
/// input length.
///
/// The result is always between 9 and 72 (inclusive).
///
/// # Arguments
///
/// * `input_length` - The length of the input length. This value is
///     used because the amount of padding is always such that the
///     total padded string is a multiple of 64 bytes.
///
/// # Returns
///
/// This function returns the amount of padding required for
/// the given input length.
pub(crate) const fn padding_length_for_input_length(input_length: usize) -> usize {
    Sha1::padding_length_for_input_length(input_length)
}

/// Compute the SHA-0/SHA-1 hash of the input data
///
/// # Arguments
///
/// * `input` - The input data to be hashed - this could be a
///     UTF-8 string or any other binary data.
///
/// # Returns
///
/// This function returns the computed SHA-0/SHA-1 hash.
pub(crate) const fn compute_hash(input: &[u8], hash_type: HashType) -> [u8; 20] {
    let num_chunks = Sha1::get_num_chunks(input.len());
    let mut sha1 = Sha1::new();
    let mut i = 0;
    while i < num_chunks {
        let chunk = Sha1::get_chunk(input, input.len(), i);
        sha1 = sha1.apply_chunk(chunk, hash_type);
        i += 1;
    }
    sha1.hash_from_data()
}

/// Calculate a SHA-0/SHA-1 hash extension.
///
/// # Arguments
///
/// * `hash` - The SHA-0/SHA-1 hash of some previous (unknown) data
/// * `length` - The length of the unknown data (without any
///       added padding)
/// * `additional_input` - Additional input to be included
///       in the new hash.
///
/// # Returns
///
/// This function returns the SHA-0/SHA-1 hash of the concatenation of
/// the original unknown data, its padding, and the `additional_input`.
/// You can see the included (intermediate) padding by
/// calling `sha1::padding_for_length`.
pub(crate) const fn extend_hash(
    hash: [u8; 20],
    length: usize,
    additional_input: &[u8],
    hash_type: HashType,
) -> [u8; 20] {
    let len = length + padding_length_for_input_length(length) + additional_input.len();
    let num_chunks = (additional_input.len() + padding_length_for_input_length(len)) / 64;
    let mut sha1 = Sha1::from(hash);
    let mut i = 0;
    while i < num_chunks {
        let chunk = Sha1::get_chunk(additional_input, len, i);
        sha1 = sha1.apply_chunk(chunk, hash_type);
        i += 1;
    }
    sha1.hash_from_data()
}

#[cfg(test)]
mod tests {
    use crate::sha01;
    use crate::sha01::HashType;
    use alloc::string::String;
    use alloc::vec::Vec;

    #[test]
    fn empty_hash() {
        assert_eq!(
            sha01::compute_hash(&[], HashType::Sha1),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn a_test() {
        assert_eq!(
            sha01::compute_hash(b"a", HashType::Sha1),
            [
                0x86, 0xf7, 0xe4, 0x37, 0xfa, 0xa5, 0xa7, 0xfc, 0xe1, 0x5d, 0x1d, 0xdc, 0xb9, 0xea,
                0xea, 0xea, 0x37, 0x76, 0x67, 0xb8
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test() {
        assert_eq!(
            sha01::compute_hash(
                b"The quick brown fox jumps over the lazy dog",
                HashType::Sha1
            ),
            [
                0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76,
                0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test_2() {
        assert_eq!(
            sha01::compute_hash(
                b"The quick brown fox jumps over the lazy cog",
                HashType::Sha1
            ),
            [
                0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3, 0xe8, 0x5a, 0x0b, 0xd1,
                0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3
            ]
        );
    }

    #[test]
    fn abc_test() {
        assert_eq!(
            sha01::compute_hash(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                HashType::Sha1
            ),
            [
                0x76, 0x1c, 0x45, 0x7b, 0xf7, 0x3b, 0x14, 0xd2, 0x7e, 0x9e, 0x92, 0x65, 0xc4, 0x6f,
                0x4b, 0x4d, 0xda, 0x11, 0xf9, 0x40
            ]
        );
    }

    #[test]
    fn long_test() {
        let mut input = String::new();
        for _ in 0..10000 {
            input.push_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            input.push_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        }
        assert_eq!(input.len(), 1_000_000);
        assert_eq!(
            sha01::compute_hash(input.as_bytes(), HashType::Sha1),
            [
                0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad,
                0x27, 0x31, 0x65, 0x34, 0x01, 0x6f
            ]
        );
    }

    #[test]
    fn padding_length_tests() {
        assert_eq!(sha01::padding_length_for_input_length(0), 64);
        assert_eq!(sha01::padding_length_for_input_length(1), 63);
        assert_eq!(sha01::padding_length_for_input_length(2), 62);
        assert_eq!(sha01::padding_length_for_input_length(3), 61);
        assert_eq!(sha01::padding_length_for_input_length(4), 60);

        assert_eq!(sha01::padding_length_for_input_length(50), 14);
        assert_eq!(sha01::padding_length_for_input_length(54), 10);
        assert_eq!(sha01::padding_length_for_input_length(55), 9);
        assert_eq!(sha01::padding_length_for_input_length(56), 64 + 8);
        assert_eq!(sha01::padding_length_for_input_length(57), 64 + 7);
        assert_eq!(sha01::padding_length_for_input_length(62), 64 + 2);
        assert_eq!(sha01::padding_length_for_input_length(63), 64 + 1);
        assert_eq!(sha01::padding_length_for_input_length(64), 64);
        assert_eq!(sha01::padding_length_for_input_length(128), 64);
        assert_eq!(sha01::padding_length_for_input_length(64 * 100_000), 64);
    }

    #[test]
    fn test_hash_ext() {
        let secret = b"count=10&lat=37.351&user_id=1&\
                       long=-119.827&waffle=eggo";
        let hash = sha01::compute_hash(secret, HashType::Sha1);

        let appended_str = b"&waffle=liege";
        let combined_hash = sha01::extend_hash(hash, secret.len(), appended_str, HashType::Sha1);

        let mut concatenation = Vec::<u8>::new();
        concatenation.extend_from_slice(secret);
        let intermediate_padding = sha01::padding_for_length(secret.len());
        concatenation.extend_from_slice(intermediate_padding.as_slice());
        concatenation.extend_from_slice(appended_str);
        assert_eq!(
            combined_hash,
            sha01::compute_hash(concatenation.as_slice(), HashType::Sha1)
        );
    }
}
