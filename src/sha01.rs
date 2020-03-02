// This file contains shared code for SHA-0 and SHA-1.

#[derive(Clone)]
struct SHA1 {
    h: [u32; 5],
}

#[derive(Copy, Clone)]
pub enum HashType {
    SHA0,
    SHA1,
}

impl SHA1 {
    fn apply_chunk(self, chunk: &[u8], hash_type: HashType) -> SHA1 {
        assert_eq!(chunk.len(), 64);

        let mut w = [0u32; 80];
        for i in 0..80 {
            if i < 16 {
                w[i] = u32::from_be_bytes([
                    chunk[4 * i],
                    chunk[4 * i + 1],
                    chunk[4 * i + 2],
                    chunk[4 * i + 3],
                ]);
            } else {
                let rotate_amount = match hash_type {
                    HashType::SHA0 => 0,
                    HashType::SHA1 => 1,
                };
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(rotate_amount);
            }
        }

        let mut h = self.h;

        for (i, &current_w) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((h[1] & h[2]) | ((!h[1]) & h[3]), 0x5a82_7999),
                20..=39 => (h[1] ^ h[2] ^ h[3], 0x6ed9_eba1),
                40..=59 => ((h[1] & h[2]) | (h[1] & h[3]) | (h[2] & h[3]), 0x8f1b_bcdc),
                60..=79 => (h[1] ^ h[2] ^ h[3], 0xca62_c1d6),
                _ => unreachable!(),
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
        }

        SHA1 {
            h: [
                self.h[0].wrapping_add(h[0]),
                self.h[1].wrapping_add(h[1]),
                self.h[2].wrapping_add(h[2]),
                self.h[3].wrapping_add(h[3]),
                self.h[4].wrapping_add(h[4]),
            ],
        }
    }

    fn hash_from_data(self) -> [u8; 20] {
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
}

impl Default for SHA1 {
    fn default() -> SHA1 {
        SHA1 {
            h: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
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
pub fn padding_length_for_input_length(input_length: usize) -> usize {
    if input_length % 64 <= 55 {
        64 - input_length % 64
    } else {
        128 - input_length % 64
    }
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
pub fn compute_hash(input: &[u8], hash_type: HashType) -> [u8; 20] {
    let mut data = Vec::<u8>::new();
    data.extend_from_slice(input);
    data.extend_from_slice(padding_for_length(input.len()).as_slice());
    assert_eq!(data.len() % 64, 0);

    let sha1 = data.chunks_exact(64).fold(SHA1::default(), |sha1, chunk| {
        sha1.apply_chunk(chunk, hash_type)
    });
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
pub fn extend_hash(
    hash: [u8; 20],
    length: usize,
    additional_input: &[u8],
    hash_type: HashType,
) -> [u8; 20] {
    let mut sha1 = SHA1 {
        h: [
            u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]),
            u32::from_be_bytes([hash[4], hash[5], hash[6], hash[7]]),
            u32::from_be_bytes([hash[8], hash[9], hash[10], hash[11]]),
            u32::from_be_bytes([hash[12], hash[13], hash[14], hash[15]]),
            u32::from_be_bytes([hash[16], hash[17], hash[18], hash[19]]),
        ],
    };

    let len = length + padding_length_for_input_length(length) + additional_input.len();

    let mut data = Vec::<u8>::new();
    data.extend_from_slice(additional_input);
    data.extend_from_slice(padding_for_length(len).as_slice());
    assert_eq!(data.len() % 64, 0);

    for chunk in data.chunks_exact(64) {
        sha1 = sha1.apply_chunk(chunk, hash_type);
    }

    sha1.hash_from_data()
}

#[cfg(test)]
mod tests {
    use crate::sha01;
    use crate::sha01::HashType;

    #[test]
    fn empty_hash() {
        assert_eq!(
            sha01::compute_hash(&[], HashType::SHA1),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn a_test() {
        assert_eq!(
            sha01::compute_hash("a".as_bytes(), HashType::SHA1),
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
                "The quick brown fox jumps over the lazy dog".as_bytes(),
                HashType::SHA1
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
                "The quick brown fox jumps over the lazy cog".as_bytes(),
                HashType::SHA1
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
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
                HashType::SHA1
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
            sha01::compute_hash(input.as_bytes(), HashType::SHA1),
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
        assert_eq!(sha01::padding_length_for_input_length(64 * 100000), 64);
    }

    #[test]
    fn test_hash_ext() {
        let secret = "count=10&lat=37.351&user_id=1&\
                      long=-119.827&waffle=eggo"
            .as_bytes();
        let hash = sha01::compute_hash(secret, HashType::SHA1);

        let appended_str = "&waffle=liege".as_bytes();
        let combined_hash = sha01::extend_hash(hash, secret.len(), appended_str, HashType::SHA1);

        let mut concatenation = Vec::<u8>::new();
        concatenation.extend_from_slice(secret);
        let intermediate_padding = sha01::padding_for_length(secret.len());
        concatenation.extend_from_slice(intermediate_padding.as_slice());
        concatenation.extend_from_slice(appended_str);
        assert_eq!(
            combined_hash,
            sha01::compute_hash(concatenation.as_slice(), HashType::SHA1)
        );
    }
}
