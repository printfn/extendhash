use crate::hash::Hash;
use alloc::vec::Vec;
use core::iter;

#[derive(Copy, Clone)]
struct MD5 {
    h: [u32; 4],
}

impl MD5 {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];

    fn padding_for_length(input_length: usize) -> impl Iterator<Item = u8> {
        let len_as_bytes = (input_length as u64).wrapping_mul(8).to_le_bytes();

        iter::once(0b1000_0000)
            .chain(iter::repeat(0).take(Self::padding_length_for_input_length(input_length) - 9))
            .chain(iter::once(len_as_bytes[0]))
            .chain(iter::once(len_as_bytes[1]))
            .chain(iter::once(len_as_bytes[2]))
            .chain(iter::once(len_as_bytes[3]))
            .chain(iter::once(len_as_bytes[4]))
            .chain(iter::once(len_as_bytes[5]))
            .chain(iter::once(len_as_bytes[6]))
            .chain(iter::once(len_as_bytes[7]))
    }
}

impl Hash<[u8; 16]> for MD5 {
    fn apply_chunk(self, chunk: &[u8]) -> MD5 {
        assert_eq!(chunk.len(), 64);

        let mut h = self.h;

        for i in 0_usize..64 {
            let (mut f, g) = match i {
                0..=15 => ((h[1] & h[2]) | ((!h[1]) & h[3]), i),
                16..=31 => ((h[3] & h[1]) | ((!h[3]) & h[2]), (5 * i + 1) % 16),
                32..=47 => (h[1] ^ h[2] ^ h[3], (3 * i + 5) % 16),
                48..=63 => (h[2] ^ (h[1] | (!h[3])), (7 * i) % 16),
                _ => unreachable!(),
            };

            let slice = [
                chunk[4 * g],
                chunk[4 * g + 1],
                chunk[4 * g + 2],
                chunk[4 * g + 3],
            ];

            f = f
                .wrapping_add(h[0])
                .wrapping_add(Self::K[i])
                .wrapping_add(u32::from_le_bytes(slice));

            h[0] = h[3];
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[1].wrapping_add(f.rotate_left(Self::S[i]));
        }

        MD5 {
            h: [
                self.h[0].wrapping_add(h[0]),
                self.h[1].wrapping_add(h[1]),
                self.h[2].wrapping_add(h[2]),
                self.h[3].wrapping_add(h[3]),
            ],
        }
    }

    fn hash_from_data(self) -> [u8; 16] {
        let h = [
            self.h[0].to_le_bytes(),
            self.h[1].to_le_bytes(),
            self.h[2].to_le_bytes(),
            self.h[3].to_le_bytes(),
        ];
        [
            h[0][0], h[0][1], h[0][2], h[0][3], h[1][0], h[1][1], h[1][2], h[1][3], h[2][0],
            h[2][1], h[2][2], h[2][3], h[3][0], h[3][1], h[3][2], h[3][3],
        ]
    }

    fn padding_length_for_input_length(input_length: usize) -> usize {
        if input_length % 64 <= 55 {
            64 - input_length % 64
        } else {
            128 - input_length % 64
        }
    }
}

impl Default for MD5 {
    fn default() -> MD5 {
        MD5 {
            h: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
        }
    }
}

impl From<[u8; 16]> for MD5 {
    fn from(hash: [u8; 16]) -> MD5 {
        MD5 {
            h: [
                u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]),
                u32::from_le_bytes([hash[4], hash[5], hash[6], hash[7]]),
                u32::from_le_bytes([hash[8], hash[9], hash[10], hash[11]]),
                u32::from_le_bytes([hash[12], hash[13], hash[14], hash[15]]),
            ],
        }
    }
}

/// Compute the MD5 padding for the given input length.
///
/// # Arguments
///
/// * `input_length` - The length of the input length. This value is
///     needed to determine the padding length, and to embed the length
///     in the last 8 bytes of padding.
///
/// # Returns
///
/// This function returns MD5 padding for the given input size. This
/// padding has a length you can determine by calling
/// `md5::padding_length_for_input_length`.
///
/// # Example
///
/// ```
/// # use extendhash::md5;
/// let data = "This string will be hashed.";
/// let padding = md5::padding_for_length(data.len());
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
    MD5::padding_for_length(input_length).collect()
}

/// Compute the MD5 padding length (in bytes) for the given
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
/// This function returns the amount of padding required for the given
/// input length.
///
/// # Example
///
/// ```
/// # use extendhash::md5;
/// let data = "This string will be hashed.";
/// let padding_length =
///     md5::padding_length_for_input_length(data.len());
/// assert_eq!(data.len() + padding_length, 64);
/// ```
#[must_use]
pub fn padding_length_for_input_length(input_length: usize) -> usize {
    MD5::padding_length_for_input_length(input_length)
}

/// Compute the MD5 hash of the input data
///
/// # Arguments
///
/// * `input` - The input data to be hashed - this could be a UTF-8
///     string or any other binary data.
///
/// # Returns
///
/// This function returns the computed MD5 hash.
///
/// # Example
///
/// ```
/// # use extendhash::md5;
/// let secret_data = "input string".as_bytes();
/// let hash = md5::compute_hash(secret_data);
/// assert_eq!(hash, [
///     0x16, 0x4c, 0x37, 0x5b, 0x4a, 0x5d, 0xf4, 0x4a,
///     0x33, 0x2c, 0xa3, 0x4b, 0xda, 0x6c, 0xba, 0x9d]);
/// ```
#[must_use]
pub fn compute_hash(input: &[u8]) -> [u8; 16] {
    let data: Vec<u8> = input
        .iter()
        .copied()
        .chain(MD5::padding_for_length(input.len()))
        .collect();

    assert_eq!(data.len() % 64, 0);

    data.chunks_exact(64)
        .fold(MD5::default(), |md5, chunk| md5.apply_chunk(chunk))
        .hash_from_data()
}

/// Calculate an MD5 hash extension.
///
/// # Arguments
///
/// * `hash` - The MD5 hash of some previous (unknown) data
/// * `length` - The length of the unknown data (without any
///       added padding)
/// * `additional_input` - Additional input to be
///       included in the new hash.
///
/// # Returns
///
/// This function returns the MD5 hash of the concatenation of the
/// original unknown data, its padding, and the `additional_input`.
/// You can see the included (intermediate) padding by calling
/// `md5::padding_for_length`.
///
/// # Example
///
/// ```
/// # use extendhash::md5;
/// let secret_data = "This is a secret!".as_bytes();
/// let hash = md5::compute_hash(secret_data);
/// let secret_data_length = secret_data.len();
///
/// // Now we try computing a hash extension, assuming that
/// // `secret_data` is not available. We only need `hash` and
/// // `secret_data_length`.
/// let appended_message = "Appended message.".as_bytes();
/// let combined_hash = md5::extend_hash(
///     hash, secret_data_length, appended_message);
///
/// // Now we verify that `combined_hash` matches the
/// // concatenation (note the intermediate padding):
/// let mut combined_data = Vec::<u8>::new();
/// combined_data.extend_from_slice(secret_data);
/// let padding = md5::padding_for_length(secret_data_length);
/// combined_data.extend_from_slice(padding.as_slice());
/// combined_data.extend_from_slice(appended_message);
/// assert_eq!(
///     combined_hash,
///     md5::compute_hash(combined_data.as_slice()));
/// ```
#[must_use]
pub fn extend_hash(hash: [u8; 16], length: usize, additional_input: &[u8]) -> [u8; 16] {
    let len = length + padding_length_for_input_length(length) + additional_input.len();

    let data: Vec<u8> = additional_input
        .iter()
        .copied()
        .chain(MD5::padding_for_length(len))
        .collect();

    assert_eq!(data.len() % 64, 0);

    data.chunks_exact(64)
        .fold(MD5::from(hash), |md5, chunk| md5.apply_chunk(chunk))
        .hash_from_data()
}

#[cfg(test)]
mod tests {
    use crate::md5;

    #[test]
    fn empty_hash() {
        assert_eq!(
            md5::compute_hash(&[]),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
    }

    #[test]
    fn a_test() {
        assert_eq!(
            md5::compute_hash("a".as_bytes()),
            [
                0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77,
                0x26, 0x61
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test() {
        let s = "The quick brown fox jumps over the lazy dog";
        assert_eq!(
            md5::compute_hash(s.as_bytes()),
            [
                0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4,
                0x19, 0xd6
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test_2() {
        let s = "The quick brown fox jumps over the lazy dog.";
        assert_eq!(
            md5::compute_hash(s.as_bytes()),
            [
                0xe4, 0xd9, 0x09, 0xc2, 0x90, 0xd0, 0xfb, 0x1c, 0xa0, 0x68, 0xff, 0xad, 0xdf, 0x22,
                0xcb, 0xd0
            ]
        );
    }

    #[test]
    fn abc_test() {
        let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                 abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            md5::compute_hash(s.as_bytes()),
            [
                0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41,
                0x9d, 0x9f
            ]
        );
    }

    #[test]
    fn long_test() {
        assert_eq!(
            md5::compute_hash(&[b'a'; 1_000_000]),
            [
                0x77, 0x07, 0xd6, 0xae, 0x4e, 0x02, 0x7c, 0x70, 0xee, 0xa2, 0xa9, 0x35, 0xc2, 0x29,
                0x6f, 0x21
            ]
        );
    }

    #[test]
    fn padding_length_tests() {
        assert_eq!(md5::padding_length_for_input_length(0), 64);
        assert_eq!(md5::padding_length_for_input_length(1), 63);
        assert_eq!(md5::padding_length_for_input_length(2), 62);
        assert_eq!(md5::padding_length_for_input_length(3), 61);
        assert_eq!(md5::padding_length_for_input_length(4), 60);

        assert_eq!(md5::padding_length_for_input_length(50), 14);
        assert_eq!(md5::padding_length_for_input_length(54), 10);
        assert_eq!(md5::padding_length_for_input_length(55), 9);
        assert_eq!(md5::padding_length_for_input_length(56), 64 + 8);
        assert_eq!(md5::padding_length_for_input_length(57), 64 + 7);
        assert_eq!(md5::padding_length_for_input_length(62), 64 + 2);
        assert_eq!(md5::padding_length_for_input_length(63), 64 + 1);
        assert_eq!(md5::padding_length_for_input_length(64), 64);
        assert_eq!(md5::padding_length_for_input_length(128), 64);
        assert_eq!(md5::padding_length_for_input_length(64 * 100000), 64);
    }

    #[test]
    fn test_hash_ext_unknown_length() {
        let secret = "count=10&lat=37.351&user_id=1\
                      &long=-119.827&waffle=eggo"
            .as_bytes();
        let hash = md5::compute_hash(secret);

        let appended_str = "&waffle=liege".as_bytes();
        let target_hash = [
            0xf2, 0xf0, 0x69, 0x64, 0xeb, 0xbf, 0xc3, 0xdb, 0xa5, 0xe1, 0xfb, 0xfe, 0x35, 0x08,
            0x21, 0x49,
        ];
        for length in 0..100 {
            let combined_hash = md5::extend_hash(hash, length, appended_str);
            if combined_hash == target_hash {
                return;
            }
        }
        assert!(false, "No matching hash found");
    }
}
