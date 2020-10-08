use alloc::vec::Vec;

#[derive(Copy, Clone)]
struct SHA512 {
    h: [u64; 8],
}

impl SHA512 {
    const K: [u64; 80] = [
        0x428a_2f98_d728_ae22,
        0x7137_4491_23ef_65cd,
        0xb5c0_fbcf_ec4d_3b2f,
        0xe9b5_dba5_8189_dbbc,
        0x3956_c25b_f348_b538,
        0x59f1_11f1_b605_d019,
        0x923f_82a4_af19_4f9b,
        0xab1c_5ed5_da6d_8118,
        0xd807_aa98_a303_0242,
        0x1283_5b01_4570_6fbe,
        0x2431_85be_4ee4_b28c,
        0x550c_7dc3_d5ff_b4e2,
        0x72be_5d74_f27b_896f,
        0x80de_b1fe_3b16_96b1,
        0x9bdc_06a7_25c7_1235,
        0xc19b_f174_cf69_2694,
        0xe49b_69c1_9ef1_4ad2,
        0xefbe_4786_384f_25e3,
        0x0fc1_9dc6_8b8c_d5b5,
        0x240c_a1cc_77ac_9c65,
        0x2de9_2c6f_592b_0275,
        0x4a74_84aa_6ea6_e483,
        0x5cb0_a9dc_bd41_fbd4,
        0x76f9_88da_8311_53b5,
        0x983e_5152_ee66_dfab,
        0xa831_c66d_2db4_3210,
        0xb003_27c8_98fb_213f,
        0xbf59_7fc7_beef_0ee4,
        0xc6e0_0bf3_3da8_8fc2,
        0xd5a7_9147_930a_a725,
        0x06ca_6351_e003_826f,
        0x1429_2967_0a0e_6e70,
        0x27b7_0a85_46d2_2ffc,
        0x2e1b_2138_5c26_c926,
        0x4d2c_6dfc_5ac4_2aed,
        0x5338_0d13_9d95_b3df,
        0x650a_7354_8baf_63de,
        0x766a_0abb_3c77_b2a8,
        0x81c2_c92e_47ed_aee6,
        0x9272_2c85_1482_353b,
        0xa2bf_e8a1_4cf1_0364,
        0xa81a_664b_bc42_3001,
        0xc24b_8b70_d0f8_9791,
        0xc76c_51a3_0654_be30,
        0xd192_e819_d6ef_5218,
        0xd699_0624_5565_a910,
        0xf40e_3585_5771_202a,
        0x106a_a070_32bb_d1b8,
        0x19a4_c116_b8d2_d0c8,
        0x1e37_6c08_5141_ab53,
        0x2748_774c_df8e_eb99,
        0x34b0_bcb5_e19b_48a8,
        0x391c_0cb3_c5c9_5a63,
        0x4ed8_aa4a_e341_8acb,
        0x5b9c_ca4f_7763_e373,
        0x682e_6ff3_d6b2_b8a3,
        0x748f_82ee_5def_b2fc,
        0x78a5_636f_4317_2f60,
        0x84c8_7814_a1f0_ab72,
        0x8cc7_0208_1a64_39ec,
        0x90be_fffa_2363_1e28,
        0xa450_6ceb_de82_bde9,
        0xbef9_a3f7_b2c6_7915,
        0xc671_78f2_e372_532b,
        0xca27_3ece_ea26_619c,
        0xd186_b8c7_21c0_c207,
        0xeada_7dd6_cde0_eb1e,
        0xf57d_4f7f_ee6e_d178,
        0x06f0_67aa_7217_6fba,
        0x0a63_7dc5_a2c8_98a6,
        0x113f_9804_bef9_0dae,
        0x1b71_0b35_131c_471b,
        0x28db_77f5_2304_7d84,
        0x32ca_ab7b_40c7_2493,
        0x3c9e_be0a_15c9_bebc,
        0x431d_67c4_9c10_0d4c,
        0x4cc5_d4be_cb3e_42b6,
        0x597f_299c_fc65_7e2a,
        0x5fcb_6fab_3ad6_faec,
        0x6c44_198c_4a47_5817,
    ];

    const fn padding_value_at_idx(input_length: usize, idx: usize) -> u8 {
        let padding_length = Self::padding_length_for_input_length(input_length);
        if idx == 0 {
            0b1000_0000
        } else if idx <= padding_length - 17 {
            0
        } else {
            let offset = idx + 16 - padding_length;
            let bytes = (input_length as u128).wrapping_mul(8).to_be_bytes();
            bytes[offset]
        }
    }

    const fn apply_chunk(self, chunk: [u8; 128]) -> Self {
        let mut w = [0_u64; 80];
        {
            let mut i = 0;
            while i < 80 {
                if i < 16 {
                    w[i] = u64::from_be_bytes([
                        chunk[8 * i],
                        chunk[8 * i + 1],
                        chunk[8 * i + 2],
                        chunk[8 * i + 3],
                        chunk[8 * i + 4],
                        chunk[8 * i + 5],
                        chunk[8 * i + 6],
                        chunk[8 * i + 7],
                    ]);
                } else {
                    let s0 =
                        w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                    let s1 =
                        w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
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
        while i < 80 {
            let current_w = w[i];
            let s1 = h[4].rotate_right(14) ^ h[4].rotate_right(18) ^ h[4].rotate_right(41);
            let ch = (h[4] & h[5]) ^ ((!h[4]) & h[6]);
            let temp1 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(current_w);
            let s0 = h[0].rotate_right(28) ^ h[0].rotate_right(34) ^ h[0].rotate_right(39);
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

    const fn hash_from_data(self) -> [u8; 64] {
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
            h[0][0], h[0][1], h[0][2], h[0][3], h[0][4], h[0][5], h[0][6], h[0][7], h[1][0],
            h[1][1], h[1][2], h[1][3], h[1][4], h[1][5], h[1][6], h[1][7], h[2][0], h[2][1],
            h[2][2], h[2][3], h[2][4], h[2][5], h[2][6], h[2][7], h[3][0], h[3][1], h[3][2],
            h[3][3], h[3][4], h[3][5], h[3][6], h[3][7], h[4][0], h[4][1], h[4][2], h[4][3],
            h[4][4], h[4][5], h[4][6], h[4][7], h[5][0], h[5][1], h[5][2], h[5][3], h[5][4],
            h[5][5], h[5][6], h[5][7], h[6][0], h[6][1], h[6][2], h[6][3], h[6][4], h[6][5],
            h[6][6], h[6][7], h[7][0], h[7][1], h[7][2], h[7][3], h[7][4], h[7][5], h[7][6],
            h[7][7],
        ]
    }

    const fn get_num_chunks(data_length: usize) -> usize {
        (data_length + Self::padding_length_for_input_length(data_length)) / 128
    }

    const fn get_chunk(data: &[u8], data_len: usize, chunk_idx: usize) -> [u8; 128] {
        let mut chunk = [0; 128];
        let mut i = 0;
        while i < 128 {
            if chunk_idx * 128 + i < data.len() {
                chunk[i] = data[chunk_idx * 128 + i];
            } else {
                let padding_len = Self::padding_length_for_input_length(data_len);
                let index_into_padding = chunk_idx * 128 + i - data.len();
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

    const fn padding_length_for_input_length(input_length: usize) -> usize {
        if input_length % 128 <= 111 {
            128 - input_length % 128
        } else {
            256 - input_length % 128
        }
    }

    const fn new() -> Self {
        Self {
            h: [
                0x6a09_e667_f3bc_c908,
                0xbb67_ae85_84ca_a73b,
                0x3c6e_f372_fe94_f82b,
                0xa54f_f53a_5f1d_36f1,
                0x510e_527f_ade6_82d1,
                0x9b05_688c_2b3e_6c1f,
                0x1f83_d9ab_fb41_bd6b,
                0x5be0_cd19_137e_2179,
            ],
        }
    }

    const fn from(hash: [u8; 64]) -> Self {
        Self {
            h: [
                u64::from_be_bytes([
                    hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
                ]),
                u64::from_be_bytes([
                    hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
                ]),
                u64::from_be_bytes([
                    hash[16], hash[17], hash[18], hash[19], hash[20], hash[21], hash[22], hash[23],
                ]),
                u64::from_be_bytes([
                    hash[24], hash[25], hash[26], hash[27], hash[28], hash[29], hash[30], hash[31],
                ]),
                u64::from_be_bytes([
                    hash[32], hash[33], hash[34], hash[35], hash[36], hash[37], hash[38], hash[39],
                ]),
                u64::from_be_bytes([
                    hash[40], hash[41], hash[42], hash[43], hash[44], hash[45], hash[46], hash[47],
                ]),
                u64::from_be_bytes([
                    hash[48], hash[49], hash[50], hash[51], hash[52], hash[53], hash[54], hash[55],
                ]),
                u64::from_be_bytes([
                    hash[56], hash[57], hash[58], hash[59], hash[60], hash[61], hash[62], hash[63],
                ]),
            ],
        }
    }
}

/// Compute the SHA-512 padding for the given input length.
///
/// # Arguments
///
/// * `input_length` - The length of the input length. This value
///     is needed to determine the padding length, and to embed the
///     length in the last 16 bytes of padding.
///
/// # Returns
///
/// This function returns SHA-512 padding for the given input size.
/// This padding has a length you can determine by calling
/// `sha512::padding_length_for_input_length`.
///
/// # Example
///
/// ```
/// # use extendhash::sha512;
/// let data = "This string will be hashed.";
/// let padding = sha512::padding_for_length(data.len());
/// assert_eq!(data.len() + padding.len(), 128);
/// for (i, p) in padding.iter().enumerate() {
///     match i {
///         0       => 0b1000_0000,
///         1..=84  => 0b0000_0000,
///         85      => data.len() as u8 * 8,
///         86..=100 => 0b0000_0000,
///         _       => unreachable!("Invalid padding length")
///     };
/// }
/// ```
#[must_use]
pub fn padding_for_length(input_length: usize) -> Vec<u8> {
    let padding_length = padding_length_for_input_length(input_length);
    let mut result = Vec::with_capacity(padding_length);
    for i in 0..padding_length {
        result.push(SHA512::padding_value_at_idx(input_length, i));
    }
    result
}

/// Compute the SHA-512 padding length (in bytes) for the given
/// input length.
///
/// The result is always between 17 and 112 (inclusive).
///
/// # Arguments
///
/// * `input_length` - The length of the input length. This value is
///     used because the amount of padding is always such that the
///     total padded string is a multiple of 128 bytes.
///
/// # Returns
///
/// This function returns the amount of padding required for the given
/// input length.
///
/// # Example
///
/// ```
/// # use extendhash::sha512;
/// let data = "This string will be hashed.";
/// let padding_length =
///     sha512::padding_length_for_input_length(data.len());
/// assert_eq!(data.len() + padding_length, 128);
/// ```
#[must_use]
pub const fn padding_length_for_input_length(input_length: usize) -> usize {
    SHA512::padding_length_for_input_length(input_length)
}

/// Compute the SHA-512 hash of the input data
///
/// # Arguments
///
/// * `input` - The input data to be hashed - this could be a
///     UTF-8 string or any other binary data.
///
/// # Returns
///
/// This function returns the computed SHA-512 hash.
///
/// # Example
///
/// ```
/// # use extendhash::sha512;
/// let secret_data = "input string".as_bytes();
/// let hash = sha512::compute_hash(secret_data);
/// assert_eq!(hash, [
///     0x61, 0xfd, 0xf5, 0x27, 0xeb, 0x4a, 0x1a, 0x79,
///     0x36, 0x33, 0xea, 0x74, 0x5c, 0x36, 0xae, 0x06,
///     0xf1, 0x97, 0xb5, 0x65, 0xf0, 0x7e, 0xa0, 0xe2,
///     0x25, 0x4c, 0x15, 0x06, 0x4b, 0xd8, 0xc7, 0x44,
///     0xd8, 0xe6, 0x6b, 0x73, 0xc5, 0x5b, 0x40, 0x9b,
///     0x3d, 0xbc, 0xb3, 0xc3, 0xcf, 0x4f, 0x52, 0xd3,
///     0xf2, 0x34, 0xe3, 0xdf, 0xd7, 0xcd, 0x4a, 0x34,
///     0x4b, 0xb8, 0xd8, 0x3b, 0xbf, 0x00, 0x94, 0xdb]);
/// ```
#[must_use]
pub const fn compute_hash(input: &[u8]) -> [u8; 64] {
    let num_chunks = SHA512::get_num_chunks(input.len());
    let mut sha512 = SHA512::new();
    let mut i = 0;
    while i < num_chunks {
        let chunk = SHA512::get_chunk(input, input.len(), i);
        sha512 = sha512.apply_chunk(chunk);
        i += 1;
    }
    sha512.hash_from_data()
}

/// Calculate a SHA-512 hash extension.
///
/// # Arguments
///
/// * `hash` - The SHA-512 hash of some previous (unknown) data
/// * `length` - The length of the unknown data (without any
///       added padding)
/// * `additional_input` - Additional input to be included
///       in the new hash.
///
/// # Returns
///
/// This function returns the SHA-512 hash of the concatenation of the
/// original unknown data, its padding, and the `additional_input`.
/// You can see the included (intermediate) padding by calling
/// `sha512::padding_for_length`.
///
/// # Example
///
/// ```
/// # use extendhash::sha512;
/// let secret_data = "This is a secret!".as_bytes();
/// let hash = sha512::compute_hash(secret_data);
/// let secret_data_length = secret_data.len();
///
/// // Now we try computing a hash extension, assuming that
/// // `secret_data` is not available. We only need `hash`
/// // and `secret_data_length`.
/// let appended_message = "Appended message.".as_bytes();
/// let combined_hash = sha512::extend_hash(
///     hash, secret_data_length, appended_message);
///
/// // Now we verify that `combined_hash` matches the
/// // concatenation (note the intermediate padding):
/// let mut combined_data = Vec::<u8>::new();
/// combined_data.extend_from_slice(secret_data);
/// let padding = sha512::padding_for_length(secret_data_length);
/// combined_data.extend_from_slice(padding.as_slice());
/// combined_data.extend_from_slice(appended_message);
/// assert_eq!(
///     combined_hash,
///     sha512::compute_hash(combined_data.as_slice()));
/// ```
#[must_use]
pub const fn extend_hash(hash: [u8; 64], length: usize, additional_input: &[u8]) -> [u8; 64] {
    let len = length + padding_length_for_input_length(length) + additional_input.len();
    let num_chunks = (additional_input.len() + padding_length_for_input_length(len)) / 128;
    let mut sha512 = SHA512::from(hash);
    let mut i = 0;
    while i < num_chunks {
        let chunk = SHA512::get_chunk(additional_input, len, i);
        sha512 = sha512.apply_chunk(chunk);
        i += 1;
    }
    sha512.hash_from_data()
}

#[cfg(test)]
mod tests {
    use crate::sha512;
    use alloc::vec::Vec;

    #[test]
    fn empty_hash() {
        assert_eq!(
            sha512::compute_hash(&[]),
            [
                0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
                0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
                0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
                0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
            ]
        );
    }

    #[test]
    fn a_test() {
        assert_eq!(
            sha512::compute_hash(b"a"),
            [
                0x1f, 0x40, 0xfc, 0x92, 0xda, 0x24, 0x16, 0x94, 0x75, 0x09, 0x79, 0xee, 0x6c, 0xf5,
                0x82, 0xf2, 0xd5, 0xd7, 0xd2, 0x8e, 0x18, 0x33, 0x5d, 0xe0, 0x5a, 0xbc, 0x54, 0xd0,
                0x56, 0x0e, 0x0f, 0x53, 0x02, 0x86, 0x0c, 0x65, 0x2b, 0xf0, 0x8d, 0x56, 0x02, 0x52,
                0xaa, 0x5e, 0x74, 0x21, 0x05, 0x46, 0xf3, 0x69, 0xfb, 0xbb, 0xce, 0x8c, 0x12, 0xcf,
                0xc7, 0x95, 0x7b, 0x26, 0x52, 0xfe, 0x9a, 0x75
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test() {
        let s = b"The quick brown fox jumps over the lazy dog";
        assert_eq!(
            sha512::compute_hash(s),
            [
                0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73, 0xf7, 0x3f, 0xba, 0xc0, 0x43, 0x5e,
                0xd7, 0x69, 0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88, 0xa3, 0x09, 0xd7, 0x85,
                0x43, 0x6b, 0xbb, 0x64, 0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2, 0x39, 0x12, 0x54,
                0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6, 0xe1, 0xbf, 0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f,
                0xa0, 0x53, 0x8f, 0x3d, 0xb8, 0x54, 0xfe, 0xe6
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test_2() {
        let s = b"The quick brown fox jumps over the lazy cog";
        assert_eq!(
            sha512::compute_hash(s),
            [
                0x3e, 0xee, 0xe1, 0xd0, 0xe1, 0x17, 0x33, 0xef, 0x15, 0x2a, 0x6c, 0x29, 0x50, 0x3b,
                0x3a, 0xe2, 0x0c, 0x4f, 0x1f, 0x3c, 0xda, 0x4c, 0xb2, 0x6f, 0x1b, 0xc1, 0xa4, 0x1f,
                0x91, 0xc7, 0xfe, 0x4a, 0xb3, 0xbd, 0x86, 0x49, 0x40, 0x49, 0xe2, 0x01, 0xc4, 0xbd,
                0x51, 0x55, 0xf3, 0x1e, 0xcb, 0x7a, 0x3c, 0x86, 0x06, 0x84, 0x3c, 0x4c, 0xc8, 0xdf,
                0xca, 0xb7, 0xda, 0x11, 0xc8, 0xae, 0x50, 0x45
            ]
        );
    }

    #[test]
    fn abc_test() {
        let s = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                  abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            sha512::compute_hash(s),
            [
                0x1e, 0x07, 0xbe, 0x23, 0xc2, 0x6a, 0x86, 0xea, 0x37, 0xea, 0x81, 0x0c, 0x8e, 0xc7,
                0x80, 0x93, 0x52, 0x51, 0x5a, 0x97, 0x0e, 0x92, 0x53, 0xc2, 0x6f, 0x53, 0x6c, 0xfc,
                0x7a, 0x99, 0x96, 0xc4, 0x5c, 0x83, 0x70, 0x58, 0x3e, 0x0a, 0x78, 0xfa, 0x4a, 0x90,
                0x04, 0x1d, 0x71, 0xa4, 0xce, 0xab, 0x74, 0x23, 0xf1, 0x9c, 0x71, 0xb9, 0xd5, 0xa3,
                0xe0, 0x12, 0x49, 0xf0, 0xbe, 0xbd, 0x58, 0x94
            ]
        );
    }

    #[test]
    fn long_test() {
        assert_eq!(
            sha512::compute_hash(&*alloc::vec![b'a'; 1_000_000].into_boxed_slice()),
            [
                0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64, 0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15,
                0xb4, 0x63, 0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28, 0x56, 0x32, 0xa8, 0x03,
                0xaf, 0xa9, 0x73, 0xeb, 0xde, 0x0f, 0xf2, 0x44, 0x87, 0x7e, 0xa6, 0x0a, 0x4c, 0xb0,
                0x43, 0x2c, 0xe5, 0x77, 0xc3, 0x1b, 0xeb, 0x00, 0x9c, 0x5c, 0x2c, 0x49, 0xaa, 0x2e,
                0x4e, 0xad, 0xb2, 0x17, 0xad, 0x8c, 0xc0, 0x9b
            ]
        );
    }

    #[test]
    fn padding_length_tests() {
        assert_eq!(sha512::padding_length_for_input_length(0), 128);
        assert_eq!(sha512::padding_length_for_input_length(1), 127);
        assert_eq!(sha512::padding_length_for_input_length(2), 126);
        assert_eq!(sha512::padding_length_for_input_length(3), 125);
        assert_eq!(sha512::padding_length_for_input_length(4), 124);

        assert_eq!(sha512::padding_length_for_input_length(50), 78);
        assert_eq!(sha512::padding_length_for_input_length(51), 77);
        assert_eq!(sha512::padding_length_for_input_length(100), 28);
        assert_eq!(sha512::padding_length_for_input_length(101), 27);
        assert_eq!(sha512::padding_length_for_input_length(111), 17);
        assert_eq!(sha512::padding_length_for_input_length(112), 144);
        assert_eq!(sha512::padding_length_for_input_length(113), 143);
        assert_eq!(sha512::padding_length_for_input_length(126), 130);
        assert_eq!(sha512::padding_length_for_input_length(127), 129);
        assert_eq!(sha512::padding_length_for_input_length(128), 128);
        assert_eq!(sha512::padding_length_for_input_length(256), 128);
        assert_eq!(sha512::padding_length_for_input_length(128 * 100_000), 128);
    }

    #[test]
    fn test_hash_ext() {
        let secret = b"count=10&lat=37.351&user_id=1&\
                       long=-119.827&waffle=eggo";
        let hash = sha512::compute_hash(secret);

        let appended_str = b"&waffle=liege";
        let combined_hash = sha512::extend_hash(hash, secret.len(), appended_str);

        let mut concatenation = Vec::<u8>::new();
        concatenation.extend_from_slice(secret);
        let padding = sha512::padding_for_length(secret.len());
        concatenation.extend_from_slice(padding.as_slice());
        concatenation.extend_from_slice(appended_str);
        assert_eq!(
            combined_hash,
            sha512::compute_hash(concatenation.as_slice())
        );
    }
}
