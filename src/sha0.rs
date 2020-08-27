use crate::sha01;
use alloc::vec::Vec;

/// Compute the SHA-0 padding for the given input length.
///
/// # Arguments
///
/// * `input_length` - The length of the input length. This value is
///     needed to determine the padding length, and to embed the
///     length in the last 8 bytes of padding.
///
/// # Returns
///
/// This function returns SHA-0 padding for the given input size.
/// This padding has a length you can determine by calling
/// `sha1::padding_length_for_input_length`.
///
/// # Example
///
/// ```
/// # use extendhash::sha0;
/// let data = "This string will be hashed.";
/// let padding = sha0::padding_for_length(data.len());
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
    sha01::padding_for_length(input_length)
}

/// Compute the SHA-0 padding length (in bytes) for the
/// given input length.
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
/// # use extendhash::sha0;
/// let data = "This string will be hashed.";
/// let padding_length =
///     sha0::padding_length_for_input_length(data.len());
/// assert_eq!(data.len() + padding_length, 64);
/// ```
#[must_use]
pub const fn padding_length_for_input_length(input_length: usize) -> usize {
    sha01::padding_length_for_input_length(input_length)
}

/// Compute the SHA-0 hash of the input data
///
/// # Arguments
///
/// * `input` - The input data to be hashed - this could be a UTF-8
///     string or any other binary data.
///
/// # Returns
///
/// This function returns the computed SHA-0 hash.
///
/// # Example
///
/// ```
/// # use extendhash::sha0;
/// let secret_data = "abc".as_bytes();
/// let hash = sha0::compute_hash(secret_data);
/// assert_eq!(hash, [
///     0x01, 0x64, 0xb8, 0xa9, 0x14, 0xcd, 0x2a, 0x5e, 0x74, 0xc4,
///     0xf7, 0xff, 0x08, 0x2c, 0x4d, 0x97, 0xf1, 0xed, 0xf8, 0x80]);
/// ```
#[must_use]
pub fn compute_hash(input: &[u8]) -> [u8; 20] {
    sha01::compute_hash(input, sha01::HashType::SHA0)
}

/// Calculate a SHA-1 hash extension.
///
/// # Arguments
///
/// * `hash` - The SHA-1 hash of some previous (unknown) data
/// * `length` - The length of the unknown data (without
///       any added padding)
/// * `additional_input` - Additional input to be
///       included in the new hash.
///
/// # Returns
///
/// This function returns the SHA-1 hash of the concatenation of the
/// original unknown data, its padding, and the `additional_input`.
/// You can see the included (intermediate) padding by
/// calling `sha1::padding_for_length`.
///
/// # Example
///
/// ```
/// # use extendhash::sha0;
/// let secret_data = "This is a secret!".as_bytes();
/// let hash = sha0::compute_hash(secret_data);
/// let secret_data_length = secret_data.len();
///
/// // Now we try computing a hash extension, assuming that
/// // `secret_data` is not available. We only need `hash`
/// // and `secret_data_length`.
/// let appended_message = "Appended message.".as_bytes();
/// let combined_hash = sha0::extend_hash(
///     hash, secret_data_length, appended_message);
///
/// // Now we verify that `combined_hash` matches the
/// // concatenation (note the intermediate padding):
/// let mut combined_data = Vec::<u8>::new();
/// combined_data.extend_from_slice(secret_data);
/// let padding = sha0::padding_for_length(secret_data_length);
/// combined_data.extend_from_slice(padding.as_slice());
/// combined_data.extend_from_slice(appended_message);
/// assert_eq!(
///     combined_hash,
///     sha0::compute_hash(combined_data.as_slice()));
/// ```
#[must_use]
pub fn extend_hash(hash: [u8; 20], length: usize, additional_input: &[u8]) -> [u8; 20] {
    sha01::extend_hash(hash, length, additional_input, sha01::HashType::SHA0)
}

#[cfg(test)]
mod tests {
    use crate::sha0;
    use alloc::vec::Vec;

    #[test]
    fn abc_test() {
        assert_eq!(
            sha0::compute_hash(b"abc"),
            [
                0x01, 0x64, 0xb8, 0xa9, 0x14, 0xcd, 0x2a, 0x5e, 0x74, 0xc4, 0xf7, 0xff, 0x08, 0x2c,
                0x4d, 0x97, 0xf1, 0xed, 0xf8, 0x80
            ]
        );
    }

    #[test]
    fn slightly_longer_test() {
        let input = b"abcdbcdecdefdefgefghfghighi\
                      jhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            sha0::compute_hash(input),
            [
                0xd2, 0x51, 0x6e, 0xe1, 0xac, 0xfa, 0x5b, 0xaf, 0x33, 0xdf, 0xc1, 0xc4, 0x71, 0xe4,
                0x38, 0x44, 0x9e, 0xf1, 0x34, 0xc8
            ]
        );
    }

    #[test]
    fn padding_length_tests() {
        assert_eq!(sha0::padding_length_for_input_length(0), 64);
        assert_eq!(sha0::padding_length_for_input_length(1), 63);
        assert_eq!(sha0::padding_length_for_input_length(2), 62);
        assert_eq!(sha0::padding_length_for_input_length(3), 61);
        assert_eq!(sha0::padding_length_for_input_length(4), 60);

        assert_eq!(sha0::padding_length_for_input_length(50), 14);
        assert_eq!(sha0::padding_length_for_input_length(54), 10);
        assert_eq!(sha0::padding_length_for_input_length(55), 9);
        assert_eq!(sha0::padding_length_for_input_length(56), 64 + 8);
        assert_eq!(sha0::padding_length_for_input_length(57), 64 + 7);
        assert_eq!(sha0::padding_length_for_input_length(62), 64 + 2);
        assert_eq!(sha0::padding_length_for_input_length(63), 64 + 1);
        assert_eq!(sha0::padding_length_for_input_length(64), 64);
        assert_eq!(sha0::padding_length_for_input_length(128), 64);
        assert_eq!(sha0::padding_length_for_input_length(64 * 100_000), 64);
    }

    #[test]
    fn test_hash_ext() {
        let secret = b"count=10&lat=37.351&user_id=1&\
                       long=-119.827&waffle=eggo";
        let hash = sha0::compute_hash(secret);

        let appended_str = b"&waffle=liege";
        let combined_hash = sha0::extend_hash(hash, secret.len(), appended_str);

        let mut concatenation = Vec::<u8>::new();
        concatenation.extend_from_slice(secret);
        let padding = sha0::padding_for_length(secret.len());
        concatenation.extend_from_slice(padding.as_slice());
        concatenation.extend_from_slice(appended_str);
        assert_eq!(combined_hash, sha0::compute_hash(concatenation.as_slice()));
    }
}
