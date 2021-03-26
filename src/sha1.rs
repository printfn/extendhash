use crate::sha01;
use alloc::vec::Vec;

/// Compute the SHA-1 padding for the given input length.
///
/// # Arguments
///
/// * `input_length` - The length of the input length. This value is
///     needed to determine the padding length, and to embed the
///     length in the last 8 bytes of padding.
///
/// # Returns
///
/// This function returns SHA-1 padding for the given input size.
/// This padding has a length you can determine by calling
/// `sha1::padding_length_for_input_length`.
///
/// # Example
///
/// ```
/// # use extendhash::sha1;
/// let data = "This string will be hashed.";
/// let padding = sha1::padding_for_length(data.len());
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

/// Compute the SHA-1 padding length (in bytes) for the given
/// input length.
///
/// The result is always between 9 and 72 (inclusive).
///
/// # Arguments
///
/// * `input_length` - The length of the input length. This value
///     is used because the amount of padding is always such that
///     the total padded string is a multiple of 64 bytes.
///
/// # Returns
///
/// This function returns the amount of padding required for the
/// given input length.
///
/// # Example
///
/// ```
/// # use extendhash::sha1;
/// let data = "This string will be hashed.";
/// let padding_length =
///     sha1::padding_length_for_input_length(data.len());
/// assert_eq!(data.len() + padding_length, 64);
/// ```
#[must_use]
pub const fn padding_length_for_input_length(input_length: usize) -> usize {
    sha01::padding_length_for_input_length(input_length)
}

/// Compute the SHA-1 hash of the input data
///
/// # Arguments
///
/// * `input` - The input data to be hashed - this could be a
///     UTF-8 string or any other binary data.
///
/// # Returns
///
/// This function returns the computed SHA-1 hash.
///
/// # Example
///
/// ```
/// # use extendhash::sha1;
/// let secret_data = "input string".as_bytes();
/// let hash = sha1::compute_hash(secret_data);
/// assert_eq!(hash, [
///     0xb1, 0xa3, 0x9a, 0x26, 0xea, 0x62, 0xa5, 0xc0, 0x75, 0xcd,
///     0x3c, 0xb5, 0xaa, 0x46, 0x49, 0x2c, 0x8e, 0x11, 0x34, 0xb7]);
/// ```
#[must_use]
pub const fn compute_hash(input: &[u8]) -> [u8; 20] {
    sha01::compute_hash(input, sha01::HashType::Sha1)
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
/// This function returns the SHA-1 hash of the
/// concatenation of the original
/// unknown data, its padding, and the `additional_input`.
/// You can see the included (intermediate) padding by
/// calling `sha1::padding_for_length`.
///
/// # Example
///
/// ```
/// # use extendhash::sha1;
/// let secret_data = "This is a secret!".as_bytes();
/// let hash = sha1::compute_hash(secret_data);
/// let secret_data_length = secret_data.len();
///
/// // Now we try computing a hash extension, assuming that
/// // `secret_data` is not available. We only need `hash`
/// // and `secret_data_length`.
/// let appended_message = "Appended message.".as_bytes();
/// let combined_hash = sha1::extend_hash(
///     hash, secret_data_length, appended_message);
///
/// // Now we verify that `combined_hash` matches the
/// // concatenation (note the intermediate padding):
/// let mut combined_data = Vec::<u8>::new();
/// combined_data.extend_from_slice(secret_data);
/// let padding = sha1::padding_for_length(secret_data_length);
/// combined_data.extend_from_slice(padding.as_slice());
/// combined_data.extend_from_slice(appended_message);
/// assert_eq!(
///     combined_hash,
///     sha1::compute_hash(combined_data.as_slice()));
/// ```
#[must_use]
pub const fn extend_hash(hash: [u8; 20], length: usize, additional_input: &[u8]) -> [u8; 20] {
    sha01::extend_hash(hash, length, additional_input, sha01::HashType::Sha1)
}

#[cfg(test)]
mod tests {
    use crate::sha1;
    use alloc::vec::Vec;

    #[test]
    fn empty_hash() {
        assert_eq!(
            sha1::compute_hash(&[]),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn a_test() {
        assert_eq!(
            sha1::compute_hash(b"a"),
            [
                0x86, 0xf7, 0xe4, 0x37, 0xfa, 0xa5, 0xa7, 0xfc, 0xe1, 0x5d, 0x1d, 0xdc, 0xb9, 0xea,
                0xea, 0xea, 0x37, 0x76, 0x67, 0xb8
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test() {
        let s = b"The quick brown fox jumps over the lazy dog";
        assert_eq!(
            sha1::compute_hash(s),
            [
                0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76,
                0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12
            ]
        );
    }

    #[test]
    fn quick_brown_fox_test_2() {
        let s = b"The quick brown fox jumps over the lazy cog";
        assert_eq!(
            sha1::compute_hash(s),
            [
                0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3, 0xe8, 0x5a, 0x0b, 0xd1,
                0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3
            ]
        );
    }

    #[test]
    fn abc_test() {
        let s = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                  abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            sha1::compute_hash(s),
            [
                0x76, 0x1c, 0x45, 0x7b, 0xf7, 0x3b, 0x14, 0xd2, 0x7e, 0x9e, 0x92, 0x65, 0xc4, 0x6f,
                0x4b, 0x4d, 0xda, 0x11, 0xf9, 0x40
            ]
        );
    }

    #[test]
    fn long_test() {
        assert_eq!(
            sha1::compute_hash(&*alloc::vec![b'a'; 1_000_000].into_boxed_slice()),
            [
                0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad,
                0x27, 0x31, 0x65, 0x34, 0x01, 0x6f
            ]
        );
    }

    #[test]
    fn padding_length_tests() {
        assert_eq!(sha1::padding_length_for_input_length(0), 64);
        assert_eq!(sha1::padding_length_for_input_length(1), 63);
        assert_eq!(sha1::padding_length_for_input_length(2), 62);
        assert_eq!(sha1::padding_length_for_input_length(3), 61);
        assert_eq!(sha1::padding_length_for_input_length(4), 60);

        assert_eq!(sha1::padding_length_for_input_length(50), 14);
        assert_eq!(sha1::padding_length_for_input_length(54), 10);
        assert_eq!(sha1::padding_length_for_input_length(55), 9);
        assert_eq!(sha1::padding_length_for_input_length(56), 64 + 8);
        assert_eq!(sha1::padding_length_for_input_length(57), 64 + 7);
        assert_eq!(sha1::padding_length_for_input_length(62), 64 + 2);
        assert_eq!(sha1::padding_length_for_input_length(63), 64 + 1);
        assert_eq!(sha1::padding_length_for_input_length(64), 64);
        assert_eq!(sha1::padding_length_for_input_length(128), 64);
        assert_eq!(sha1::padding_length_for_input_length(64 * 100_000), 64);
    }

    #[test]
    fn test_hash_ext() {
        let secret = b"count=10&lat=37.351&user_id=1&\
                       long=-119.827&waffle=eggo";
        let hash = sha1::compute_hash(secret);

        let appended_str = b"&waffle=liege";
        let combined_hash = sha1::extend_hash(hash, secret.len(), appended_str);

        let mut concatenation = Vec::<u8>::new();
        concatenation.extend_from_slice(secret);
        let padding = sha1::padding_for_length(secret.len());
        concatenation.extend_from_slice(padding.as_slice());
        concatenation.extend_from_slice(appended_str);
        assert_eq!(combined_hash, sha1::compute_hash(concatenation.as_slice()));
    }
}
