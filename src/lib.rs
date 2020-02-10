//! **extendhash** is a Rust crate to compute hash extensions.
//!
//! Supported hash algorithms:
//!
//!   * MD5
//!   * SHA-0
//!   * SHA-1
//!   * SHA-256
//!   * SHA-512
//!
//! # Example
//!
//! ```
//! use extendhash::sha256;
//!
//! let secret_data = "This is a secret!".as_bytes();
//! let hash = sha256::compute_hash(secret_data);
//! let secret_data_length = secret_data.len();
//!
//! // Now we try computing a hash extension, assuming that
//! // `secret_data` is not available. We only need `hash` and
//! // `secret_data_length`.
//! let appended_message = "Appended message.".as_bytes();
//! let combined_hash = sha256::extend_hash(
//!     hash, secret_data_length, appended_message);
//!
//! // Now we verify that `combined_hash` matches the
//! // concatenation (note the intermediate padding):
//! let mut combined_data = Vec::<u8>::new();
//! combined_data.extend_from_slice(secret_data);
//! let padding = sha256::padding_for_length(secret_data_length);
//! combined_data.extend_from_slice(padding.as_slice());
//! combined_data.extend_from_slice(appended_message);
//! assert_eq!(
//!     combined_hash,
//!     sha256::compute_hash(combined_data.as_slice()));
//! ```

#![doc(html_root_url = "https://docs.rs/extendhash/1.0.1")]

/// Compute MD5 hashes and hash extensions.
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
pub mod md5;

/// Shared code for SHA-0 and SHA-1.
pub(crate) mod sha01;

/// Compute SHA-0 hashes and hash extensions.
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
/// // `secret_data` is not available. We only need `hash` and
/// // `secret_data_length`.
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
pub mod sha0;

/// Compute SHA-1 hashes and hash extensions.
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
/// // `secret_data` is not available. We only need `hash` and
/// // `secret_data_length`.
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
pub mod sha1;

/// Compute SHA-256 hashes and hash extensions.
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
/// // `secret_data` is not available. We only need `hash` and
/// // `secret_data_length`.
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
pub mod sha256;

/// Compute SHA-512 hashes and hash extensions.
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
/// // `secret_data` is not available. We only need `hash` and
/// // `secret_data_length`.
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
///     &combined_hash[..],
///     &sha512::compute_hash(combined_data.as_slice())[..]);
/// ```
pub mod sha512;
