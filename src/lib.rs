//! **extendhash** is a Rust crate to compute hash extensions. Currently
//! only MD5 is supported, but more hash algorithms are planned in the future.
//!
//! # Example
//!
//! ```
//! use extendhash::md5;
//!
//! let secret_data = "This is a secret!".as_bytes();
//! let hash = md5::compute_hash(secret_data);
//! let secret_data_length = secret_data.len();
//! 
//! // Now we try computing a hash extension, assuming that `secret_data`
//! // is not available. We only need `hash` and `secret_data_length`.
//! let appended_message = "Appended message.".as_bytes();
//! let combined_hash = md5::extend_hash(hash, secret_data_length, appended_message);
//! 
//! // Now we verify that `combined_hash` matches the
//! // concatenation (note the intermediate padding):
//! let mut combined_data = Vec::<u8>::new();
//! combined_data.extend_from_slice(secret_data);
//! let intermediate_padding = md5::padding_for_length(secret_data_length);
//! combined_data.extend_from_slice(intermediate_padding.as_slice());
//! combined_data.extend_from_slice(appended_message);
//! assert_eq!(combined_hash, md5::compute_hash(combined_data.as_slice()));
//! ```

#![doc(html_root_url = "https://docs.rs/extendhash/0.2.0")]

/// This module contains all functions related to the MD5
/// hash algorithm. In particular, it contains the features needed
/// to compute MD5 hashes and hash extensions.
///
/// # Example
///
/// ```
/// # use extendhash::md5;
/// let secret_data = "This is a secret!".as_bytes();
/// let hash = md5::compute_hash(secret_data);
/// let secret_data_length = secret_data.len();
/// 
/// // Now we try computing a hash extension, assuming that `secret_data`
/// // is not available. We only need `hash` and `secret_data_length`.
/// let appended_message = "Appended message.".as_bytes();
/// let combined_hash = md5::extend_hash(hash, secret_data_length, appended_message);
/// 
/// // Now we verify that `combined_hash` matches the
/// // concatenation (note the intermediate padding):
/// let mut combined_data = Vec::<u8>::new();
/// combined_data.extend_from_slice(secret_data);
/// let intermediate_padding = md5::padding_for_length(secret_data_length);
/// combined_data.extend_from_slice(intermediate_padding.as_slice());
/// combined_data.extend_from_slice(appended_message);
/// assert_eq!(combined_hash, md5::compute_hash(combined_data.as_slice()));
/// ```
pub mod md5;
