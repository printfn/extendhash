# extendhash

[![crates.io](https://img.shields.io/crates/v/extendhash.svg)](https://crates.io/crates/extendhash)
[![docs.rs](https://docs.rs/extendhash/badge.svg)](https://docs.rs/extendhash)

**extendhash** is a Rust library to compute hash extensions.

Supported hash algorithms:

  * MD5
  * SHA-0
  * SHA-1
  * SHA-256

## Usage

```rust
use extendhash::sha256;

let secret_data = "This is a secret!".as_bytes();
let hash = sha256::compute_hash(secret_data);
let secret_data_length = secret_data.len();

// Now we try computing a hash extension,
// assuming that `secret_data` is not available.
// We only need `hash` and `secret_data_length`.
let appended_message = "Appended message.".as_bytes();
let combined_hash = sha256::extend_hash(
	hash, secret_data_length, appended_message);

// Now we verify that `combined_hash` matches the
// concatenation (note the intermediate padding):
let mut combined_data = Vec::<u8>::new();
combined_data.extend_from_slice(secret_data);
let intermediate_padding = sha256::padding_for_length(secret_data_length);
combined_data.extend_from_slice(intermediate_padding.as_slice());
combined_data.extend_from_slice(appended_message);
assert_eq!(combined_hash, sha256::compute_hash(combined_data.as_slice()));
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
