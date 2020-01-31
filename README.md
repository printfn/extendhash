# extendhash

[![crates.io](https://img.shields.io/crates/v/extendhash.svg)](https://crates.io/crates/extendhash)
[![docs.rs](https://docs.rs/extendhash/badge.svg)](https://docs.rs/extendhash)

**extendhash** is a Rust library to compute hash extensions. Currently
only MD5 is supported, but more hash algorithms are planned in the future.

## Usage

```rust
# use extendhash::MD5;

let secret_data = "This is a secret!";
let hash = MD5::compute_hash(secret_data.as_bytes());
let secret_data_length = secret_data.len();

// Now we try computing a hash extension, assuming that `secret_data`
// is not available. We only need `hash` and `secret_data_length`.
let appended_message = "Appended message.";
let combined_hash = MD5::extend_hash(hash, secret_data_length, appended_message.as_bytes());

// Now we verify that `combined_hash` matches the concatenation (note the intermediate
// padding):
let mut combined_data = Vec::<u8>::new();
combined_data.extend_from_slice(secret_data.as_bytes());
combined_data.extend_from_slice(MD5::padding_for_length(secret_data_length).as_slice());
combined_data.extend_from_slice(appended_message.as_bytes());
assert_eq!(combined_hash, MD5::compute_hash(combined_data.as_slice()));
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
