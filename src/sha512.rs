#[derive(Clone)]
struct SHA512 {
	h: [u64; 8]
}

impl SHA512 {
	fn apply_chunk(&mut self, chunk: &[u8]) {
		assert_eq!(chunk.len(), 128);

		let k: [u64; 80] = [
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
			0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
			0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
			0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
			0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
			0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
			0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
			0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
			0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
			0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
			0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
			0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
			0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
			0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
			0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
			0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
			0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
			0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
			0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
			0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
			0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
			0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
			0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
			0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
			0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
			0x5fcb6fab3ad6faec, 0x6c44198c4a475817
		];

		let mut a: u64 = self.h[0];
		let mut b: u64 = self.h[1];
		let mut c: u64 = self.h[2];
		let mut d: u64 = self.h[3];
		let mut e: u64 = self.h[4];
		let mut f: u64 = self.h[5];
		let mut g: u64 = self.h[6];
		let mut h: u64 = self.h[7];

		let mut w: [u64; 80] = [0; 80];
		for i in 0..80 {
			if i < 16 {
				w[i] = u64::from_be_bytes([
					chunk[8 * i + 0],
					chunk[8 * i + 1],
					chunk[8 * i + 2],
					chunk[8 * i + 3],
					chunk[8 * i + 4],
					chunk[8 * i + 5],
					chunk[8 * i + 6],
					chunk[8 * i + 7]]);
			} else {
				let s0 = w[i - 15].rotate_right(1)
					^ w[i - 15].rotate_right(8)
					^ (w[i - 15] >> 7);
				let s1 = w[i - 2].rotate_right(19)
					^ w[i - 2].rotate_right(61)
					^ (w[i - 2] >> 6);
				w[i] = w[i - 16]
					.wrapping_add(s0)
					.wrapping_add(w[i - 7])
					.wrapping_add(s1);
			}
		}

		for i in 0..80 {
			let s1 = e.rotate_right(14)
				^ e.rotate_right(18)
				^ e.rotate_right(41);
			let ch = (e & f) ^ ((!e) & g);
			let temp1 = h
				.wrapping_add(s1).wrapping_add(ch)
				.wrapping_add(k[i]).wrapping_add(w[i]);
			let s0 = a.rotate_right(28)
				^ a.rotate_right(34)
				^ a.rotate_right(39);
			let maj = (a & b) ^ (a & c) ^ (b & c);
			let temp2 = s0.wrapping_add(maj);

			h = g;
			g = f;
			f = e;
			e = d.wrapping_add(temp1);
			d = c;
			c = b;
			b = a;
			a = temp1.wrapping_add(temp2);
		}

		self.h[0] = self.h[0].wrapping_add(a);
		self.h[1] = self.h[1].wrapping_add(b);
		self.h[2] = self.h[2].wrapping_add(c);
		self.h[3] = self.h[3].wrapping_add(d);
		self.h[4] = self.h[4].wrapping_add(e);
		self.h[5] = self.h[5].wrapping_add(f);
		self.h[6] = self.h[6].wrapping_add(g);
		self.h[7] = self.h[7].wrapping_add(h);
	}

	fn hash_from_data(&self) -> [u8; 64] {
		let mut result = Vec::<u8>::new();
		result.extend_from_slice(&self.h[0].to_be_bytes());
		result.extend_from_slice(&self.h[1].to_be_bytes());
		result.extend_from_slice(&self.h[2].to_be_bytes());
		result.extend_from_slice(&self.h[3].to_be_bytes());
		result.extend_from_slice(&self.h[4].to_be_bytes());
		result.extend_from_slice(&self.h[5].to_be_bytes());
		result.extend_from_slice(&self.h[6].to_be_bytes());
		result.extend_from_slice(&self.h[7].to_be_bytes());
		let mut res = [0; 64];
		res.copy_from_slice(result.as_slice());
		res
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
pub fn padding_for_length(input_length: usize) -> Vec<u8> {
	let padding_length = padding_length_for_input_length(input_length);
	let mut result = Vec::<u8>::with_capacity(padding_length);
	result.push(0b1000_0000);
	for _ in 0..(padding_length - 17) {
		result.push(0b0000_0000);
	}
	result.extend_from_slice(
		&(input_length as u128).wrapping_mul(8).to_be_bytes());
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
pub fn padding_length_for_input_length(input_length: usize) -> usize {
	if input_length % 128 <= 111 {
		128 - input_length % 128
	} else {
		256 - input_length % 128
	}
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
/// assert_eq!(&hash[..], &[
///     0x61, 0xfd, 0xf5, 0x27, 0xeb, 0x4a, 0x1a, 0x79,
///     0x36, 0x33, 0xea, 0x74, 0x5c, 0x36, 0xae, 0x06,
///     0xf1, 0x97, 0xb5, 0x65, 0xf0, 0x7e, 0xa0, 0xe2,
///     0x25, 0x4c, 0x15, 0x06, 0x4b, 0xd8, 0xc7, 0x44,
///     0xd8, 0xe6, 0x6b, 0x73, 0xc5, 0x5b, 0x40, 0x9b,
///     0x3d, 0xbc, 0xb3, 0xc3, 0xcf, 0x4f, 0x52, 0xd3,
///     0xf2, 0x34, 0xe3, 0xdf, 0xd7, 0xcd, 0x4a, 0x34,
///     0x4b, 0xb8, 0xd8, 0x3b, 0xbf, 0x00, 0x94, 0xdb][..]);
/// ```
pub fn compute_hash(input: &[u8]) -> [u8; 64] {
	let mut sha512 = SHA512 {
		h: [
			0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
			0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
			0x510e527fade682d1, 0x9b05688c2b3e6c1f,
			0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
		]
	};

	let mut data = Vec::<u8>::new();
	data.extend_from_slice(input);
	data.extend_from_slice(padding_for_length(input.len()).as_slice());
	assert_eq!(data.len() % 128, 0);
	for chunk in data.chunks_exact(128) {
		sha512.apply_chunk(chunk);
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
///     &combined_hash[..],
///     &sha512::compute_hash(combined_data.as_slice())[..]);
/// ```
pub fn extend_hash(
	hash: [u8; 64],
	length: usize,
	additional_input: &[u8]) -> [u8; 64] {

	let mut sha512 = SHA512 {
		h: [
			u64::from_be_bytes([
					hash[ 0], hash[ 1], hash[ 2], hash[ 3],
					hash[ 4], hash[ 5], hash[ 6], hash[ 7]]),
			u64::from_be_bytes([
					hash[ 8], hash[ 9], hash[10], hash[11],
					hash[12], hash[13], hash[14], hash[15]]),
			u64::from_be_bytes([
					hash[16], hash[17], hash[18], hash[19],
					hash[20], hash[21], hash[22], hash[23]]),
			u64::from_be_bytes([
					hash[24], hash[25], hash[26], hash[27],
					hash[28], hash[29], hash[30], hash[31]]),
			u64::from_be_bytes([
					hash[32], hash[33], hash[34], hash[35],
					hash[36], hash[37], hash[38], hash[39]]),
			u64::from_be_bytes([
					hash[40], hash[41], hash[42], hash[43],
					hash[44], hash[45], hash[46], hash[47]]),
			u64::from_be_bytes([
					hash[48], hash[49], hash[50], hash[51],
					hash[52], hash[53], hash[54], hash[55]]),
			u64::from_be_bytes([
					hash[56], hash[57], hash[58], hash[59],
					hash[60], hash[61], hash[62], hash[63]])
		]
	};

	let len = length
		+ padding_length_for_input_length(length)
		+ additional_input.len();

	let mut data = Vec::<u8>::new();
	data.extend_from_slice(additional_input);
	data.extend_from_slice(padding_for_length(len).as_slice());
	assert_eq!(data.len() % 128, 0);

	for chunk in data.chunks_exact(128) {
		sha512.apply_chunk(chunk);
	}

	sha512.hash_from_data()
}

#[cfg(test)]
mod tests {
	use crate::sha512;

	#[test]
	fn empty_hash() {
		assert_eq!(&sha512::compute_hash(&[])[..], &[
			0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
			0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
			0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
			0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
			0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
			0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
			0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
			0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e][..]);
	}

	#[test]
	fn a_test() {
		assert_eq!(&sha512::compute_hash("a".as_bytes())[..], &[
			0x1f, 0x40, 0xfc, 0x92, 0xda, 0x24, 0x16, 0x94,
			0x75, 0x09, 0x79, 0xee, 0x6c, 0xf5, 0x82, 0xf2,
			0xd5, 0xd7, 0xd2, 0x8e, 0x18, 0x33, 0x5d, 0xe0,
			0x5a, 0xbc, 0x54, 0xd0, 0x56, 0x0e, 0x0f, 0x53,
			0x02, 0x86, 0x0c, 0x65, 0x2b, 0xf0, 0x8d, 0x56,
			0x02, 0x52, 0xaa, 0x5e, 0x74, 0x21, 0x05, 0x46,
			0xf3, 0x69, 0xfb, 0xbb, 0xce, 0x8c, 0x12, 0xcf,
			0xc7, 0x95, 0x7b, 0x26, 0x52, 0xfe, 0x9a, 0x75][..]);
	}

	#[test]
	fn quick_brown_fox_test() {
		let s = "The quick brown fox jumps over the lazy dog";
		assert_eq!(&sha512::compute_hash(s.as_bytes())[..], &[
			0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73,
			0xf7, 0x3f, 0xba, 0xc0, 0x43, 0x5e, 0xd7, 0x69,
			0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88,
			0xa3, 0x09, 0xd7, 0x85, 0x43, 0x6b, 0xbb, 0x64,
			0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2, 0x39,
			0x12, 0x54, 0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6,
			0xe1, 0xbf, 0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f,
			0xa0, 0x53, 0x8f, 0x3d, 0xb8, 0x54, 0xfe, 0xe6][..]);
	}

	#[test]
	fn quick_brown_fox_test_2() {
		let s = "The quick brown fox jumps over the lazy cog";
		assert_eq!(&sha512::compute_hash(s.as_bytes())[..], &[
			0x3e, 0xee, 0xe1, 0xd0, 0xe1, 0x17, 0x33, 0xef,
			0x15, 0x2a, 0x6c, 0x29, 0x50, 0x3b, 0x3a, 0xe2,
			0x0c, 0x4f, 0x1f, 0x3c, 0xda, 0x4c, 0xb2, 0x6f,
			0x1b, 0xc1, 0xa4, 0x1f, 0x91, 0xc7, 0xfe, 0x4a,
			0xb3, 0xbd, 0x86, 0x49, 0x40, 0x49, 0xe2, 0x01,
			0xc4, 0xbd, 0x51, 0x55, 0xf3, 0x1e, 0xcb, 0x7a,
			0x3c, 0x86, 0x06, 0x84, 0x3c, 0x4c, 0xc8, 0xdf,
			0xca, 0xb7, 0xda, 0x11, 0xc8, 0xae, 0x50, 0x45][..]);
	}

	#[test]
	fn abc_test() {
		let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
			abcdefghijklmnopqrstuvwxyz0123456789";
		assert_eq!(&sha512::compute_hash(s.as_bytes())[..], &[
			0x1e, 0x07, 0xbe, 0x23, 0xc2, 0x6a, 0x86, 0xea,
			0x37, 0xea, 0x81, 0x0c, 0x8e, 0xc7, 0x80, 0x93,
			0x52, 0x51, 0x5a, 0x97, 0x0e, 0x92, 0x53, 0xc2,
			0x6f, 0x53, 0x6c, 0xfc, 0x7a, 0x99, 0x96, 0xc4,
			0x5c, 0x83, 0x70, 0x58, 0x3e, 0x0a, 0x78, 0xfa,
			0x4a, 0x90, 0x04, 0x1d, 0x71, 0xa4, 0xce, 0xab,
			0x74, 0x23, 0xf1, 0x9c, 0x71, 0xb9, 0xd5, 0xa3,
			0xe0, 0x12, 0x49, 0xf0, 0xbe, 0xbd, 0x58, 0x94][..]);
	}

	#[test]
	fn long_test() {
		let mut input = String::new();
		for _ in 0..40000 {
			input.push_str("aaaaaaaaaaaaaaaaaaaaaaaaa");
		}
		assert_eq!(input.len(), 1_000_000);
		assert_eq!(&sha512::compute_hash(input.as_bytes())[..], &[
			0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64,
			0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63,
			0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28,
			0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb,
			0xde, 0x0f, 0xf2, 0x44, 0x87, 0x7e, 0xa6, 0x0a,
			0x4c, 0xb0, 0x43, 0x2c, 0xe5, 0x77, 0xc3, 0x1b,
			0xeb, 0x00, 0x9c, 0x5c, 0x2c, 0x49, 0xaa, 0x2e,
			0x4e, 0xad, 0xb2, 0x17, 0xad, 0x8c, 0xc0, 0x9b][..]);
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
		assert_eq!(
			sha512::padding_length_for_input_length(128 * 100000),
			128);
	}

	#[test]
	fn test_hash_ext() {
		let secret = "count=10&lat=37.351&user_id=1&\
			long=-119.827&waffle=eggo".as_bytes();
		let hash = sha512::compute_hash(secret);

		let appended_str = "&waffle=liege".as_bytes();
		let combined_hash = sha512::extend_hash(
			hash, secret.len(), appended_str);

		let mut concatenation = Vec::<u8>::new();
		concatenation.extend_from_slice(secret);
		let padding = sha512::padding_for_length(secret.len());
		concatenation.extend_from_slice(padding.as_slice());
		concatenation.extend_from_slice(appended_str);
		assert_eq!(
			&combined_hash[..],
			&sha512::compute_hash(concatenation.as_slice())[..]);
	}
}
