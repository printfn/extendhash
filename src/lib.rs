#![doc(html_root_url = "https://docs.rs/extendhash/0.1.0")]

#[derive(Clone)]
pub struct MD5 {
	a0: u32,
	b0: u32,
	c0: u32,
	d0: u32
}

impl MD5 {
	fn apply_chunk(&mut self, chunk: &[u8]) {
		assert_eq!(chunk.len(), 64);

		let s: [u32; 64] = [
			7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
			5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
			4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
			6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];

		let k: [u32; 64] = [
			0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
			0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
			0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
			0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
			0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
			0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
			0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
			0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
			0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
			0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
			0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
			0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
			0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
			0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
			0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
			0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];

		let mut a: u32 = self.a0;
		let mut b: u32 = self.b0;
		let mut c: u32 = self.c0;
		let mut d: u32 = self.d0;

		for i in 0..64 {
			let (mut f, g) = match i {
				 0..=15 => ((b & c) | ((!b) & d),      i          ),
				16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
				32..=47 => (b ^ c ^ d,            (3 * i + 5) % 16),
				48..=63 => (c ^ (b | (!d)),       (7 * i    ) % 16),
				_ => unreachable!()
			};

			let slice = [
				chunk[(4 * g as usize + 0)],
				chunk[(4 * g as usize + 1)],
				chunk[(4 * g as usize + 2)],
				chunk[(4 * g as usize + 3)]];

			f = f.wrapping_add(a).wrapping_add(k[i as usize]).wrapping_add(u32::from_le_bytes(slice));

			a = d;
			d = c;
			c = b;
			b = b.wrapping_add(f.rotate_left(s[i as usize]));
		}

		self.a0 = self.a0.wrapping_add(a);
		self.b0 = self.b0.wrapping_add(b);
		self.c0 = self.c0.wrapping_add(c);
		self.d0 = self.d0.wrapping_add(d);
	}

	fn hash_from_data(&self) -> [u8; 16] {
		let mut result = Vec::<u8>::new();
		result.extend_from_slice(&self.a0.to_le_bytes());
		result.extend_from_slice(&self.b0.to_le_bytes());
		result.extend_from_slice(&self.c0.to_le_bytes());
		result.extend_from_slice(&self.d0.to_le_bytes());
		let mut res = [0; 16];
		res.copy_from_slice(result.as_slice());
		res
	}

	/// This function computes MD5 padding for the given input length.
	pub fn padding_for_length(input_length: usize) -> Vec<u8> {
		let padding_length = MD5::padding_length_for_input_length(input_length);
		let mut result = Vec::<u8>::with_capacity(padding_length);
		result.push(0b1000_0000);
		for _ in 0..(padding_length - 9) {
			result.push(0b0000_0000);
		}
		result.extend_from_slice(&(input_length as u64).wrapping_mul(8).to_le_bytes());
		result
	}

	/// Compute the total padding length (in bytes) for the given input length.
	/// The result is always between 9 and 72 (inclusive).
	pub fn padding_length_for_input_length(input_length: usize) -> usize {
		if input_length % 64 <= 55 {
			64 - input_length % 64
		} else {
			128 - input_length % 64
		}
	}

	/// Compute the MD5 hash of the input data
	///
	/// # Arguments
	///
	/// * `input` - The input data to be hashed - this could be a UTF-8 string
	///     or any other binary data.
	///
	/// # Returns
	///
	/// This function returns the computed MD5 hash.
	pub fn compute_hash(input: &[u8]) -> [u8; 16] {
		let mut md5 = MD5 {
			a0: 0x67452301,
			b0: 0xefcdab89,
			c0: 0x98badcfe,
			d0: 0x10325476
		};

		let mut data = Vec::<u8>::new();
		data.extend_from_slice(input);
		data.extend_from_slice(MD5::padding_for_length(input.len()).as_slice());
		assert_eq!(data.len() % 64, 0);
		for chunk in data.chunks_exact(64) {
			md5.apply_chunk(chunk);
		}

		md5.hash_from_data()
	}

	/// Calculates a hash extension.
	///
	/// # Arguments
	///
	/// * `hash` - The MD5 hash of some previous (unknown) data
	/// * `length` - The length of the unknown data (without any added padding)
	/// * `additional_input` - Additional input to be included in the new hash.
	///
	/// # Returns
	///
	/// This function returns the MD5 hash of the concatenation of the original
	/// unknown data, its padding, and the `additional_input`.
	/// You can see the included (intermediate) padding by calling `MD5::padding_for_length`.
	///
	/// # Example
	///
	/// ```
	/// # use extendhash::MD5;
	/// let secret_data = "This is a secret! ".as_bytes();
	/// let hash = MD5::compute_hash(secret_data);
	/// let secret_data_length = secret_data.len();
	/// 
	/// // Now we try computing a hash extension, assuming that `secret_data`
	/// // is not available. We only need `hash` and `secret_data_length`.
	///
	/// let appended_message = "Appended message.".as_bytes();
	/// let combined_hash = MD5::extend_hash(hash, secret_data_length, appended_message);
	/// 
	/// // Now we verify that `combined_hash` matches the concatenation (note the intermediate
	/// // padding):
	///
	/// let mut combined_data = Vec::<u8>::new();
	/// combined_data.extend_from_slice(secret_data);
	/// combined_data.extend_from_slice(MD5::padding_for_length(secret_data_length).as_slice());
	/// combined_data.extend_from_slice(appended_message);
	/// assert_eq!(combined_hash, MD5::compute_hash(combined_data.as_slice()));
	/// ```
	pub fn extend_hash(hash: [u8; 16], length: usize, additional_input: &[u8]) -> [u8; 16] {
		let mut md5 = MD5 {
			a0: u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]),
			b0: u32::from_le_bytes([hash[4], hash[5], hash[6], hash[7]]),
			c0: u32::from_le_bytes([hash[8], hash[9], hash[10], hash[11]]),
			d0: u32::from_le_bytes([hash[12], hash[13], hash[14], hash[15]])
		};

		let len = length + Self::padding_length_for_input_length(length) + additional_input.len();

		let mut data = Vec::<u8>::new();
		data.extend_from_slice(additional_input);
		data.extend_from_slice(MD5::padding_for_length(len).as_slice());
		assert_eq!(data.len() % 64, 0);

		for chunk in data.chunks_exact(64) {
			md5.apply_chunk(chunk);
		}

		md5.hash_from_data()
	}
}

#[cfg(test)]
mod tests {
	use crate::MD5;

	#[test]
	fn empty_hash() {
		assert_eq!(MD5::compute_hash(&[]), [
			0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
			0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e]);
	}

	#[test]
	fn a_test() {
		assert_eq!(MD5::compute_hash("a".as_bytes()), [
			0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8,
			0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61]);
	}

	#[test]
	fn quick_brown_fox_test() {
		assert_eq!(MD5::compute_hash("The quick brown fox jumps over the lazy dog".as_bytes()), [
			0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82,
			0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6]);
	}

	#[test]
	fn quick_brown_fox_test_2() {
		assert_eq!(MD5::compute_hash("The quick brown fox jumps over the lazy dog.".as_bytes()), [
			0xe4, 0xd9, 0x09, 0xc2, 0x90, 0xd0, 0xfb, 0x1c,
			0xa0, 0x68, 0xff, 0xad, 0xdf, 0x22, 0xcb, 0xd0]);
	}

	#[test]
	fn abc_test() {
		assert_eq!(MD5::compute_hash(
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes()), [
			0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5,
			0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f]);
	}
}