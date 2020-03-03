pub trait Hash<T>: Default + Copy + Clone + From<T> {
    fn apply_chunk(self, chunk: &[u8]) -> Self;
    fn hash_from_data(self) -> T;
    fn padding_length_for_input_length(input_length: usize) -> usize;
}
