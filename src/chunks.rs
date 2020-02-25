struct ChunkIterator<T, I>
where
    I: Iterator<Item = T>,
{
    base_iterator: I,
}

impl<T, I> Iterator for ChunkIterator<T, I>
where
    I: Iterator<Item = T>,
    T: Copy,
{
    type Item = [T; 64];

    fn next(&mut self) -> Option<[T; 64]> {
        let mut next_item: [T; 64] = [match self.base_iterator.next() {
            Some(item) => item,
            None => return None,
        }; 64];
        for val in next_item.iter_mut().skip(1) {
            *val = match self.base_iterator.next() {
                Some(item) => item,
                None => return None,
            }
        }
        Some(next_item)
    }
}

pub fn chunks_from_iter<T: Copy>(
    iterator: impl Iterator<Item = T>,
) -> impl Iterator<Item = [T; 64]> {
    ChunkIterator {
        base_iterator: iterator,
    }
}

struct ChainLenIterator<T, I, F, J, S>
where
    I: Iterator<Item = T>,
    F: FnMut(usize, S) -> J,
    J: Iterator<Item = T>,
    S: Copy,
{
    iter1: I,
    len: usize,
    func: F,
    iter2: Option<J>,
    state: S,
}

impl<T, I, F, J, S> Iterator for ChainLenIterator<T, I, F, J, S>
where
    I: Iterator<Item = T>,
    F: FnMut(usize, S) -> J,
    J: Iterator<Item = T>,
    S: Copy,
{
    type Item = T;

    fn next(&mut self) -> Option<T> {
        match &mut self.iter2 {
            Some(i2) => i2.next(),
            None => match self.iter1.next() {
                Some(res) => {
                    self.len += 1;
                    Some(res)
                }
                None => {
                    self.iter2 = Some((self.func)(self.len, self.state));
                    self.next()
                }
            },
        }
    }
}

pub fn chain_with_len<T, F, J, S>(
    iter1: impl Iterator<Item = T>,
    func: F,
    state: S,
) -> impl Iterator<Item = T>
where
    F: FnMut(usize, S) -> J,
    J: Iterator<Item = T>,
    S: Copy,
{
    ChainLenIterator {
        iter1,
        len: 0,
        func,
        iter2: None,
        state,
    }
}

pub struct U8ArrayIter {
    idx: usize,
    arr: [u8; 8]
}

impl Iterator for U8ArrayIter {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.idx < 8 {
            let val = self.arr[self.idx];
            self.idx += 1;
            Some(val)
        } else {
            None
        }
    }
}

pub fn make_u8_array_iter(arr: [u8; 8]) -> U8ArrayIter {
    U8ArrayIter {
        arr,
        idx: 0
    }
}
