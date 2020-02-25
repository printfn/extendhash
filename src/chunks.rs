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

struct ChainLenIterator<T, I, F, J>
where
    I: Iterator<Item = T>,
    F: FnMut(usize) -> J,
    J: Iterator<Item = T>,
{
    iter1: I,
    len: usize,
    func: F,
    iter2: Option<J>,
}

impl<T, I, F, J> Iterator for ChainLenIterator<T, I, F, J>
where
    I: Iterator<Item = T>,
    F: FnMut(usize) -> J,
    J: Iterator<Item = T>,
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
                    self.iter2 = Some((self.func)(self.len));
                    self.next()
                }
            },
        }
    }
}

pub fn chain_with_len<T, F, J>(iter1: impl Iterator<Item = T>, func: F) -> impl Iterator<Item = T>
where
    F: FnMut(usize) -> J,
    J: Iterator<Item = T>,
{
    ChainLenIterator {
        iter1,
        len: 0,
        func,
        iter2: None,
    }
}

pub struct ArrayLen8Iter<T>
where
    T: Copy,
{
    idx: usize,
    arr: [T; 8],
}

impl<T> Iterator for ArrayLen8Iter<T>
where
    T: Copy,
{
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.idx < 8 {
            let val = self.arr[self.idx];
            self.idx += 1;
            Some(val)
        } else {
            None
        }
    }
}

pub fn make_len_8_array_iter<T>(arr: [T; 8]) -> ArrayLen8Iter<T>
where
    T: Copy,
{
    ArrayLen8Iter { arr, idx: 0 }
}
