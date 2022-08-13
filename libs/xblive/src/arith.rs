#[allow(dead_code)]
pub const fn roundup(unrounded: usize, to: usize) -> usize {
    let rem = unrounded % to;
    if rem == 0 {
        unrounded
    } else {
        unrounded - rem + to
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundup() {
        assert_eq!(0x000, roundup(0, 0x100));
        assert_eq!(0x100, roundup(1, 0x100));
        assert_eq!(0x100, roundup(0x100, 0x100));
        assert_eq!(0x200, roundup(0x101, 0x100));
    }
}