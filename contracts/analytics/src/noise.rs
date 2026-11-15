//! The noise: two counts of fair-coin heads per published cell.
//!
//! The coins are the bits of the operating system's random bytes
//! (`/dev/urandom`). A count is the number of heads (1 bits) before the first
//! tail (a 0 bit), so it is `g` with probability `2^-(g+1)`; the difference
//! of two independent counts has the discrete Laplace law the spec calls
//! `lap` (`difference_nonneg`, `difference_neg` in
//! `lean/QedAnalytics/Spec.lean`). Lean proves that law of the model; that the
//! bytes are fair and independent is a property of the operating system, and
//! a count stops at `u32::MAX` heads, which has probability `2^-(2^32)`.
//! No floating point is involved.
use std::io::{self, Read};

pub struct Coins<R> {
    source: R,
    word: u64,
    left: u32,
}

impl Coins<std::fs::File> {
    pub fn system() -> io::Result<Self> {
        Ok(Self::new(std::fs::File::open("/dev/urandom")?))
    }
}

impl<R: Read> Coins<R> {
    pub fn new(source: R) -> Self {
        Self {
            source,
            word: 0,
            left: 0,
        }
    }

    fn flip(&mut self) -> io::Result<bool> {
        if self.left == 0 {
            let mut bytes = [0u8; 8];
            self.source.read_exact(&mut bytes)?;
            self.word = u64::from_le_bytes(bytes);
            self.left = 64;
        }
        let heads = self.word & 1 == 1;
        self.word >>= 1;
        self.left -= 1;
        Ok(heads)
    }

    /// Heads before the first tail.
    pub fn geometric(&mut self) -> io::Result<u32> {
        let mut heads = 0u32;
        while self.flip()? {
            if heads == u32::MAX {
                break;
            }
            heads += 1;
        }
        Ok(heads)
    }

    /// The two counts one published cell needs.
    pub fn pair(&mut self) -> io::Result<(u32, u32)> {
        Ok((self.geometric()?, self.geometric()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_heads_before_the_first_tail() {
        // Bits are read least significant first: 1,1,0 then 0.
        let mut coins = Coins::new(&[0b0000_0011u8, 0, 0, 0, 0, 0, 0, 0][..]);
        assert_eq!(coins.geometric().unwrap(), 2);
        assert_eq!(coins.geometric().unwrap(), 0);
    }

    /// The difference of two counts from the system's bytes has the law
    /// `P(z) = 2^-|z| / 3`: over 300,000 draws each of z in -4..=4 is within
    /// 1 % (absolute) of it, and the mean is within 0.02 of 0.
    #[test]
    fn the_difference_follows_the_discrete_laplace_law() {
        let mut coins = Coins::system().unwrap();
        let n = 300_000;
        let mut seen = std::collections::BTreeMap::new();
        let mut sum = 0i64;
        for _ in 0..n {
            let (a, b) = coins.pair().unwrap();
            let z = a as i64 - b as i64;
            sum += z;
            *seen.entry(z).or_insert(0u32) += 1;
        }
        for z in -4i64..=4 {
            let expected = 1.0 / 3.0 / 2f64.powi(z.unsigned_abs() as i32);
            let got = f64::from(*seen.get(&z).unwrap_or(&0)) / n as f64;
            assert!((got - expected).abs() < 0.01, "z={z}: {got} vs {expected}");
        }
        assert!((sum as f64 / n as f64).abs() < 0.02);
    }
}
