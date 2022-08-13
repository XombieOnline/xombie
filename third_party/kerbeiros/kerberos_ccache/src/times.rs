use nom::number::complete::be_u32;
use nom::IResult;

/// Holds the differents timestamps handled by Kerberos.
/// # Definition
///
/// ```c
/// times {
///       uint32_t  authtime;
///       uint32_t  starttime;
///       uint32_t  endtime;
///       uint32_t  renew_till;
/// };
/// ```
///
#[derive(Debug, PartialEq, Clone)]
pub struct Times {
    pub authtime: u32,
    pub starttime: u32,
    pub endtime: u32,
    pub renew_till: u32,
}

impl Times {
    pub fn new(
        authtime: u32,
        starttime: u32,
        endtime: u32,
        renew_till: u32,
    ) -> Self {
        return Self {
            authtime,
            starttime,
            endtime,
            renew_till,
        };
    }

    /// Build the binary representation
    pub fn build(&self) -> Vec<u8> {
        let mut bytes = self.authtime.to_be_bytes().to_vec();
        bytes.append(&mut self.starttime.to_be_bytes().to_vec());
        bytes.append(&mut self.endtime.to_be_bytes().to_vec());
        bytes.append(&mut self.renew_till.to_be_bytes().to_vec());

        return bytes;
    }

    /// Creates a new instance from the binary representation
    /// # Error
    /// Returns error when the binary has not the expected format.
    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (rest, authtime) = be_u32(raw)?;
        let (rest, starttime) = be_u32(rest)?;
        let (rest, endtime) = be_u32(rest)?;
        let (rest, renew_till) = be_u32(rest)?;

        return Ok((rest, Self::new(authtime, starttime, endtime, renew_till)));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;

    #[test]
    fn times_to_bytes() {
        assert_eq!(
            vec![
                0x5d, 0x22, 0x00, 0x65, 0x5d, 0x22, 0x00, 0x65, 0x5d, 0x22,
                0x8d, 0x05, 0x5d, 0x23, 0x51, 0xe2
            ],
            Times::new(
                Utc.ymd(2019, 7, 7).and_hms(14, 23, 33).timestamp() as u32,
                Utc.ymd(2019, 7, 7).and_hms(14, 23, 33).timestamp() as u32,
                Utc.ymd(2019, 7, 8).and_hms(0, 23, 33).timestamp() as u32,
                Utc.ymd(2019, 7, 8).and_hms(14, 23, 30).timestamp() as u32,
            )
            .build()
        )
    }

    #[test]
    fn test_parse_times_from_bytes() {
        assert_eq!(
            Times::new(
                Utc.ymd(2019, 7, 7).and_hms(14, 23, 33).timestamp() as u32,
                Utc.ymd(2019, 7, 7).and_hms(14, 23, 33).timestamp() as u32,
                Utc.ymd(2019, 7, 8).and_hms(0, 23, 33).timestamp() as u32,
                Utc.ymd(2019, 7, 8).and_hms(14, 23, 30).timestamp() as u32,
            ),
            Times::parse(&[
                0x5d, 0x22, 0x00, 0x65, 0x5d, 0x22, 0x00, 0x65, 0x5d, 0x22,
                0x8d, 0x05, 0x5d, 0x23, 0x51, 0xe2
            ])
            .unwrap()
            .1
        )
    }

    #[test]
    #[should_panic(expected = "[0], Eof")]
    fn test_parse_times_from_bytes_panic() {
        Times::parse(&[0x0]).unwrap();
    }
}
