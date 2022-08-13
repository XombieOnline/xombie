use chrono::{TimeZone, Utc};
use kerberos_asn1::KerberosTime;
use kerberos_ccache::Times;

pub struct TimesMapper {}

impl TimesMapper {
    pub fn authtime_starttime_endtime_renew_till_to_times(
        authtime: &KerberosTime,
        starttime: Option<&KerberosTime>,
        endtime: &KerberosTime,
        renew_till: Option<&KerberosTime>,
    ) -> Times {
        let authtime_timestamp = authtime.timestamp() as u32;
        let endtime_timestamp = endtime.timestamp() as u32;
        let starttime_timestamp;
        let renew_till_timestamp;

        if let Some(starttime) = starttime {
            starttime_timestamp = starttime.timestamp() as u32;
        } else {
            starttime_timestamp = authtime_timestamp;
        }

        if let Some(renew_till) = renew_till {
            renew_till_timestamp = renew_till.timestamp() as u32;
        } else {
            renew_till_timestamp = 0
        }

        return Times::new(
            authtime_timestamp,
            starttime_timestamp,
            endtime_timestamp,
            renew_till_timestamp,
        );
    }

    pub fn times_to_authtime_starttime_endtime_renew_till(
        times: &Times,
    ) -> (
        KerberosTime,
        KerberosTime,
        KerberosTime,
        Option<KerberosTime>,
    ) {
        let authtime =
            KerberosTime::from(Utc.timestamp(times.authtime as i64, 0));
        let starttime =
            KerberosTime::from(Utc.timestamp(times.starttime as i64, 0));
        let endtime =
            KerberosTime::from(Utc.timestamp(times.endtime as i64, 0));

        let renew_till = match times.renew_till {
            0 => None,
            _ => Some(KerberosTime::from(
                Utc.timestamp(times.renew_till as i64, 0),
            )),
        };

        return (authtime, starttime, endtime, renew_till);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn authtime_starttime_endtime_renew_till_to_times() {
        let authtime =
            KerberosTime::from(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31));
        let starttime =
            KerberosTime::from(Utc.ymd(2019, 4, 19).and_hms(06, 00, 31));
        let endtime =
            KerberosTime::from(Utc.ymd(2019, 4, 20).and_hms(16, 00, 31));
        let renew_till =
            KerberosTime::from(Utc.ymd(2019, 4, 25).and_hms(06, 00, 31));

        let time = Times::new(
            authtime.timestamp() as u32,
            starttime.timestamp() as u32,
            endtime.timestamp() as u32,
            renew_till.timestamp() as u32,
        );

        assert_eq!(
            time,
            TimesMapper::authtime_starttime_endtime_renew_till_to_times(
                &authtime,
                Some(&starttime),
                &endtime,
                Some(&renew_till)
            )
        );
    }

    #[test]
    fn authtime_endtime_to_times() {
        let authtime =
            KerberosTime::from(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31));
        let endtime =
            KerberosTime::from(Utc.ymd(2019, 4, 20).and_hms(16, 00, 31));

        let time = Times::new(
            authtime.timestamp() as u32,
            authtime.timestamp() as u32,
            endtime.timestamp() as u32,
            0,
        );

        assert_eq!(
            time,
            TimesMapper::authtime_starttime_endtime_renew_till_to_times(
                &authtime, None, &endtime, None
            )
        );
    }

    #[test]
    fn test_times_to_authtime_starttime_endtime_renew_till() {
        let authtime =
            KerberosTime::from(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31));
        let starttime =
            KerberosTime::from(Utc.ymd(2019, 4, 19).and_hms(06, 00, 31));
        let endtime =
            KerberosTime::from(Utc.ymd(2019, 4, 20).and_hms(16, 00, 31));
        let renew_till =
            KerberosTime::from(Utc.ymd(2019, 4, 25).and_hms(06, 00, 31));

        let time = Times::new(
            authtime.timestamp() as u32,
            starttime.timestamp() as u32,
            endtime.timestamp() as u32,
            renew_till.timestamp() as u32,
        );

        assert_eq!(
            (authtime, starttime, endtime, Some(renew_till)),
            TimesMapper::times_to_authtime_starttime_endtime_renew_till(&time)
        );
    }

    #[test]
    fn test_times_to_authtime_endtime() {
        let authtime =
            KerberosTime::from(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31));
        let endtime =
            KerberosTime::from(Utc.ymd(2019, 4, 20).and_hms(16, 00, 31));

        let time = Times::new(
            authtime.timestamp() as u32,
            authtime.timestamp() as u32,
            endtime.timestamp() as u32,
            0,
        );

        assert_eq!(
            (authtime.clone(), authtime, endtime, None),
            TimesMapper::times_to_authtime_starttime_endtime_renew_till(&time)
        );
    }
}
