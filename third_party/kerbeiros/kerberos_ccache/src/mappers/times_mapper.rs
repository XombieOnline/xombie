use crate::Times;
use chrono::{TimeZone, Utc};
use kerberos_asn1::KerberosTime;

pub fn authtime_starttime_endtime_renew_till_to_times(
    authtime: Option<&KerberosTime>,
    starttime: Option<&KerberosTime>,
    endtime: Option<&KerberosTime>,
    renew_till: Option<&KerberosTime>,
) -> Times {
    let authtime_timestamp = if let Some(time) = authtime {
        time.timestamp() as u32
    } else {
        0
    };

    let starttime_timestamp = if let Some(time) = starttime {
        time.timestamp() as u32
    } else {
        0
    };

    let endtime_timestamp = if let Some(time) = endtime {
        time.timestamp() as u32
    } else {
        0
    };

    let renew_till_timestamp = if let Some(time) = renew_till {
        time.timestamp() as u32
    } else {
        0
    };

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
    Option<KerberosTime>,
    Option<KerberosTime>,
    Option<KerberosTime>,
    Option<KerberosTime>,
) {
    let authtime = match times.authtime {
        0 => None,
        _ => Some(KerberosTime::from(
            Utc.timestamp(times.authtime as i64, 0),
        )),
    };
    
    let starttime = match times.starttime {
        0 => None,
        _ => Some(KerberosTime::from(
            Utc.timestamp(times.starttime as i64, 0),
        )),
    };
    
    let endtime = match times.endtime {
        0 => None,
        _ => Some(KerberosTime::from(
            Utc.timestamp(times.endtime as i64, 0),
        )),
    };

    
    let renew_till = match times.renew_till {
        0 => None,
        _ => Some(KerberosTime::from(
            Utc.timestamp(times.renew_till as i64, 0),
        )),
    };

    return (authtime, starttime, endtime, renew_till);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_authtime_starttime_endtime_renew_till_to_times() {
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
            authtime_starttime_endtime_renew_till_to_times(
                Some(&authtime),
                Some(&starttime),
                Some(&endtime),
                Some(&renew_till)
            )
        );
    }

    #[test]
    fn test_authtime_endtime_to_times() {
        let authtime =
            KerberosTime::from(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31));
        let endtime =
            KerberosTime::from(Utc.ymd(2019, 4, 20).and_hms(16, 00, 31));

        let time = Times::new(
            authtime.timestamp() as u32,
            0,
            endtime.timestamp() as u32,
            0,
        );

        assert_eq!(
            time,
            authtime_starttime_endtime_renew_till_to_times(
                Some(&authtime),
                None,
                Some(&endtime),
                None
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
            (
                Some(authtime),
                Some(starttime),
                Some(endtime),
                Some(renew_till)
            ),
            times_to_authtime_starttime_endtime_renew_till(&time)
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
            (Some(authtime.clone()), Some(authtime), Some(endtime), None),
            times_to_authtime_starttime_endtime_renew_till(&time)
        );
    }
}
