use chrono::{DateTime, FixedOffset, Utc};
use clap::{App, Arg};

use kerberos_asn1::{Asn1Object, AsReq, KdcReqBody, KerberosFlags, KerberosTime, PaData, PrincipalName};
use kerberos_constants::*;
use tokio::net::UdpSocket;

use std::{error::Error, net::SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("get-machine-account")
        .arg(Arg::with_name("serial-number")
            .long("serial-number")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("hdd-key")
            .long("hdd-key")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("online-key")
            .long("online-key")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("server-addr")
            .long("server-addr")
            .takes_value(true)
            .required(true))
        .get_matches();

    let serial_number = matches.value_of("serial-number").unwrap();
    let _hdd_key = matches.value_of("hdd-key").unwrap();
    let _online_key = matches.value_of("online-key").unwrap();
    let server_addr = matches.value_of("server-addr").unwrap();

    let nonce: u32 = 990932720;

    let till_time = DateTime::<FixedOffset>::parse_from_rfc3339("2037-09-13T02:48:05Z").unwrap();
    let till_time = DateTime::<Utc>::from(till_time);

    let macs_as_req = AsReq {
        pvno: protocol_version::PVNO,
        msg_type: message_types::KRB_AS_REQ,
        padata: Some(vec![
            PaData { padata_type: xblive::krb::PA_XBOX_CLIENT_VERSION, padata_value: vec![]},
            PaData { padata_type: xblive::krb::PA_XBOX_PPA, padata_value: vec![]},
            PaData { padata_type: xblive::krb::PA_MSKILE_FOR_CHECK_DUPS, padata_value: vec![]},
            PaData { padata_type: pa_data_types::PA_ENC_TIMESTAMP, padata_value: vec![]},
        ]),
        req_body: KdcReqBody {
            kdc_options: KerberosFlags { flags: kdc_options::CANONICALIZE },
            cname: Some(PrincipalName {
                name_type: principal_names::NT_ENTERPRISE,
                name_string: vec![serial_number.to_owned()],
            }),
            realm: xblive::krb::MACS_REALM.to_owned(),
            sname: Some(xblive::krb::macs_sname()),
            from: None,
            till: KerberosTime {
                time: red_asn1::GeneralizedTime {
                    time: till_time,
                }
            },
            rtime: None,
            nonce,
            etypes: vec![etypes::RC4_HMAC],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        }
    };

    let tx_buf = macs_as_req.build();

    let remote_addr: SocketAddr = server_addr.parse()?;
    let local_addr = "0.0.0.0:0";

    let socket = UdpSocket::bind(local_addr)
        .await?;

    socket.connect(remote_addr)
        .await?;

    socket.send(&tx_buf)
        .await?;

    const MTU_SIZE: usize = 1500;

    let mut rx_buf = [0;MTU_SIZE];

    socket.recv(&mut rx_buf)
        .await?;

    println!("{:02x?}", rx_buf);

    Ok(())
}
