use hex_literal::hex;

use kerberos_asn1::{AsReq, Asn1Object, TgsReq};

use xbox_sys::crypto::SymmetricKey;

pub const TGS_MASTER_KEY: SymmetricKey =
    SymmetricKey(hex!["8b27f6581f2695da755f8f8ffea571f1"]);

pub enum RequestType {
    As(AsReq),
    Tgs(TgsReq),
}

pub fn request_type(buf: &[u8]) -> Option<RequestType> {
    match buf.get(0) {
        //ASN.1 DER Application 10 tag
        Some(0x6a) => {
            let (rem, as_req) = AsReq::parse(buf)
                .map_err(|err| eprintln!("Warning: Couldn't parse AS-REQ: {:?}: {:02x?}",
                    err, buf))
                .ok()?;
            if !rem.is_empty() {
                eprintln!("Warning: AS-REQ had remainder bytes: {:02x?}", buf);
            }
            Some(RequestType::As(as_req))
        }

        //ASN.1 DER Application 12 tag
        Some(0x6c) => {
            let (rem, tgs_req) = TgsReq::parse(buf)
                .map_err(|err| eprintln!("Warning: Couldn't parse TGS-REQ: {:?}: {:02x?}",
                    err, buf))
                .ok()?;

            if !rem.is_empty() {
                eprintln!("Warning: TGS-REQ had remainder bytes: {:02x?}", buf);
            }
            Some(RequestType::Tgs(tgs_req))
        }
        _ => None,
    }
}
