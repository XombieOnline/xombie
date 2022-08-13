use nom::IResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MarshalError {

}

type MarshalResult = Result<(), MarshalError>;

fn marshal_be_u16(value: u16, buffer: &mut Vec<u8>) -> MarshalResult {
    buffer.push((value >> 8) as u8);
    buffer.push((value >> 0) as u8);

    Ok(())
}

fn marshal_be_u32(value: u32, buffer: &mut Vec<u8>) -> MarshalResult {
    buffer.push((value >> 24) as u8);
    buffer.push((value >> 16) as u8);
    buffer.push((value >>  8) as u8);
    buffer.push((value >>  0) as u8);

    Ok(())
}

fn marshal_qname(qname: &[String], buffer: &mut Vec<u8>) -> MarshalResult {
    for label in qname {
        let len = label.len();
        if len >= 255 {
            panic!("qname len >= 255: {} \"{}\"", len, label);
        }
        buffer.push(len as u8);
        buffer.append(&mut label.clone().into_bytes());
    }

    buffer.push(0);

    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub trans_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answer_rrs: u16,
    pub authority_rrs: u16,
    pub addition_rrs: u16,
}

impl Header {
    named!(from_buffer<&[u8], Header>,
        do_parse!(
            trans_id:  be_u16 >>
            flags:     be_u16 >>
            questions: be_u16 >>
            answer_rrs: be_u16 >>
            authority_rrs: be_u16 >>
            addition_rrs: be_u16 >>
            (Header {
                trans_id,
                flags,
                questions,
                answer_rrs,
                authority_rrs,
                addition_rrs,
            })
        )
    );

    fn marshal(&self, buffer: &mut Vec<u8>) -> Result<(), MarshalError> {
        marshal_be_u16(self.trans_id, buffer)?;
        marshal_be_u16(self.flags, buffer)?;
        marshal_be_u16(self.questions, buffer)?;
        marshal_be_u16(self.answer_rrs, buffer)?;
        marshal_be_u16(self.authority_rrs, buffer)?;
        marshal_be_u16(self.addition_rrs, buffer)?;

        Ok(())
    }
}

named!(take1, take!(1));
named!(take2, take!(2));

fn be_u8(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, slice) = take1(input)?;
    Ok((input, slice[0]))
}

fn be_u16(input: &[u8]) -> IResult<&[u8], u16> {
    let (input, slice) = take2(input)?;
    let val = u16::from_be_bytes([slice[0], slice[1]]);
    Ok((input, val))
}

named!(parse_label<&[u8], String>,
    do_parse!(
        len: be_u8 >>
        bytes: take!(len as usize) >>
        (std::str::from_utf8(&bytes).unwrap().to_string())
    )
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query {
    pub name: Vec<String>,
    pub dns_type: u16,
    pub class: u16,
}

pub fn name_from_components(domains: &[String]) -> String {
    if domains.len() == 0 {
        return "".to_string();
    }

    let mut ret: String = domains[0].clone();

    for offset in 1..domains.len() {
        ret = format!("{}.{}", ret, domains[offset]);
    }
    
    ret
}

impl Query {
    fn from_buffer(i: &[u8]) -> IResult<&[u8], Query> {
        let mut domains: Vec<String> = Vec::new();
        let mut have_end = false;
        let mut remaining = i;
        while !have_end {
            let (residue, domain) = parse_label(remaining)?;
            remaining = residue;
            if domain == "".to_string() {
                have_end = true;
            } else {
                domains.push(domain);
            }
        }

        let (remaining, dns_type) = be_u16(remaining)?;
        let (remaining, class) = be_u16(remaining)?;

        Ok((remaining, Query {
            name: domains,
            dns_type,
            class,
        }))
    }

    fn marshal(&self, buffer: &mut Vec<u8>) -> MarshalResult {
        marshal_qname(&self.name, buffer)?;
        marshal_be_u16(self.dns_type, buffer)?;
        marshal_be_u16(self.class, buffer)?;

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Answer {
    pub qname: Vec<String>,
    pub dns_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl Answer {
    fn marshal(&self, buffer: &mut Vec<u8>) -> MarshalResult {
        //marshal_qname(&self.qname, buffer)?;
        marshal_be_u16(0xC0_0C, buffer)?;
        marshal_be_u16(self.dns_type, buffer)?;
        marshal_be_u16(self.class, buffer)?;
        marshal_be_u32(self.ttl, buffer)?;
        marshal_be_u16(self.data.len() as u16, buffer)?;
        let mut data = self.data.clone();
        buffer.append(&mut data);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub header: Header,
    pub queries: Vec<Query>,
    pub answers: Vec<Answer>,
}

impl Packet {
    pub fn from_buffer(i: &[u8]) -> IResult<&[u8], Packet> {

        let (after_header, header) = Header::from_buffer(i)?;

        let mut queries = Vec::new();

        let mut remaining = after_header;

        for _ in 0..header.questions {
            let (residue, query) = Query::from_buffer(remaining)?;
            remaining = residue;
            queries.push(query);
        }

        let answers = Vec::new();

        //TODO: parse answers

        Ok((remaining, Packet {
            header,
            queries,
            answers,
        }))
    }

    pub fn marshal(&self, buffer: &mut Vec<u8>) -> MarshalResult {
        self.header.marshal(buffer)?;
        for query in self.queries.iter() {
            query.marshal(buffer)?;
        }
        for answer in self.answers.iter() {
            answer.marshal(buffer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header() {
        let buffer: [u8;12] = [120, 146, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];

        let (remaining, header) = Header::from_buffer(&buffer).unwrap();

        assert_eq!(remaining.len(), 0);
        assert_eq!(header, Header {
            trans_id: 0x7892,
            flags: 0x0100,
            questions: 1,
            answer_rrs: 0,
            authority_rrs: 0,
            addition_rrs: 0,
        });
    }

    #[test]
    fn parse_label_good() {
        let buf = vec![0x4, 0x4d, 0x41, 0x43, 0x53];
        let (remaining, value) = parse_label(&buf).unwrap();
        assert_eq!(remaining.len(), 0);
        assert_eq!(value, "MACS".to_string());
    }

    #[test]
    fn parse_empty_label() {
        let empty_buf = vec![0];
        let (remaining, value) = parse_label(&empty_buf).unwrap();
        assert_eq!(remaining.len(), 0);
        assert_eq!(value, "".to_string());
    }

    #[test]
    fn parse_query() {
        let buffer: [u8;23] = [4, 77, 65, 67, 83, 8, 88, 66, 79, 88, 76, 73, 86, 69, 3, 67, 79, 77, 0, 0, 1, 0, 1];

        let (remaining, query) = Query::from_buffer(&buffer).unwrap();

        assert_eq!(remaining.len(), 0);
        assert_eq!(query, Query {
            name: vec!["MACS".to_string(), "XBOXLIVE".to_string(), "COM".to_string()],
            dns_type: 1,
            class: 1,
        });
    }

    #[test]
    fn marshal_qname_good() {
        let mut buffer = Vec::new();
        marshal_qname(&vec!["MACS".to_string(), "XBOXLIVE".to_string(), "COM".to_string()], &mut buffer).unwrap();

        let expected: Vec<u8> = vec![4, 77, 65, 67, 83, 8, 88, 66, 79, 88, 76, 73, 86, 69, 3, 67, 79, 77, 0];

        assert_eq!(buffer, expected);
    }

    #[test]
    fn names() {
        let domains = vec![
            "MACS".to_string(),
            "XBOXLIVE".to_string(),
            "COM".to_string(),
        ];
        assert_eq!(name_from_components(&domains), "MACS.XBOXLIVE.COM");
    }

    #[test]
    fn empty_domain() {
        let domains = Vec::new();
        assert_eq!(name_from_components(&domains), "");
    }

    #[test]
    fn single_domain() {
        let domains = vec!["com".to_string()];
        assert_eq!(name_from_components(&domains), "com");
    }

    #[test]
    fn parse_simple_packet() {
        let buffer = vec![120, 146, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 77, 65, 67, 83, 8, 88, 66, 79, 88, 76, 73, 86, 69, 3, 67, 79, 77, 0, 0, 1, 0, 1];
        let (remaining, packet) = Packet::from_buffer(&buffer).unwrap();

        assert_eq!(remaining.len(), 0);

        let expected = Packet {
            header: Header {
                trans_id: 0x7892,
                flags: 0x0100,
                questions: 1,
                answer_rrs: 0,
                authority_rrs: 0,
                addition_rrs: 0,
            },
            queries: vec![ Query {
                name: vec!["MACS".to_string(), "XBOXLIVE".to_string(), "COM".to_string()],
                dns_type: 1,
                class: 1,
            }],
            answers: Vec::new(),
        };

        assert_eq!(packet, expected);
    }
}
