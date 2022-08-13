use bytes::BufMut;

use httparse::{EMPTY_HEADER, Status};

use log::debug;

use std::convert::Infallible;
use std::collections::BTreeMap;
use std::future::Future;
use std::str::{FromStr, from_utf8};
use std::sync::Arc;

use crate::tcp::{AcceptFn, TcpStream};

pub fn gen_http_accept<Ctx, FutResult, F>(ctx: Ctx, request_fn: Arc<F>) -> AcceptFn
where
	Ctx: Clone + Send + 'static + Sync,
	FutResult: Future<Output = Result<Response, Infallible>> + Send + 'static,
	F:  (Fn(Ctx, Request) -> FutResult) + Clone + Send + 'static + Sync,
{
	Box::new(move |stream: TcpStream| {
		let ctx = ctx.clone();
		let request_fn = request_fn.clone();
		tokio::spawn(run_http_connection(stream, ctx, request_fn));
		Ok(())
	})
}

async fn run_http_connection<Ctx, FutResult, F>(mut stream: TcpStream, ctx: Ctx, request_fn: Arc<F>)
where
	Ctx: Clone + Send + 'static + Sync,
	FutResult: Future<Output = Result<Response, Infallible>> + Send + 'static,
	F:  (Fn(Ctx, Request) -> FutResult) + Clone + Send + 'static,
{
	let mut complete_buf = vec![];
	loop {
		let mut buf = stream.read()
			.await.unwrap();
		complete_buf.append(&mut buf);
		match RequestHeader::parse(&complete_buf) {
			Ok(header) => {
				match header.content_len {
					None => debug!("todo add content len max"),
					Some(content_len) => {
						if complete_buf.len() < header.header_len + content_len {
							continue
						} else {
							break
						}
					}
				}
				break
			}
			Err(ParseReqError::Partial) => continue,
			Err(e) => panic!("Parse failure: {:?}", e),
		}
	}

	let header = RequestHeader::parse(&complete_buf)
		.unwrap();

	let req = Request {
		header,
		bytes: complete_buf,
	};

	let mut reply = (request_fn)(ctx, req)
		.await.unwrap();

	let mut header_bytes = vec![];
	reply.put_header(&mut header_bytes);

	header_bytes.append(&mut reply.body);

	stream.write(header_bytes)
		.await;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Method {
	Get,
	Put,
	Post,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
	Http09,
	Http10,
	Http11,
}

impl Version {
	pub fn as_str(&self) -> &'static str {
		match self {
			Version::Http09 => "HTTP/0.9",
			Version::Http10 => "HTTP/1.0",
			Version::Http11 => "HTTP/1.1",
		}
	}
}

#[derive(Debug)]
pub enum ParseReqError {
	HttparseError(httparse::Error),
	Partial,
	Missing(&'static str),
	UnknownElement(&'static str, String),
	HeaderParse(String, Vec<u8>),
	MultipleHeaders(String, String, String),
	ContentLengthParse(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusCode {
	Ok200,

	NotFound404,

	InternalServerError500,
}

impl StatusCode {
	pub fn as_str(&self) -> &'static str {
		use StatusCode::*;
		match self {
			Ok200                  => "200 OK",
			NotFound404            => "404 Not Found",
			InternalServerError500 => "500 Internal Server Error",
		}
	}
}

#[derive(Debug)]
pub struct RequestHeader {
	pub method: Method,
	pub path: String,
	pub version: Version,
	pub headers: BTreeMap<String, String>,
	pub header_len: usize,
	pub content_len: Option<usize>,
}

impl RequestHeader {
	fn parse(buf: &[u8]) -> Result<Self, ParseReqError> {
		let mut httparse_headers = [EMPTY_HEADER; 64];
		let mut req = httparse::Request::new(&mut httparse_headers);
		let complete = req.parse(buf)
			.map_err(|err| ParseReqError::HttparseError(err))?;
		let header_len = match complete {
			Status::Complete(header_len) => header_len,
			Status::Partial => {
				return Err(ParseReqError::Partial)
			}
		};

		use ParseReqError::*;
		let method = match req.method {
			None => return Err(Missing("method")),
			Some("GET") => Method::Get,
			Some("POST") => Method::Post,
			Some("PUT") => Method::Put,
			Some(other) => return Err(UnknownElement("method", other.to_owned())),
		};

		let path = req.path
			.ok_or(Missing("path"))?
			.to_owned();

		let version = match req.version {
			None => return Err(Missing("version")),
			Some(0) => Version::Http10,
			Some(1) => Version::Http11,
			Some(other) => return Err(UnknownElement("version", format!("{}", other))),
		};

		let mut headers = BTreeMap::new();
		for header in httparse_headers {
			if header == EMPTY_HEADER {
				continue;
			}
			let value = from_utf8(header.value)
				.map_err(|_| HeaderParse(header.name.to_owned(), header.value.to_vec()))?;
			let prev = headers.insert(header.name.to_owned(), value.to_owned());
			if let Some(prev_value) = prev {
				return Err(MultipleHeaders(header.name.to_owned(), prev_value, value.to_owned()))
			}
		}

		let content_len = if let Some(value) = headers.get("Content-Length") {
			let value = usize::from_str(value.as_str())
				.map_err(|_| ContentLengthParse(value.clone()))?;
			Some(value)
		} else {
			None
		};

		Ok(RequestHeader {
			method,
			path,
			version,
			headers,
			header_len,
			content_len,
		})
	}
}

#[derive(Debug)]
pub struct Request {
	pub header: RequestHeader,
	pub bytes: Vec<u8>,
}

impl Request {
	pub fn body_bytes<'a>(&'a self) -> &'a [u8] {
		&self.bytes[self.header.header_len..]
	}
}

#[derive(Debug)]
pub struct ResponseHeader {
	pub version: Version,
	pub code: StatusCode,
	pub headers: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct Response {
	pub header: ResponseHeader,
	pub body: Vec<u8>,
}

const CONTENT_TYPE:   &'static str = "Content-Type";
const CONTENT_LENGTH: &'static str = "Content-Length";

impl Response {
	pub fn header_string(&self) -> String {
		let mut header_string = String::new();
		header_string += format!("{} {}\r\n",
			self.header.version.as_str(),
			self.header.code.as_str()
		).as_str();
		for (name, value) in self.header.headers.iter() {
			header_string += format!("{}: {}\r\n", name, value).as_str();
		}
		header_string += "\r\n";

		header_string
	}

	pub fn put_header<AnyBufMut: BufMut>(&self, buf: &mut AnyBufMut) {
		let s = self.header_string();
		buf.put_slice(s.as_bytes())
	}

	pub fn generate_good_response(req: &Request, content_type: &str, body: Vec<u8>) -> Response {
		let mut headers = BTreeMap::new();
		add_content_type(&mut headers, content_type);
		add_content_length(&mut headers, &body);

		Response {
			header: ResponseHeader {
				version: req.header.version,
				code: StatusCode::Ok200,
				headers,
			},
			body,
		}
	}

	pub fn generate_internal_server_error(req: &Request) -> Response {
		const TEXT: &'static str = "Server Error";

		let body = TEXT.as_bytes().to_vec();

		let mut headers = BTreeMap::new();
		add_content_length(&mut headers, &body);
		add_content_type(&mut headers, "text/plain");

		Response {
			header: ResponseHeader {
				version: req.header.version,
				code: StatusCode::InternalServerError500,
				headers,
			},
			body,
		}
	}
}

fn add_content_length(headers: &mut BTreeMap<String, String>, body: &[u8]) {
	headers.insert(String::from(CONTENT_LENGTH), format!("{}", body.len()));
}

fn add_content_type(headers: &mut BTreeMap<String, String>, content_type: &str) {
	headers.insert(String::from(CONTENT_TYPE), String::from(content_type));
}