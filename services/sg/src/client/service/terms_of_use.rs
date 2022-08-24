use log::error;

use crate::client::service::unimplemented::not_found_handler;

use std::{sync::Arc, collections::BTreeMap, convert::Infallible, fs::File, io::{BufReader, Read}};

use smoltcp_user_vpn::tcp::{http::{gen_http_accept, Request, Method, Response, ResponseHeader, StatusCode}, AcceptFn};

use crate::client::ClientState;

pub fn new_terms_of_use_connection(state: Arc<ClientState>) -> AcceptFn {
	gen_http_accept(state, Arc::new(move |state, req: Request| async move {
		match (req.header.method, req.header.path.as_str()) {
			(Method::Get, "/motd/US/English.txt") => serve_file_handler(state, req).await,
			(Method::Get, "/motd/US/image.xbx") => serve_file_handler(state, req).await,
			_ => not_found_handler(state, req).await,
		}
	}))
}

pub async fn serve_file_handler<Ctx>(_ctx: Ctx, req: Request) -> Result<Response, Infallible> {
	println!("Attempting to serve file from request: {:?}", req);

	let file = match File::open(&req.header.path) {
		Ok(file) => file,
		Err(_) => {
			error!("Failed to open");
			return not_found_handler(_ctx, req).await
		}
	};

	let mut content = Vec::new();
	let mut reader = BufReader::new(file);
	match reader.read_to_end(&mut content) {
		Err(_) => {
			error!("Failed to read");
			return Ok(Response::generate_internal_server_error(&req))
		}
		_ => (),
	}

	let mut headers = BTreeMap::new();
	headers.insert("Content-Length".to_owned(), format!("{}", content.len()));

	Ok(Response {
		header: ResponseHeader {
			version: req.header.version,
			code: StatusCode::Ok200,
			headers,
		},
		body: content.to_vec(),
	})
}
