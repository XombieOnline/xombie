use log::error;

use std::{sync::Arc, collections::BTreeMap, convert::Infallible};

use smoltcp_user_vpn::tcp::{http::{gen_http_accept, Request, Response, ResponseHeader, StatusCode}, AcceptFn};

use crate::client::ClientState;

const NOT_FOUND_STR: &'static str = "Not found";

#[allow(dead_code)]
pub fn new_unimplemented_connection(state: Arc<ClientState>) -> AcceptFn {
	gen_http_accept(state, Arc::new(move |state, req: Request| async move {
		log::error!("unimplemented http request {:x?}", req);
		not_found_handler(state, req).await
	}))
}


pub async fn not_found_handler<Ctx>(_ctx: Ctx, req: Request) -> Result<Response, Infallible> {
	error!("404ing request: {:?}", req);

	let mut headers = BTreeMap::new();
	headers.insert("Content-Length".to_owned(), format!("{}", NOT_FOUND_STR.len()));

	Ok(Response {
		header: ResponseHeader {
			version: req.header.version,
			code: StatusCode::NotFound404,
			headers,
		},
		body: NOT_FOUND_STR.as_bytes().to_vec(),
	})
}
