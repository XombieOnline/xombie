use log::debug;

use std::{convert::Infallible, collections::BTreeMap, time::Duration};

use smoltcp_user_vpn::tcp::{AcceptFn, http::{gen_http_accept, Method, Request, Response, ResponseHeader, StatusCode}};

use std::sync::Arc;

use xblive::service::presence::*;

use xbox_sys::codec::{BufPut, Decode};
use xbox_sys::status::HResult;

use crate::client::ClientState;

use super::unimplemented::not_found_handler;

pub const PRESENCE_CONTENT_TYPE: &'static str = "xon/1";

pub fn new_presence_connection(state: Arc<ClientState>) -> AcceptFn {
	gen_http_accept(state, Arc::new(move |state, req: Request| async move {
		match (req.header.method, req.header.path.as_str()) {
			(Method::Post, "/xpnfront/xpresence.srf") => xpresence_handler(state, req).await,
			_ => not_found_handler(state, req).await,
		}
	}))
}

async fn xpresence_handler(state: Arc<ClientState>, req: Request) -> Result<Response, Infallible> {
	let (_, message_req) = Message::decode(req.body_bytes()).unwrap();
	debug!("TODO: Check Content-Type");
	debug!("TODO: Check User-Agent");

	tokio::time::sleep(Duration::from_secs(1))
		.await;

	use MessageKind::*;
	let message_reply_kind = match message_req.kind {
		Alive{body, ref acct_name} =>
			xpresence_alive_handler(state, &message_req.header, &body, &acct_name)
				.await,
		Alive2{body, ref acct_name} =>
			xpresence_alive2_handler(state, &message_req.header, &body, &acct_name)
				.await,
		_ => todo!("Fail on unknown message types {:x?}", message_req)
	};

	let message_reply = Message::reply_from_kind_and_req(message_reply_kind, &message_req);

	let mut reply_body = vec![];
	message_reply.put(&mut reply_body);

	let mut headers = BTreeMap::new();
	headers.insert("Content-Type".to_owned(), PRESENCE_CONTENT_TYPE.to_owned());
	headers.insert("Content-Length".to_owned(), format!("{}", reply_body.len()));
	headers.insert("Server".to_owned(), "Xombie Secure Gateway (Presence)".to_owned());

	Ok(Response {
		header: ResponseHeader {
			version: req.header.version,
			code: StatusCode::Ok200,
			headers,
		},
		body: reply_body,
	})
}

async fn xpresence_alive_handler(_state: Arc<ClientState>, _header: &Header, _body: &Alive, _acct_name: &str) -> MessageKind {
	debug!("TODO: Actually do some work here");

	MessageKind::AliveReply(AliveReply {
		hr: HResult::SUCCESS,
		buddy_list_version: 0,
		buddies_sent: 0,
		block_list_version: 0,
		blocks_sent: 0,
	})
}

async fn xpresence_alive2_handler(_state: Arc<ClientState>, _header: &Header, _body: &Alive2, _acct_name: &str) -> MessageKind {
	debug!("TODO: Actually do some work here");

	MessageKind::AliveReply(AliveReply {
		hr: HResult::SUCCESS,
		buddy_list_version: 0,
		buddies_sent: 0,
		block_list_version: 0,
		blocks_sent: 0,
	})
}
