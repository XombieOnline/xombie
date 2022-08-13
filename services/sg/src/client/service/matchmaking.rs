use log::error;

use smoltcp_user_vpn::tcp::{AcceptFn, http::{Request, Method, gen_http_accept, Response}};
use xombie_matchmaking::{Users, Title};

use std::convert::Infallible;
use std::sync::Arc;

use xblive::{crypto::primitives::KeyId, ver::LibraryVersion};
use xblive::service::matchmaking::*;

use xbox_sys::{codec::{BufPut, Decode}, account::Xuid};

use crate::client::ClientState;
use crate::client::service::unimplemented::not_found_handler;

pub fn new_matchmaking_connection(state: Arc<ClientState>) -> AcceptFn {
	gen_http_accept(state, Arc::new(move |state, req: Request| async move {
		match (req.header.method, req.header.path.as_str()) {
			(Method::Post, "/xmatch/xmatchclient.srf") => xmatchclient_handler(state, req).await,
			(Method::Post, "/xmatch/xmatchhost.srf") => xmatchhost_handler(state, req).await,
			_ => not_found_handler(state, req).await,
		}
	}))
}

async fn xmatchclient_handler(state: Arc<ClientState>, req: Request) -> Result<Response, Infallible> {
	let (_, search_request) = Search::decode(req.body_bytes()).unwrap();

	error!("TODO: Get users out of as ticket");
	let users = Users {
		machine: Xuid(0),
		user: vec![Xuid(0)],
	};

	error!("TODO: Validate title_id is same as sg connection");
	let title_id = search_request.header.title_id;

	error!("TODO: Get title_version out as ticket");
	let title_version = LibraryVersion {
		major: 0,
		minor: 0,
		build: 0,
		qfe: 0,
	};

	let title = Title {
		id: title_id,
		ver: title_version,
	};

	let results = match (title_id, search_request.header.procedure_index) {
		(0x4C41000B, 1) => {
			state.ext_services.matchmaking.search_for_sessions(
				users,
				title,
				search_request.header.num_users,
				search_request.header.flags,
				10,
				search_request.attributes.as_slice()
			).await.unwrap()
		}
		_ => {
			error!("Unknown search request title_id, procedure_index tuple {:?}", search_request);
			return Ok(Response::generate_internal_server_error(&req))
		}
	};

	println!("search results: {:?}", results);

	let results: Vec<_> = results.iter().map(|result| {
		SearchResult::generate(
			result.session_id,
			result.host_address,
			result.key_exchange_key,
			result.public_open,
			result.private_open,
			result.public_filled,
			result.private_filled,
			result.attributes.clone(),
		)
	}).collect();

	let results = SearchResults::generate(0, 0, results);

	let mut body = vec![];
	results.put(&mut body);

	Ok(Response::generate_good_response(&req, CONTENT_TYPE, body))
}

async fn xmatchhost_handler(state: Arc<ClientState>, req: Request) -> Result<Response, Infallible> {
	let (_, session_request) = Session::decode(req.body_bytes()).unwrap();

	error!("TODO: Get users out of as ticket");
	let users = Users {
		machine: Xuid(0),
		user: vec![Xuid(0)],
	};

	error!("TODO: Validate title_id is same as sg connection");
	let title_id = session_request.header.title_id;

	error!("TODO: Get title_version out as ticket");
	let title_version = LibraryVersion {
		major: 0,
		minor: 0,
		build: 0,
		qfe: 0,
	};

	let title = Title {
		id: title_id,
		ver: title_version,
	};

	error!("TOOD: validate host_address is same as sg connection");
	let host_address = session_request.header.host_address;

	let session_info = if session_request.header.session_id == KeyId::INVALID {
		let created_session = match state.ext_services.matchmaking.create_session(
			users,
			title,
			host_address,
			session_request.header.public_open,
			session_request.header.private_open,
			session_request.header.public_filled,
			session_request.header.private_filled,
			session_request.attributes.clone(),
		).await {
			Ok(created_session) => created_session,
			Err(err) => {
				error!("Unable to create matchmaking session: {:?} {:?}", err, session_request);
				return Ok(Response::generate_internal_server_error(&req))
			}
		};

		SessionInfo {
			session_id: created_session.session_id,
			key_exchange_key: created_session.key_exchange_key,
		}
	} else {
		let session_info = match state.ext_services.matchmaking.update_session(
			users,
			title,
			session_request.header.session_id,
			host_address,
			session_request.header.public_open,
			session_request.header.private_open,
			session_request.header.public_filled,
			session_request.header.private_filled,
			session_request.attributes.clone(),
		).await {
			Ok(created_session) => created_session,
			Err(err) => {
				error!("Unable to update matchmaking session: {:?} {:?}", err, session_request);
				return Ok(Response::generate_internal_server_error(&req))
			}
		};

		SessionInfo {
			session_id: session_info.session_id,
			key_exchange_key: session_info.key_exchange_key,
		}
	};

	let mut body = vec![];
	session_info.put(&mut body);

	Ok(Response::generate_good_response(&req, CONTENT_TYPE, body))
}
