use xbox_sys::account::Xuid;

#[derive(Clone, Copy, Debug)]
pub struct CombinedId {
	pub machine: Xuid,
	pub users: [Option<Xuid>; 4],
}
