use crate::api::{Reply, Request};
// use crate::service::ServiceResources;
use crate::error::Error;
use crate::hwcrypto;
use crate::types::*;

pub struct Se050Wrapper {
}

impl<P> hwcrypto::HWCrypto<P> for Se050Wrapper where P: Platform {
	fn reply_to(&mut self, _client_id: ClientId, _request: &Request) -> Result<Reply, Error> {
		Err(Error::NoHardwareAcceleration)
	}
}
