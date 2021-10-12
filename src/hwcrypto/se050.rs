use crate::api::*;
use crate::config::*;
use crate::error::Error;
use crate::hwcrypto;
use crate::types::*;
use se050::Se050Device;

pub struct Se050Wrapper {
	pub device: &'static mut dyn Se050Device,
}

#[derive(Clone)]
pub struct Se050CryptoParameters {
	pub pin: Option<[u8; MAX_PIN_LENGTH]>,
}

impl<P> hwcrypto::HWCrypto<P> for Se050Wrapper where P: Platform {
	fn reply_to(&mut self, _client_id: ClientId, request: &Request) -> Result<Reply, Error> {
		match request {
		Request::RandomBytes(request) => {
			if request.count < 250 {
				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();
				self.device.get_random(&mut bytes).unwrap();
				Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))
			} else {
				Err(Error::NoHardwareAcceleration)
			}
		},
		_ => {
			Err(Error::NoHardwareAcceleration)
		}
		}
	}
}
