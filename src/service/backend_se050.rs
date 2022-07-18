use crate::api::*;
use crate::error::{Error, Result};
use crate::types::*;
use se050::Se050Device;

pub struct Se050Wrapper {
    pub device: &'static mut dyn Se050Device,
    pub delay: &'static mut se050::DelayWrapper,
}

#[derive(Copy, Clone)]
pub struct Se050Parameters {
    // pub pin: Option<[u8; MAX_PIN_LENGTH]>,
}

impl ServiceBackend for Se050Wrapper {
	fn reply_to(&mut self, _client_id: &mut ClientId, request: &Request) -> Result<Reply> {
		match request {
		Request::Encrypt(request) => {
			match request.mechanism {
			Mechanism::Aes256Cbc => { aes_encrypt() },
			_ => { Err(Error::RequestNotAvailable) }
			}
		}.map(Reply::Encrypt),
		Request::RandomBytes(request) => {
			if request.count < 250 {
				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();
				self.device.get_random(&mut bytes, self.delay).unwrap();
				Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))
			} else {
				Err(Error::RequestNotAvailable)
			}
		},
		_ => {
			Err(Error::RequestNotAvailable)
		}
		}
	}
}

fn aes_encrypt() -> Result<reply::Encrypt> {
	// 1. get keyid from request
	// 2. look up keyid in filesystem keystore
	// 3. run crypto on SE050:
		// 3a. create/reuse CryptoObject ("CreateCryptoObject")
		// 3b. create transient SymmKey ("WriteSymmKey")
		// 3c. choose between one-shot and update method (NVM!)
		// 3d. use CryptoObject and SymmKey to perform computation
		// 3e. delete transient SymmKey
	Err(Error::RequestNotAvailable)
}
