use crate::api::*;
use crate::config::*;
use crate::error::{Error, Result};
use crate::key;
use crate::store::keystore::Keystore;
use crate::hwcrypto;
use crate::types::*;
use chacha20::ChaCha8Rng;
use se050::Se050Device;

pub const SE050_PROVIDER_ID: u32 = 0x30354553;	// 'SE50'

pub struct Se050Wrapper {
	pub device: &'static mut dyn Se050Device,
}

#[derive(Clone)]
pub struct Se050CryptoParameters {
	pub pin: Option<[u8; MAX_PIN_LENGTH]>,
}

impl<P> hwcrypto::HWCrypto<P> for Se050Wrapper where P: Platform {
	fn reply_to(&mut self, _client_id: &ClientId, request: &Request) -> Result<Reply> {
		match request {
		Request::Encrypt(request) => {
			match request.mechanism {
			Mechanism::Aes256Cbc => { aes_encrypt() },
			_ => { Err(Error::NoHardwareAcceleration) }
			}
		}.map(Reply::Encrypt),
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

fn aes_encrypt() -> Result<reply::Encrypt> {
	// 1. get keyid from request
	// 2. look up keyid in filesystem keystore
	// 3. run crypto on SE050:
		// 3a. create/reuse CryptoObject ("CreateCryptoObject")
		// 3b. create transient SymmKey ("WriteSymmKey")
		// 3c. choose between one-shot and update method (NVM!)
		// 3d. use CryptoObject and SymmKey to perform computation
		// 3e. delete transient SymmKey
	Err(Error::NoHardwareAcceleration)
}

pub struct Se050Keystore {
    /* access to physical SE050 device? */
}

impl Keystore for Se050Keystore {
    fn store_key(&mut self, location: Location, secrecy: key::Secrecy, info: key::Info, material: &[u8]) -> Result<KeyId> { todo!(); }
    fn exists_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> bool { todo!(); }
    /// Return Header of key, if it exists
    fn key_info(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<key::Info> { todo!(); }
    fn delete_key(&self, id: &KeyId) -> bool { todo!(); }
    fn delete_all(&self, location: Location) -> Result<usize> { todo!(); }
    fn load_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> Result<key::Key> { todo!(); }
    fn overwrite_key(&self, location: Location, secrecy: key::Secrecy, kind: key::Kind, id: &KeyId, material: &[u8]) -> Result<()> { todo!(); }
    fn rng(&mut self) -> &mut ChaCha8Rng { todo!(); }
    fn location(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<Location> { todo!(); }
}
