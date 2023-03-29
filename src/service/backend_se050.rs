use crate::api::*;
use crate::error::{Error, Result};
use crate::types::*;
use se050::Se050Device;

const SE050_ID_SPACE: u32 = 0x53453530;	 /* 'SE50' */
 
pub struct Se050Wrapper {
    pub device: &'static mut dyn Se050Device,
    pub delay: &'static mut se050::DelayWrapper,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Se050Parameters {
    // pub pin: Option<[u8; MAX_PIN_LENGTH]>,
}
 
impl ServiceBackend for Se050Wrapper {

	fn reply_to(&mut self, _client_id: &mut ClientContext, request: &Request) -> Result<Reply> {

		match request {

		Request::Encrypt(request) => {
			match request.mechanism {
			Mechanism::Aes256Cbc => { aes_encrypt() },
			_ => { Err(Error::RequestNotAvailable) }
			}
		}.map(Reply::Encrypt),


  
		//fn get_random(&mut self, buf: &mut [u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>

		Request::RandomBytes(request) => {

			//TEST SE050 primitive delete_secure_object(&[0x20, 0xe8, 0xa1, 0x01], self.delay,);
			if request.count == 10 {

				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();
				self.device.delete_secure_object(&[0x20, 0xe8, 0xa1, 0x01], self.delay,);				 
				Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))				
			} 
			
			//TEST SE050 primitive delete_secure_object(&[0x20, 0xe8, 0xa1, 0x02], self.delay,);
			else if request.count == 20 {

				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();
				self.device.delete_secure_object(&[0x20, 0xe8, 0xa1, 0x02], self.delay,);				 
				Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))

			}

			//TEST SE050 primitive generate_p256_key(self.delay);
			else if request.count == 30 {

				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();
				self.device.generate_p256_key(self.delay);
				Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))

			}

			//TEST SE050 primitive generate_ed255_key_pair(&[0x20, 0xe8, 0xa1, 0x02], self.delay,);
			else if request.count == 40 {

				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();
				self.device.generate_ed255_key_pair(&[0x20, 0xe8, 0xa1, 0x02], self.delay,);					 
				Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))

			}

			//TEST SE050 primitive get_random(&mut bytes, self.delay);
			else if request.count == 50 {

				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();		
				self.device.get_random(&mut bytes, self.delay);
				Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))

			}

			//TEST SE050 primitive  check_object_exists(&mut bytes,&[0x20, 0xe8, 0xa1, 0x02], self.delay,);
			else if request.count == 60 {

				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();
				self.device.check_object_exists(&mut bytes,&[0x20, 0xe8, 0xa1, 0x02], self.delay,);
				Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))
			}

				else{
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
	
	impl Into<Id> for se050::ObjectId {
		fn into(self) -> Id {
			Id((SE050_ID_SPACE as u128) << 96 |
				((self.0[0] as u128) << 24) |
				((self.0[1] as u128) << 16) |
				((self.0[2] as u128) << 8) |
				 (self.0[3] as u128))
		}
	}
	
	impl TryFrom<Id> for se050::ObjectId {
		type Error = crate::error::Error;
	
		fn try_from(id: Id) -> Result<Self> {
			if id.0 >> 96 != (SE050_ID_SPACE as u128) {
				return Err(crate::error::Error::InternalError);
			}
			let buf: [u8; 4] = [
				((id.0 >> 24) & 0xff) as u8,
				((id.0 >> 16) & 0xff) as u8,
				((id.0 >>  8) & 0xff) as u8,
				( id.0        & 0xff) as u8];
			Ok(Self(buf))
		}
	}

