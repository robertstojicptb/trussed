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


//#######################################################################################################################
  
		//fn get_random(&mut self, buf: &mut [u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>

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


/* 
		Request::RandomBytes(request) => {
			if request.count < 1024 {
				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();
				self.rng()?.fill_bytes(&mut bytes);
				Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))
			} else {
				Err(Error::MechanismNotAvailable)
			}
		}

*/



//#######################################################################################################################
 
		//fn generate_p256_key (&mut self, delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error> ;


		Request::GenerateKey(request) => {
			match request.mechanism {
			Mechanism::P256 => {
				let objid  = self.device.generate_p256_key(self.delay).unwrap();
				Ok(Reply::GenerateKey(reply::GenerateKey { key: KeyId(objid.into()) }))
			}
			_ => { Err(Error::RequestNotAvailable) }
			}
		},




//#######################################################################################################################
  


			//fn generate_ed255_key_pair(&mut self, delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error> ; 

			Request::GenerateKey(request) => {
				match request.mechanism {
				Mechanism::Ed255 => {
					let objid_2 = self.device.generate_ed255_key_pair(self.delay).unwrap();
					Ok(Reply::GenerateKey(reply::GenerateKey { key: KeyId(objid_2.into()) }))
				}
				_ => { Err(Error::RequestNotAvailable) }
				}
			},
/*  
			Request::GenerateKey(request) => {
                match request.mechanism {
                    Mechanism::Chacha8Poly1305 => mechanisms::Chacha8Poly1305::generate_key(keystore, request),
                    Mechanism::Ed255 => mechanisms::Ed255::generate_key(keystore, request),
                    Mechanism::P256 => mechanisms::P256::generate_key(keystore, request),
                    Mechanism::X255 => mechanisms::X255::generate_key(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),
                }.map(Reply::GenerateKey)
            },

*/






//#######################################################################################################################
 
		   //AN12413, // 4.19 Generic management commands //44.19.5 delete_all P.112
		  // fn delete_all(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> ;


/*  
		  Request::DeleteAllKeys(request) => {
			let count = self.device.delete_all( self.delay).unwrap();
			 
			Ok(Reply::DeleteAllKeys(reply::DeleteAllKeys { count.into() } ))
		},	
*/
//fff







	  //AN12413, // 4.19 Generic management commands //44.19.5 delete_all P.112
	  //fn delete_all(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> ;
 
	  Request::DeleteAllKeys(request)=> {
		self.device.delete_all(self.delay)
		//Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))

	//	self.device.get_random(&mut bytes, self.delay).unwrap();
		//		Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))
		 

	  }.map(Reply::DeleteAllKeys),
 


/*
	  Request::DeleteAllKeys(request) => {
		let count = keystore.delete_all(request.location)?;
		Ok(Reply::DeleteAllKeys(reply::DeleteAllKeys { count } ))
	},
*/


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
//bla bla

 
/*  
impl ServiceBackend for Se050Wrapper {

	fn reply_to(&mut self, _client_id: &mut ClientContext, request: &Request) -> Result<Reply> {

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

		Request::GenerateKey(request) => {
			match request.mechanism {

			Mechanism::P256 => {

				let objid = self.device.generate_p256_key(self.delay).unwrap();

				Ok(Reply::GenerateKey(reply::GenerateKey { key: KeyId(objid.into()) }))
			}

			_ => { Err(Error::RequestNotAvailable) }

			}
		},


		_ => {
			Err(Error::RequestNotAvailable)
		}

		}
	}
}
*/

/*
/* 
		Request::DeleteAllKeys(request) => {
			let count = keystore.delete_all(request.location)?;
			Ok(Reply::DeleteAllKeys(reply::DeleteAllKeys { count } ))
		},	

Request::DeleteAllKeys(request) => {
			if request.count < 250 {
				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();


				self.device.delete_all( self.delay).unwrap();
				Ok(Reply::DeleteAllKeys(reply::DeleteAllKeys { bytes } ))

		*/	


			} else {
				Err(Error::RequestNotAvailable)
			}
		},



	



		Request::RandomBytes(request) => {
			if request.count < 1024 {
				let mut bytes = Message::new();
				bytes.resize_default(request.count).unwrap();
				self.rng()?.fill_bytes(&mut bytes);
				Ok(Reply::RandomBytes(reply::RandomBytes { bytes } ))
			} else {
				Err(Error::MechanismNotAvailable)
			}
		}



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













 */