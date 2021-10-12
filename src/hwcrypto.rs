use crate::api::{Request, Reply};
use crate::error::Error;
use crate::types::*;

#[cfg(feature = "hwcrypto-se050")]
pub mod se050;

/**
This trait gives developers the opportunity to provide alternative
hardware-backed implementations for a subset of request types.

If a client has opted in to hardware-backed crypto, this function
will be called from ServiceResources::reply_to(). If the desired
request is not available for this hardware accelerator, the reply_to()
function of this trait is expected to return Error::NoHardwareAcceleration.
This error code will cause the generic reply_to() to do its standard
request processing - any other return value will be directly returned to
the client.
*/
pub trait HWCrypto<P> where P: Platform {
	fn reply_to(&mut self, client_id: ClientId, request: &Request) -> Result<Reply, Error>;
}

/**
This struct contains all hardware crypto drivers which have been
selected at compile-time.
*/
#[derive(Default)]
pub struct HWCryptoDrivers {
	#[cfg(feature = "hwcrypto-se050")]
	pub se050: Option<se050::Se050Wrapper>,
}

/**
This struct is part of the ClientId structure that contains the
per-client state information.
*/
#[derive(Clone, Default)]
pub struct HWCryptoParameters {
	#[cfg(feature = "hwcrypto-se050")]
	pub se050: Option<se050::Se050CryptoParameters>,
}

/**
Try to dispatch a client request to each hardware crypto provider
in turn, if
  1. the particular driver has been compiled in
  2. the platform code has initialized the appropriate driver and
     filled the corresponding member in HWCryptoDrivers
  3. the client has opted into the usage of this hardware device
     and (optionally) provided additional parameters for usage
     (such as a specific PIN) in HWCryptoParameters (which is a
     member of ClientId)
*/
pub fn reply_to<P>(drivers: &mut HWCryptoDrivers, client_id: ClientId, request: &Request) -> Result<Reply, Error> where P: Platform {
	macro_rules! dispatch_hwcrypto {
	($member:ident) => {
		if client_id.hwcrypto_params.$member.is_some() && drivers.$member.is_some() {
			let drv: &mut dyn HWCrypto<P> = drivers.$member.as_mut().unwrap();
			let r = drv.reply_to(client_id, request);
			if r != Err(Error::NoHardwareAcceleration) {
				return r;
			}
		}
	};
	}

	#[cfg(feature = "hwcrypto-se050")]
	dispatch_hwcrypto!(se050);

	Err(Error::NoHardwareAcceleration)
}
