use crate::api::{Request, Reply};
use crate::error::Error;
// use crate::service::ServiceResources;
use crate::types::*;

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
	fn reply_to(&mut self, /*resources: &mut ServiceResources<P>,*/ client_id: ClientId, request: &Request) -> Result<Reply, Error>;
}
