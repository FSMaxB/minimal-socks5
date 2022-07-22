use std::error::Error;
use std::fmt::{Display, Formatter};

pub const VERSION: u8 = 0x05;

/// > The client connects to the server, and sends a version
/// > identifier/method selection message:
/// >
/// > +----+----------+----------+
/// > |VER | NMETHODS | METHODS  |
/// > +----+----------+----------+
/// > | 1  |    1     | 1 to 255 |
/// > +----+----------+----------+
/// >
/// > The VER field is set to X'05' for this version of the protocol.  The
/// > NMETHODS field contains the number of method identifier octets that
/// > appear in the METHODS field.
pub struct MethodSelectionRequest {
	pub methods: Vec<Method>,
}

impl TryFrom<&[u8]> for MethodSelectionRequest {
	type Error = ParseError;

	fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
		match value {
			&[VERSION, method_count, ref rest @ ..] => {
				if rest.len() != usize::from(method_count) {
					return Err(ParseError::InvalidMessage("Incorrect number of methods"));
				}

				Ok(Self {
					methods: rest.iter().copied().map(Method::from).collect(),
				})
			}
			_ => Err(ParseError::InvalidMessage("Invalid method selection request")),
		}
	}
}

pub struct MethodSelectionResponse {
	pub method: Method,
}

impl From<MethodSelectionResponse> for [u8; 2] {
	fn from(MethodSelectionResponse { method }: MethodSelectionResponse) -> Self {
		[VERSION, method.into()]
	}
}

#[derive(Debug)]
pub enum ParseError {
	InvalidMessage(&'static str),
}

impl Display for ParseError {
	fn fmt(&self, formatter: &mut Formatter) -> std::fmt::Result {
		use ParseError::*;
		match self {
			InvalidMessage(error) => write!(formatter, "Invalid message: {error}"),
		}
	}
}

impl Error for ParseError {}

/// > The values currently defined for METHOD are:
/// >
/// > * X'00' NO AUTHENTICATION REQUIRED
/// > * X'01' GSSAPI
/// > * X'02' USERNAME/PASSWORD
/// > * X'03' to X'7F' IANA ASSIGNED
/// > * X'80' to X'FE' RESERVED FOR PRIVATE METHODS
/// > * X'FF' NO ACCEPTABLE METHODS
pub enum Method {
	NoAuthenticationRequired,
	GSSAPI,
	UsernamePassword,
	IanaAssigned(u8),              // TODO: Prevent invalid values
	ReservedForPrivateMethods(u8), // TODO: Prevent invalid values
	NoAcceptableMethods,
}

impl From<u8> for Method {
	fn from(method: u8) -> Self {
		match method {
			// X'00' NO AUTHENTICATION REQUIRED
			0x00 => Self::NoAuthenticationRequired,
			// X'01' GSSAPI
			0x01 => Self::GSSAPI,
			// X'02' USERNAME/PASSWORD
			0x02 => Self::UsernamePassword,
			// X'03' to X'7F' IANA ASSIGNED
			0x03..=0x7f => Self::IanaAssigned(method),
			// X'80' to X'FE' RESERVED FOR PRIVATE METHODS
			0x80..=0xfe => Self::ReservedForPrivateMethods(method),
			// X'FF' NO ACCEPTABLE METHODS
			0xff => Self::NoAcceptableMethods,
		}
	}
}

impl From<Method> for u8 {
	fn from(method: Method) -> Self {
		use Method::*;
		match method {
			// X'00' NO AUTHENTICATION REQUIRED
			NoAuthenticationRequired => 0x00,
			// X'01' GSSAPI
			GSSAPI => 0x01,
			// X'02' USERNAME/PASSWORD
			UsernamePassword => 0x02,
			// X'03' to X'7F' IANA ASSIGNED
			IanaAssigned(method @ 0x03..=0x7f) => method,
			IanaAssigned(_) => unreachable!(),
			// X'80' to X'FE' RESERVED FOR PRIVATE METHODS
			ReservedForPrivateMethods(method @ 0x80..=0xfe) => method,
			ReservedForPrivateMethods(_) => unreachable!(),
			// X'FF' NO ACCEPTABLE METHODS
			NoAcceptableMethods => 0xff,
		}
	}
}
