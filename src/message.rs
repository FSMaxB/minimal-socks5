use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

/// > The VER field is set to X'05' for this version of the protocol.
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
#[derive(Debug)]
pub struct MethodSelectionRequest {
	pub methods: Vec<Method>,
}

impl MethodSelectionRequest {
	pub async fn parse_from_stream<Stream>(stream: &mut Stream) -> Result<Self, ParseError>
	where
		Stream: AsyncRead + Unpin,
	{
		if stream.read_u8().await? != VERSION {
			return Err(ParseError::InvalidMessage("Incorrect version byte"));
		}

		let method_count = usize::from(stream.read_u8().await?);
		let mut methods = vec![0u8; method_count];
		stream.read_exact(&mut methods).await?;

		let methods = methods.into_iter().map(Method::from).collect();
		Ok(Self { methods })
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
	InvalidCommand(u8),
	InvalidRequest(&'static str),
	Io(tokio::io::Error),
}

impl From<tokio::io::Error> for ParseError {
	fn from(error: tokio::io::Error) -> Self {
		Self::Io(error)
	}
}

impl Display for ParseError {
	fn fmt(&self, formatter: &mut Formatter) -> std::fmt::Result {
		use ParseError::*;
		match self {
			InvalidMessage(error) => write!(formatter, "Invalid message: {error}"),
			InvalidCommand(number) => write!(formatter, "{number:x} is not a valid command type"),
			InvalidRequest(error) => write!(formatter, "Invalid request: {error}"),
			Io(error) => write!(formatter, "Io Error: {error}"),
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
#[derive(Debug, PartialEq, Eq)]
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

///   The SOCKS request is formed as follows:
/// >
/// > +----+-----+-------+------+----------+----------+
/// > |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// > +----+-----+-------+------+----------+----------+
/// > | 1  |  1  | X'00' |  1   | Variable |    2     |
/// > +----+-----+-------+------+----------+----------+
/// >
/// > Where:
/// >  * VER	protocol version: X'05'
/// >  * CMD
/// >    * CONNECT X'01'
/// >    * BIND X'02'
/// >    * UDP ASSOCIATE X'03'
/// >  * RSV	RESERVED
/// >  * ATYP	address type of following address
/// >    * IP V4 address: X'01'
/// >    * DOMAINNAME: X'03'
/// >    * IP V6 address: X'04'
/// >  * DST.ADDR	desired destination address
/// >  * DST.PORT	desired destination port in network octet order
#[derive(Debug)]
pub struct SocksRequest {
	pub command: Command,
	pub address: Address,
	pub port: u16,
}

impl TryFrom<&[u8]> for SocksRequest {
	type Error = ParseError;

	fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
		const RESERVED: u8 = 0x00;

		let (command, remainder, port) = match value {
			&[VERSION, command, RESERVED, ref remainder @ .., port_high, port_low] => {
				let port = u16::from_be_bytes([port_high, port_low]);
				(Command::try_from(command)?, remainder, port)
			}
			_ => return Err(ParseError::InvalidRequest("")),
		};

		const IPV4_TYPE: u8 = 0x01;
		const DOMAIN_NAME_TYPE: u8 = 0x03;
		const IPV6_TYPE: u8 = 0x04;
		let address = match remainder {
			// In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
			// the type of address contained within the field:
			//   * X'01'
			// the address is a version-4 IP address, with a length of 4 octets
			&[IPV4_TYPE, ref address @ ..] => {
				let bytes = <[u8; 4]>::try_from(address)
					.map_err(|_| ParseError::InvalidRequest("Invalid IPv4 address length"))?;
				Address::Ipv4(Ipv4Addr::from(bytes))
			}
			// >   *  X'03'
			// > the address field contains a fully-qualified domain name.  The first
			// > octet of the address field contains the number of octets of name that
			// > follow, there is no terminating NUL octet.
			&[DOMAIN_NAME_TYPE, name_length, ref name @ ..] => {
				if name.len() != usize::from(name_length) {
					return Err(ParseError::InvalidRequest("Invalid domain name length"));
				}

				Address::DomainName(name.into())
			}
			// >   *  X'04'
			// > the address is a version-6 IP address, with a length of 16 octets.
			&[IPV6_TYPE, ref address @ ..] => {
				let bytes = <[u8; 16]>::try_from(address)
					.map_err(|_| ParseError::InvalidRequest("Invalid IPv6 address length"))?;
				Address::Ipv6(Ipv6Addr::from(bytes))
			}
			_ => return Err(ParseError::InvalidRequest("Invalid address")),
		};

		Ok(Self { command, address, port })
	}
}

/// > * CMD
/// >   * CONNECT X'01'
/// >   * BIND X'02'
/// >   * UDP ASSOCIATE X'03'
#[derive(Debug)]
#[repr(u8)]
pub enum Command {
	Connect = 0x01,
	Bind = 0x02,
	UdpAssociate = 0x03,
}

/// > The SOCKS request information is sent by the client as soon as it has
/// > established a connection to the SOCKS server, and completed the
/// > authentication negotiations.  The server evaluates the request, and
/// > returns a reply formed as follows:
///
/// >  +----+-----+-------+------+----------+----------+
/// >  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// >  +----+-----+-------+------+----------+----------+
/// >  | 1  |  1  | X'00' |  1   | Variable |    2     |
/// >  +----+-----+-------+------+----------+----------+
///
/// > Where:
/// > * VER	protocol version: X'05'
/// > * REP	Reply field:
/// >   * X'00' succeeded
/// >   * X'01' general SOCKS server failure
/// >   * X'02' connection not allowed by ruleset
/// >   * X'03' Network unreachable
/// >   * X'04' Host unreachable
/// >   * X'05' Connection refused
/// >   * X'06' TTL expired
/// >   * X'07' Command not supported
/// >   * X'08' Address type not supported
/// >   * X'09' to X'FF' unassigned
/// > * RSV	RESERVED
/// > * ATYP	address type of following address
pub struct SocksResponse {
	pub reply: SocksReply,
	pub address: Address,
	pub port: u16,
}

impl From<SocksResponse> for Vec<u8> {
	fn from(SocksResponse { reply, address, port }: SocksResponse) -> Self {
		const RESERVED: u8 = 0x00;

		let mut bytes = vec![VERSION, reply.into(), RESERVED, address.r#type()];
		use Address::*;
		match address {
			Ipv4(address) => bytes.extend_from_slice(&address.octets()),
			DomainName(name) => bytes.extend_from_slice(&name),
			Ipv6(address) => bytes.extend_from_slice(&address.octets()),
		}
		bytes.extend_from_slice(&port.to_be_bytes());

		bytes
	}
}

/// > * REP	Reply field:
/// >   * X'00' succeeded
/// >   * X'01' general SOCKS server failure
/// >   * X'02' connection not allowed by ruleset
/// >   * X'03' Network unreachable
/// >   * X'04' Host unreachable
/// >   * X'05' Connection refused
/// >   * X'06' TTL expired
/// >   * X'07' Command not supported
/// >   * X'08' Address type not supported
/// >   * X'09' to X'FF' unassigned
pub enum SocksReply {
	Succeeded,
	GeneralSocksServerFailure,
	ConnectionNotAllowedByRuleset,
	NetworkUnreachable,
	HostUnreachable,
	ConnectionRefused,
	TtlExpired,
	CommandNotSupported,
	AddressTypeNotSupported,
	Unassigned(u8),
}

impl From<SocksReply> for u8 {
	fn from(reply: SocksReply) -> Self {
		use SocksReply::*;
		match reply {
			// X'00' succeeded
			Succeeded => 0x00,
			// X'01' general SOCKS server failure
			GeneralSocksServerFailure => 0x01,
			// X'02' connection not allowed by ruleset
			ConnectionNotAllowedByRuleset => 0x02,
			// X'03' Network unreachable
			NetworkUnreachable => 0x03,
			// X'04' Host unreachable
			HostUnreachable => 0x04,
			// X'05' Connection refused
			ConnectionRefused => 0x05,
			// X'06' TTL expired
			TtlExpired => 0x06,
			// X'07' Command not supported
			CommandNotSupported => 0x07,
			// X'08' Address type not supported
			AddressTypeNotSupported => 0x08,
			// X'09' to X'FF' unassigned
			Unassigned(reply @ 0x09..=0xff) => reply,
			Unassigned(_) => unreachable!(),
		}
	}
}

impl TryFrom<u8> for Command {
	type Error = ParseError;

	fn try_from(command: u8) -> Result<Self, Self::Error> {
		match command {
			// CONNECT X'01'
			0x01 => Ok(Self::Connect),
			// BIND X'02'
			0x02 => Ok(Self::Bind),
			// UDP ASSOCIATE X'03'
			0x03 => Ok(Self::UdpAssociate),
			invalid => Err(ParseError::InvalidCommand(invalid)),
		}
	}
}

/// > * ATYP	address type of following address
/// >   * IP V4 address: X'01'
/// >   * DOMAINNAME: X'03'
/// >   * IP V6 address: X'04'
/// > * DST.ADDR	desired destination address
#[derive(Debug)]
pub enum Address {
	Ipv4(Ipv4Addr),
	DomainName(Vec<u8>),
	Ipv6(Ipv6Addr),
}

impl Address {
	fn r#type(&self) -> u8 {
		use Address::*;
		match self {
			Ipv4(_) => 0x01,
			DomainName(_) => 0x03,
			Ipv6(_) => 0x04,
		}
	}
}

impl From<IpAddr> for Address {
	fn from(address: IpAddr) -> Self {
		match address {
			IpAddr::V4(ipv4) => Self::Ipv4(ipv4),
			IpAddr::V6(ipv6) => Self::Ipv6(ipv6),
		}
	}
}
