use crate::message::{
	Address, Command, Method, MethodSelectionRequest, MethodSelectionResponse, SocksReply, SocksRequest, SocksResponse,
};
use anyhow::bail;
use std::io::ErrorKind;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

pub async fn listen_for_tcp_connections(socket_address: SocketAddr) -> anyhow::Result<()> {
	let listener = TcpListener::bind(socket_address).await?;
	println!("Listening on {socket_address}");
	loop {
		let (_tcp_stream, client_address) = listener.accept().await?;
		println!("New connection from: {client_address}");
		tokio::spawn(async move {
			if let Err(error) = run_socks_protocol(_tcp_stream).await {
				println!("Proxy task encountered error: {error}");
			}
		});
	}
}

async fn run_socks_protocol(mut client_stream: TcpStream) -> anyhow::Result<()> {
	let method_selection_request = MethodSelectionRequest::parse_from_stream(&mut client_stream).await?;
	println!("{method_selection_request:?}");
	match select_method(method_selection_request.methods) {
		Ok(response) => {
			response.write_to_stream(&mut client_stream).await?;
		}
		Err(response) => {
			response.write_to_stream(&mut client_stream).await?;
			bail!("No acceptable method, closing connection.");
		}
	}

	let socks_request = SocksRequest::parse_from_stream(&mut client_stream).await?;
	println!("{socks_request:?}");

	let server_stream = match perform_socks_request(socks_request).await {
		Ok((proxy_stream, response)) => {
			let response = Vec::from(response);
			client_stream.write_all(&response).await?;
			proxy_stream
		}
		Err(response) => {
			let response = Vec::from(response);
			client_stream.write_all(&response).await?;
			bail!("Failed to perform socks request, closing connection.");
		}
	};

	println!("Upstream connection established");
	let (client_reader, client_writer) = client_stream.into_split();
	let (server_reader, server_writer) = server_stream.into_split();

	// TODO: Find out if this leaks tasks/connections
	tokio::spawn(proxy_data(client_reader, server_writer));
	tokio::spawn(proxy_data(server_reader, client_writer));

	Ok(())
}

fn select_method(methods: Vec<Method>) -> Result<MethodSelectionResponse, MethodSelectionResponse> {
	if methods.contains(&Method::NoAuthenticationRequired) {
		Ok(MethodSelectionResponse {
			method: Method::NoAuthenticationRequired,
		})
	} else {
		Err(MethodSelectionResponse {
			method: Method::NoAcceptableMethods,
		})
	}
}

async fn perform_socks_request(
	SocksRequest { command, address, port }: SocksRequest,
) -> Result<(TcpStream, SocksResponse), SocksResponse> {
	if !matches!(command, Command::Connect) {
		return Err(SocksResponse {
			reply: SocksReply::CommandNotSupported,
			address,
			port,
		});
	}

	let socket_addresses = match lookup_host(&address, port).await {
		Ok(addresses) => addresses,
		Err(reply) => return Err(SocksResponse { reply, address, port }),
	};
	let proxy_stream = match TcpStream::connect(socket_addresses.as_slice()).await {
		Ok(stream) => stream,
		Err(error) => {
			use ErrorKind::*;
			let reply = match error.kind() {
				PermissionDenied => SocksReply::ConnectionNotAllowedByRuleset,
				ConnectionRefused => SocksReply::ConnectionRefused,
				_ => SocksReply::GeneralSocksServerFailure,
			};
			// TODO: What port/address to use in error response
			return Err(SocksResponse { reply, address, port });
		}
	};

	let bind_address = match proxy_stream.local_addr() {
		Ok(address) => address,
		Err(error) => {
			println!("Error getting local address: {error}");
			// TODO: What port/address to use in error response
			return Err(SocksResponse {
				reply: SocksReply::GeneralSocksServerFailure,
				address,
				port,
			});
		}
	};

	Ok((
		proxy_stream,
		SocksResponse {
			reply: SocksReply::Succeeded,
			// TODO: Is this the correct address to use in the response to CONNECT? I haven't fully understood the standard here.
			// NOTE: OpenSSH seems to unconditionally return 0.0.0.0:0 here! https://github.com/openssh/openssh-portable/blob/800c2483e68db38bd1566ff69677124be974aceb/channels.c#L1512
			address: bind_address.ip().into(),
			port: bind_address.port(),
		},
	))
}

async fn lookup_host(address: &Address, port: u16) -> Result<Vec<SocketAddr>, SocksReply> {
	use Address::*;
	match address {
		Ipv4(ipv4) => tokio::net::lookup_host((*ipv4, port)).await.map(Iterator::collect),
		DomainName(domain) => {
			let domain = std::str::from_utf8(domain).map_err(|_| {
				// TODO: This might be an incorrect reply for non-UTF8 domain names
				SocksReply::AddressTypeNotSupported
			})?;
			tokio::net::lookup_host((domain, port)).await.map(Iterator::collect)
		}
		Ipv6(ipv6) => tokio::net::lookup_host((*ipv6, port)).await.map(Iterator::collect),
	}
	.map_err(|error| {
		println!("Error looking up host for {address:?}:{port}: {error}");
		SocksReply::GeneralSocksServerFailure
	})
}

async fn proxy_data(mut reader: OwnedReadHalf, mut writer: OwnedWriteHalf) {
	match tokio::io::copy(&mut reader, &mut writer).await {
		Ok(bytes) => println!("Finished proxying {bytes} bytes"),
		Err(error) => println!("Error proxying: {error}"),
	}
}
