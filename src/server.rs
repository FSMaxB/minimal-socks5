use crate::message::{
	Address, Command, Method, MethodSelectionRequest, MethodSelectionResponse, SocksReply, SocksRequest, SocksResponse,
};
use anyhow::{anyhow, bail};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::error::Elapsed;
use tracing::{debug, error, info};

pub async fn listen_for_tcp_connections(socket_address: SocketAddr, connect_timeout: Duration) -> anyhow::Result<()> {
	let listener = TcpListener::bind(socket_address).await?;
	info!(address = %socket_address.ip(), port = socket_address.port(), "Listening for connections");
	loop {
		let (tcp_stream, client_address) = listener.accept().await?;
		info!(address = %client_address.ip(), port = client_address.port(), "New connection");
		tokio::spawn(async move {
			if let Err(error) = run_socks_protocol(tcp_stream, connect_timeout).await {
				error!(address = %client_address.ip(), port = client_address.port(), "Proxy task encountered error: {error}");
			}
		});
	}
}

async fn run_socks_protocol(mut client_stream: TcpStream, connect_timeout: Duration) -> anyhow::Result<()> {
	let server_stream = tokio::time::timeout(connect_timeout, handshake_and_connect(&mut client_stream))
		.await
		.map_err(|_: Elapsed| anyhow!("Handshake and connection timed out"))??;

	tokio::spawn(proxy_data(client_stream, server_stream));

	Ok(())
}

async fn handshake_and_connect(client_stream: &mut TcpStream) -> anyhow::Result<TcpStream> {
	let method_selection_request = MethodSelectionRequest::parse_from_stream(client_stream).await?;
	debug!("{method_selection_request:?}");
	match select_method(method_selection_request.methods) {
		Ok(response) => {
			response.write_to_stream(client_stream).await?;
		}
		Err(response) => {
			response.write_to_stream(client_stream).await?;
			bail!("No acceptable method, closing connection.");
		}
	}

	let socks_request = SocksRequest::parse_from_stream(client_stream).await?;
	debug!("{socks_request:?}");

	Ok(match perform_socks_request(socks_request).await {
		Ok((proxy_stream, response)) => {
			response.write_to_stream(client_stream).await?;
			proxy_stream
		}
		Err(response) => {
			response.write_to_stream(client_stream).await?;
			bail!("Failed to perform socks request, closing connection.");
		}
	})
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
		Ok(stream) => {
			info!(%address, port, "Upstream connection established");
			stream
		}
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
			error!("Error getting local address: {error}");
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
		error!(%address, port, "Error looking up host: {error}");
		SocksReply::GeneralSocksServerFailure
	})
}

async fn proxy_data(mut client_stream: TcpStream, mut server_stream: TcpStream) {
	match tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream).await {
		Ok((request_bytes, response_bytes)) => info!(request_bytes, response_bytes, "Finished proxying"),
		// FIXME: For some reason this always reports an error, even though the proxying works!
		Err(error) => error!("Error proxying: {error}"),
	}
}
