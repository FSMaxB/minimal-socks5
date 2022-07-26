use crate::message::{Method, MethodSelectionRequest, MethodSelectionResponse, SocksRequest};
use anyhow::bail;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub async fn listen_for_tcp_connections(socket_address: SocketAddr) -> anyhow::Result<()> {
	let listener = TcpListener::bind(socket_address).await?;
	println!("Listening on {socket_address}");
	loop {
		let (_tcp_stream, client_address) = listener.accept().await?;
		println!("New connection from: {client_address}");
		run_socks_protocol(_tcp_stream).await?;
	}
}

async fn run_socks_protocol(mut tcp_stream: TcpStream) -> anyhow::Result<()> {
	let mut buffer = [0u8; 65536];

	let packet = read_packet(&mut buffer, &mut tcp_stream).await?;
	let method_selection_request = MethodSelectionRequest::try_from(packet)?;
	println!("{method_selection_request:?}");
	match select_method(method_selection_request.methods) {
		Ok(response) => {
			let response = <[u8; 2]>::from(response);
			tcp_stream.write_all(&response).await?;
		}
		Err(response) => {
			let response = <[u8; 2]>::from(response);
			tcp_stream.write_all(&response).await?;
			bail!("No acceptable method, closing connection.");
		}
	}

	let packet = read_packet(&mut buffer, &mut tcp_stream).await?;
	let socks_request = SocksRequest::try_from(packet)?;
	println!("{socks_request:?}");

	Ok(())
}

async fn read_packet<'buffer>(buffer: &'buffer mut [u8], tcp_stream: &mut TcpStream) -> anyhow::Result<&'buffer [u8]> {
	loop {
		let length = tcp_stream.read(buffer).await?;
		println!("Read length: {length}");
		if length > 0 {
			return Ok(&buffer[0..length]);
		}
	}
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
