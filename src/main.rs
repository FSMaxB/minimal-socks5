//! https://datatracker.ietf.org/doc/html/rfc1928

use crate::server::listen_for_tcp_connections;
use anyhow::Context;
use clap::Parser;
use std::net::{IpAddr, ToSocketAddrs};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
	let Parameters { address, port } = Parameters::parse();

	let socket_address = (address, port)
		.to_socket_addrs()?
		.next()
		.with_context(|| format!("Invalid Ip/port: {address}:{port}"))?;
	listen_for_tcp_connections(socket_address).await?;

	Ok(())
}

#[derive(Debug, Parser)]
struct Parameters {
	/// IPv4 or IPv6 Address to listen on.
	#[clap(default_value = "127.0.0.1", env = "SOCKS_BIND_ADDRESS")]
	address: IpAddr,
	/// TCP port to listen on.
	#[clap(default_value = "1080", env = "SOCKS_BIND_PORT")]
	port: u16,
}

mod message;
mod server;
