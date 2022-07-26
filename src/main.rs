//! https://datatracker.ietf.org/doc/html/rfc1928

use crate::server::listen_for_tcp_connections;
use anyhow::Context;
use clap::Parser;
use std::net::{IpAddr, ToSocketAddrs};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
	let Parameters {
		socks_address,
		socks_port,
	} = Parameters::parse();

	let socket_address = (socks_address, socks_port)
		.to_socket_addrs()?
		.next()
		.with_context(|| format!("Invalid Ip/port: {socks_address}:{socks_port}"))?;
	listen_for_tcp_connections(socket_address).await?;

	Ok(())
}

#[derive(Debug, Parser)]
struct Parameters {
	#[clap(long)]
	socks_address: IpAddr,
	#[clap(long, default_value = "1080")]
	socks_port: u16,
}

mod message;
mod server;
