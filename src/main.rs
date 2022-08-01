//! https://datatracker.ietf.org/doc/html/rfc1928

use crate::server::listen_for_tcp_connections;
use anyhow::Context;
use clap::Parser;
use std::net::{IpAddr, ToSocketAddrs};
use tokio::sync::oneshot;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
	let Parameters { address, port } = Parameters::parse();

	let (shutdown_sender, shutdown_receiver) = oneshot::channel();
	ctrlc::set_handler({
		let mut shutdown_sender = Some(shutdown_sender);
		move || {
			let _ = shutdown_sender.take().map(|sender| sender.send(()));
		}
	})
	.context("Failed to register Ctrl-C handler")?;

	let socket_address = (address, port)
		.to_socket_addrs()?
		.next()
		.with_context(|| format!("Invalid Ip/port: {address}:{port}"))?;
	tokio::select! {
		result = listen_for_tcp_connections(socket_address) => {
			result?;
		}
		_ = shutdown_receiver => {
			println!("Received ctrl-c, shutting down")
		}
	};

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
