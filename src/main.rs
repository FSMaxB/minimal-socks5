//! https://datatracker.ietf.org/doc/html/rfc1928

use crate::server::listen_for_tcp_connections;
use anyhow::{bail, Context};
use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
	let parameters = Parameters::parse();

	tracing_subscriber::fmt()
		.with_ansi(atty::is(atty::Stream::Stdout))
		.with_env_filter(EnvFilter::new(&parameters.log_filter))
		.init();

	let (shutdown_sender, shutdown_receiver) = oneshot::channel();
	ctrlc::set_handler({
		let mut shutdown_sender = Some(shutdown_sender);
		move || {
			let _ = shutdown_sender.take().map(|sender| sender.send(()));
		}
	})
	.context("Failed to register Ctrl-C handler")?;

	let mut join_set = JoinSet::new();
	for listen_address in parameters.listen_addresses.iter().copied() {
		join_set.spawn(listen_for_tcp_connections(listen_address, parameters.connect_timeout()));
	}

	tokio::select! {
		option = join_set.join_next() => {
			match option {
				Some(result) => result??,
				None => bail!("No listen adddress specified."),
			};
		}
		_ = shutdown_receiver => {
			info!("Received ctrl-c, shutting down");
			join_set.shutdown().await;
		}
	};

	Ok(())
}

#[derive(Debug, Parser)]
struct Parameters {
	/// IPv4 or IPv6 Address to listen on.
	#[arg(
		default_value = "127.0.0.1:1080",
		env = "SOCKS_BIND_ADDRESSES",
		value_delimiter = ','
	)]
	listen_addresses: Vec<SocketAddr>,
	#[arg(long, default_value = "info", env = "LOG_FILTER")]
	log_filter: String,
	#[arg(long, default_value = "10", env = "SOCKS_CONNECT_TIMEOUT_SECONDS")]
	connect_timeout_seconds: u64,
}

impl Parameters {
	fn connect_timeout(&self) -> Duration {
		Duration::from_secs(self.connect_timeout_seconds)
	}
}

mod message;
mod server;
