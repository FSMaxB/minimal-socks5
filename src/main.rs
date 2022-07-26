//! https://datatracker.ietf.org/doc/html/rfc1928

use clap::Parser;
use std::net::IpAddr;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
	let parameters = Parameters::parse();

	println!("{parameters:?}");
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
