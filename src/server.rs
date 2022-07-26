use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn listen_for_tcp_connections(socket_address: SocketAddr) -> anyhow::Result<()> {
	let listener = TcpListener::bind(socket_address).await?;
	println!("Listening on {socket_address}");
	loop {
		let (_tcp_stream, client_address) = listener.accept().await?;
		println!("New connection from: {client_address}");
	}
}
