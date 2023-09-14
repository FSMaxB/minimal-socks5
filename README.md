# minimal-socks5

A minimal SOCKS5 server written in async rust with tokio.

This is not fully compliant with [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928).
Restrictions:
* Only authentication method is "No Authorization required".
* Only supports the `CONNECT` command and only via TCP.

This was written for my personal use only and I will change it and break compatibility as I see fit.
My use case is as a replacement of OpenSSH's builtin SOCK5 proxy for use with Wireguard instead of SSH tunneling.
