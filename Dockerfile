FROM rust:alpine as builder
RUN apk update && apk add libc-dev
WORKDIR /usr/src/minimal-socks5
COPY . .
RUN cargo install --path .

FROM alpine:latest as minimal-socks5
LABEL minimal-socks5=latest
RUN apk add --no-cache shadow
RUN useradd -u 1000 -s /usr/bin/nologin minimal-socks5
COPY --from=builder --chown=minimal-socks5 /usr/local/cargo/bin/minimal-socks5 /usr/local/bin
USER minimal-socks5
CMD ["minimal-socks5"]
