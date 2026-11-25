FROM rust:1.100.0-alpine3.24@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS builder
RUN apk add --no-cache libc-dev
WORKDIR /usr/src/minimal-socks5
COPY . .
RUN cargo install --locked --path .

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS minimal-socks5
LABEL minimal-socks5=latest
RUN apk add --no-cache shadow
RUN useradd -u 1000 -s /usr/bin/nologin minimal-socks5
COPY --from=builder --chown=minimal-socks5 /usr/local/cargo/bin/minimal-socks5 /usr/local/bin
USER minimal-socks5
CMD ["minimal-socks5"]
