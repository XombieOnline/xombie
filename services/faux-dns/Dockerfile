FROM rust:1.55 as builder

RUN mkdir -p /opt/xombie
COPY . /opt/xombie

WORKDIR /opt/xombie/services/faux-dns
RUN cargo build --release

FROM debian:buster-slim

EXPOSE 5300/udp

RUN mkdir -p /opt/xombie/bin
WORKDIR /opt/xombie

COPY --from=builder /opt/xombie/target/release/faux-dns /opt/xombie/bin/faux-dns

CMD ["./bin/faux-dns"]
