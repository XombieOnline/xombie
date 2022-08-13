FROM rust:1.55 as builder

RUN mkdir -p /opt/xombie
COPY . /opt/xombie

WORKDIR /opt/xombie/services/kdc
RUN cargo build --release

FROM debian:buster-slim

EXPOSE 88/udp

RUN mkdir -p /opt/xombie/bin
WORKDIR /opt/xombie

COPY --from=builder /opt/xombie/target/release/kdc /opt/xombie/bin/kdc

CMD ["./bin/kdc"]
