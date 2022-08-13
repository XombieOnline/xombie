FROM rust:1.55 as builder

RUN mkdir -p /opt/xombie
COPY . /opt/xombie

WORKDIR /opt/xombie/services/sg
RUN cargo build --release

FROM debian:buster-slim

EXPOSE 3074/udp

RUN mkdir -p /opt/xombie/bin
WORKDIR /opt/xombie

COPY --from=builder /opt/xombie/target/release/sg /opt/xombie/bin/sg

CMD ["./bin/sg"]
