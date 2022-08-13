FROM rust:1.55 as builder

RUN mkdir -p /opt/xombie
COPY . /opt/xombie

WORKDIR /opt/xombie/services/api
RUN cargo build --release

FROM debian:buster

EXPOSE 80

RUN mkdir -p /opt/xombie/bin
WORKDIR /opt/xombie

COPY --from=builder /opt/xombie/target/release/api /opt/xombie/bin/api

CMD ["./bin/api"]
