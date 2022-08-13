FROM rust:1.62-slim-buster as builder

RUN mkdir -p /opt/xombie-build
COPY . /opt/xombie-build

WORKDIR /opt/xombie-build

RUN cargo build --release

FROM debian:buster-slim

# api
EXPOSE 80
# kdc
EXPOSE 88/udp
# faux_dns
EXPOSE 5300/udp
# sg
EXPOSE 3074/udp

RUN mkdir -p /opt/xombie/bin
WORKDIR /opt/xombie

COPY --from=builder /opt/xombie-build/target/release/api /opt/xombie/bin/api
COPY --from=builder /opt/xombie-build/target/release/kdc /opt/xombie/bin/kdc
COPY --from=builder /opt/xombie-build/target/release/faux-dns /opt/xombie/bin/faux-dns
COPY --from=builder /opt/xombie-build/target/release/sg /opt/xombie/bin/sg
