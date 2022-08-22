FROM rust:1.62-slim-buster AS builder
ENV BUILD_DIR=/opt/xombie-build
WORKDIR ${BUILD_DIR}

# -- build from scratch
COPY libs        ${BUILD_DIR}/libs
COPY services    ${BUILD_DIR}/services
COPY third_party ${BUILD_DIR}/third_party
COPY tools       ${BUILD_DIR}/tools
COPY Cargo.toml  ${BUILD_DIR}/Cargo.toml
COPY Cargo.lock  ${BUILD_DIR}/Cargo.lock
RUN cargo build --release

# -- or copy in pre-built binaries
# RUN mkdir -p ${BUILD_DIR}/target
# COPY target/release ${BUILD_DIR}/target/release

FROM debian:buster-slim AS common
RUN mkdir -p /opt/xombie/bin
WORKDIR /opt/xombie

FROM common AS api
EXPOSE 80
COPY --from=builder /opt/xombie-build/target/release/api /opt/xombie/bin/api

FROM common AS kdc
EXPOSE 88/udp
COPY --from=builder /opt/xombie-build/target/release/kdc /opt/xombie/bin/kdc

FROM common AS dns
EXPOSE 5300/udp
COPY --from=builder /opt/xombie-build/target/release/faux-dns /opt/xombie/bin/faux-dns

FROM common AS sg
EXPOSE 3074/udp
COPY --from=builder /opt/xombie-build/target/release/sg /opt/xombie/bin/sg
