FROM rust:1.94.1-trixie AS build
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config

RUN cargo build --release

FROM gcr.io/distroless/base-nossl-debian13:nonroot
WORKDIR /app

COPY --from=build /build/target/release/polaris /usr/local/bin/polaris
COPY --from=build /build/config /app/config

EXPOSE 8053
ENTRYPOINT ["/usr/local/bin/polaris"]
