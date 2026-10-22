# Static musl build → scratch image. Result is a few-hundred-KB container
# with nothing but the binary.
FROM rust:1.83-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
# rust:alpine targets musl and links statically by default
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/phpsafepass /phpsafepass
# phpsafepass LISTEN UPSTREAM — override at `docker run`:
#   docker run -p 9000:9000 IMAGE 0.0.0.0:9000 php-fpm:9000
ENTRYPOINT ["/phpsafepass"]
CMD ["0.0.0.0:9000", "127.0.0.1:9001"]
