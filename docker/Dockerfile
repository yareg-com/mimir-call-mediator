FROM rust:1.95.0-alpine3.23 AS builder

ENV APP=mimir-call-mediator

WORKDIR /usr/src/$APP

COPY Cargo.toml Cargo.lock ./

# Cache dependencies by creating a dummy main.rs to compile dependencies first
# This ensures that if only source code changes, the dependencies remain cached
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/$APP

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM alpine:3.23.4

ENV APP=mimir-call-mediator
ENV DATA_PATH=/var/lib/$APP

RUN apk --no-cache add curl && \
    adduser --disabled-password --gecos '' $APP && \
    mkdir -p $DATA_PATH && chown -R $APP $DATA_PATH

WORKDIR /home/$APP
USER $APP

COPY --from=builder /usr/src/mimir-call-mediator/target/release/mimir-call-mediator /usr/local/bin/$APP
COPY --chmod=755 ./docker/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
