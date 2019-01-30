FROM ubuntu:16.04

RUN apt update && \
    apt install -y clang git curl pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

ENV PATH=$PATH:/root/.cargo/bin
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN git clone https://github.com/kobigurk/privacypass-rs && cd privacypass-rs && git submodule update --init --recursive

EXPOSE 2416

WORKDIR privacypass-rs/example_data

RUN cargo build --bin privacypass-rs-server --release

CMD ["cargo", "run", "--bin", "privacypass-rs-server", "--release"]
