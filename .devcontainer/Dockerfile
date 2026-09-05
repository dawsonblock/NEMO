# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

FROM mcr.microsoft.com/devcontainers/base:bookworm

ARG TARGETARCH
ARG RUST_VERSION=1.96.1
ARG NODE_VERSION=24.0.0
ARG GO_VERSION=1.26.1
ARG UV_VERSION=0.9.28
ARG PROTOC_VERSION=33.1
ARG JUST_VERSION=1.47.1
ARG CARGO_NEXTEST_VERSION=0.9.133
ARG CARGO_DENY_VERSION=0.19.1
ARG CARGO_ABOUT_VERSION=0.9.1
ARG CARGO_LLVM_COV_VERSION=0.8.5
ARG CARGO_AUDIT_VERSION=0.22.2

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential ca-certificates clang cmake curl git libssl-dev pkg-config \
        python3.11 python3.11-dev python3.11-venv unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

USER vscode
ENV PATH=/home/vscode/.cargo/bin:/home/vscode/.local/bin:/usr/local/go/bin:/opt/node/bin:${PATH}

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal \
    && rustup component add clippy rustfmt \
    && cargo install just --version ${JUST_VERSION} --locked \
    && cargo install cargo-nextest --version ${CARGO_NEXTEST_VERSION} --locked \
    && cargo install cargo-deny --version ${CARGO_DENY_VERSION} --locked \
    && cargo install cargo-about --version ${CARGO_ABOUT_VERSION} --locked --features cli \
    && cargo install cargo-llvm-cov --version ${CARGO_LLVM_COV_VERSION} --locked \
    && cargo install cargo-audit --version ${CARGO_AUDIT_VERSION} --locked

USER root
RUN case "${TARGETARCH}" in \
        amd64) node_arch=x64; go_arch=amd64; protoc_arch=x86_64 ;; \
        arm64) node_arch=arm64; go_arch=arm64; protoc_arch=aarch_64 ;; \
        *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" \
    && mkdir -p /opt/node \
    && tar -xJf /tmp/node.tar.xz --strip-components=1 -C /opt/node \
    && /opt/node/bin/npm install --global npm@11.11.0 \
    && curl -fsSLo /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && curl -fsSLo /tmp/protoc.zip "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${protoc_arch}.zip" \
    && unzip -q /tmp/protoc.zip -d /usr/local \
    && rm -f /tmp/node.tar.xz /tmp/go.tar.gz /tmp/protoc.zip

USER vscode
RUN curl -LsSf https://astral.sh/uv/${UV_VERSION}/install.sh | sh

WORKDIR /workspace/NeMo-Relay
