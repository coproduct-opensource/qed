# The QED seller image: the seller and the tools it runs, prebuilt.
#
# Build from the repository root (built with Docker BuildKit on x86-64 Linux
# and Apple `container` on arm64; give the builder enough memory, since
# RISC Zero's C++ was killed in a 2 GB builder and passed in 20 GB):
#   docker build -f Containerfile -t qed-seller:local .
#   container build -c 8 -m 20g -f Containerfile -t qed-seller:local .
#
# What is in it: nucleus-seller, nucleus-buyer, nucleus-vault-ops,
# nucleus-fixture-prover, qed-wrap, qed-groth16-data, and the prover host
# (nucleus-acceptance-host) built to prove in-process, so no r0vm is needed.
# What is not: RISC Zero's Groth16 circuit data (4.2 GB). A seller either asks
# a wrap service (`"groth16": "remote:https://…"`) or fetches the data once
# into a volume with `qed-groth16-data /data/groth16` (archive and files are
# checked against pinned SHA-256 values) and sets `"groth16Data"`.
#
# Base images are pinned by multi-architecture index digest.
ARG RUST_IMAGE=docker.io/library/rust:1.96.1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

FROM ${RUST_IMAGE} AS build
# The binaries carry no dependency metadata, so a scan of the final image
# finds only Debian packages (measured 2026-11-13: 92 packages, no Rust
# crates). With this, BuildKit's SBOM also scans this stage, whose
# Cargo.lock files name every crate (it over-reports: every lockfile in the
# tree is read, not only the two built here).
ARG BUILDKIT_SBOM_SCAN_STAGE=true
WORKDIR /src
COPY . .
ENV CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR=/target \
    RISC0_SKIP_BUILD=1 \
    CARGO_NET_RETRY=5
# Remap the build's paths so no build-machine path ends up in a binary.
ENV RUSTFLAGS="--remap-path-prefix=/src=/qed --remap-path-prefix=/usr/local/cargo=/cargo"
RUN cargo build --locked --release --manifest-path contracts/agents/Cargo.toml --bins
RUN cargo build --locked --release --manifest-path contracts/proof-acceptance/zkvm/Cargo.toml \
        -p nucleus-acceptance-host --features in-process-prover
RUN mkdir -p /out \
 && cp /target/release/nucleus-seller /target/release/nucleus-buyer \
       /target/release/nucleus-vault-ops /target/release/nucleus-fixture-prover \
       /target/release/qed-wrap /target/release/qed-groth16-data \
       /target/release/nucleus-acceptance-host /out/

FROM ${RUNTIME_IMAGE}
# ca-certificates for TLS to RPC endpoints and the data download; nothing else.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin qed \
 && mkdir -p /data && chown qed /data
COPY --from=build /out/ /usr/local/bin/
# Work, keys and circuit data live in /data; mount a volume there. The root
# filesystem can be mounted read-only.
ENV HOME=/data
WORKDIR /data
VOLUME ["/data"]
USER 10001
ENTRYPOINT ["/usr/local/bin/nucleus-seller"]
CMD ["watch", "/data/seller.json"]
