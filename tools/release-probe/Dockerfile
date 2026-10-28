FROM ubuntu:24.04@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c
RUN apt-get update -qq && apt-get install -y --no-install-recommends ca-certificates libssl3t64 libudev1 && rm -rf /var/lib/apt/lists/*
COPY target/release/spr-release-probe /usr/local/bin/release-probe
COPY prover/server/prover/request/testdata/transfer-2x2.json /fixtures/confidential.json
COPY prover/server/prover/transfer_eddsa/testdata/eddsa-ring-2x2.json /fixtures/eddsa.json
USER 65532:65532
ENTRYPOINT ["release-probe"]
