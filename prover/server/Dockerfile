FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG GOAMD64
ARG PROVER_PGO
RUN GOAMD64="$GOAMD64" PROVER_PGO="$PROVER_PGO" sh ./build-release.sh /usr/local/bin/light-prover

FROM gcr.io/distroless/base-debian11:nonroot

COPY --from=builder /usr/local/bin/light-prover /usr/local/bin/light-prover

WORKDIR /proving-keys

COPY --chown=nonroot:nonroot ./proving-keys/*.key /proving-keys/

WORKDIR /

ENTRYPOINT [ "light-prover" ]
CMD [ "start", "--require-optimized-build", "--preload-circuits", "transfer-confidential:2:3,transfer-ring:2:3,transfer-p256-ring:2:3,merge:8:1", "--keys-dir", "/proving-keys/" ]
