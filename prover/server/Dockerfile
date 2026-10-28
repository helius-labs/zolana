FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

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
CMD [ "start", "--require-optimized-build", "--preload-circuits", "transfer-confidential:2:2,transfer-ring:2:2,transfer-eddsa-ring:2:2,merge:24:1", "--keys-dir", "/proving-keys/" ]
