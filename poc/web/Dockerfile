# syntax=docker/dockerfile:1
# Build context is the repository root, `just poc-deploy` passes it.

FROM golang:1.25-alpine AS wasm
WORKDIR /src/prover/server
COPY prover/server/go.mod prover/server/go.sum ./
RUN go mod download
COPY prover/server/ ./
RUN GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" \
      -o /out/zolana-prover.wasm ./cmd/prover-wasm/ \
 && cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" /out/wasm_exec.js

FROM node:24-alpine AS web
WORKDIR /src
COPY package.json package-lock.json LICENSE ./
COPY sdk-libs/ts/package.json sdk-libs/ts/
COPY poc/core/package.json poc/core/
COPY poc/web/package.json poc/web/
RUN npm ci --no-audit --no-fund
COPY sdk-libs/ts/ sdk-libs/ts/
COPY poc/core/ poc/core/
COPY poc/web/ poc/web/
COPY prover/server/prover/provingkeys/proving-keys.lock prover/server/prover/provingkeys/
COPY --from=wasm /out/wasm_exec.js poc/core/src/vendor/
COPY --from=wasm /out/zolana-prover.wasm poc/web/public/prover/
ENV VITE_ZOLANA_DEFAULT_PRESET=devnet
RUN npm run build:ts && npm run poc:build \
 && node poc/web/scripts/key-manifest.mjs poc/web/dist/keys/manifest.json \
 && node -p 'JSON.parse(require("fs").readFileSync("prover/server/prover/provingkeys/proving-keys.lock","utf8")).prefix' \
      > poc/web/dist/.keys-prefix

FROM nginx:1.27-alpine
COPY poc/web/deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=web /src/poc/web/dist/ /usr/share/nginx/html/
RUN sed -i "s|__KEYS_PREFIX__|$(cat /usr/share/nginx/html/.keys-prefix)|" /etc/nginx/conf.d/default.conf \
 && rm /usr/share/nginx/html/.keys-prefix \
 && nginx -t
EXPOSE 8080
