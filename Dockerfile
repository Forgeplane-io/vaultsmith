# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM golang:1.26-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS backend
WORKDIR /src
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
COPY go.mod go.sum ./
RUN go mod download
COPY backend/ ./backend/
COPY --from=frontend /src/backend/web/dist ./backend/web/dist
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -trimpath -ldflags="-s -w -X github.com/forgeplane-io/vaultsmith/backend/internal/version.Version=${VERSION} -X github.com/forgeplane-io/vaultsmith/backend/internal/version.Commit=${COMMIT} -X github.com/forgeplane-io/vaultsmith/backend/internal/version.BuildDate=${BUILD_DATE}" -o /out/vaultsmith ./backend/cmd/server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Vaultsmith" \
      org.opencontainers.image.description="A UI for Ansible Vault 1.1/AES256 values" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/forgeplane-io/vaultsmith"
COPY --from=backend /out/vaultsmith /vaultsmith
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/vaultsmith"]
