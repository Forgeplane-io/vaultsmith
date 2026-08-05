# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM node:26-alpine@sha256:233761595746769ebfdb6090f44fc7cdf818ae0ce62d2b37e0367723b9823e36 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS backend
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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
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
