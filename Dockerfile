# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS backend
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
