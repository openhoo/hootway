# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -buildvcs=false -trimpath \
    -ldflags="-s -w -buildid= -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/rootfs/hootway ./cmd/hootway
# Minimal root filesystem: CA bundle for upstream TLS and an unprivileged user.
# Hootway needs no shell, libc, tzdata or MIME database.
RUN mkdir -p /out/rootfs/etc/ssl/certs /out/rootfs/tmp \
 && cp /etc/ssl/certs/ca-certificates.crt /out/rootfs/etc/ssl/certs/ \
 && printf 'root:x:0:0:root:/root:/sbin/nologin\nnonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin\n' > /out/rootfs/etc/passwd \
 && printf 'root:x:0:\nnonroot:x:65532:\n' > /out/rootfs/etc/group \
 && chmod 1777 /out/rootfs/tmp

FROM scratch
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Hootway" \
      org.opencontainers.image.description="API gateway that gives agent sandboxes scoped virtual keys instead of real API credentials" \
      org.opencontainers.image.source="https://github.com/openhoo/hootway" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$COMMIT" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/rootfs/ /
USER 65532:65532
EXPOSE 8787 8788
ENTRYPOINT ["/hootway"]
CMD ["serve", "-config", "/etc/hootway/hootway.json", "-listen", "0.0.0.0:8787"]
