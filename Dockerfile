FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/hootway ./cmd/hootway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/hootway /hootway
EXPOSE 8787
ENTRYPOINT ["/hootway"]
CMD ["serve", "-config", "/etc/hootway/hootway.json", "-listen", "0.0.0.0:8787"]
