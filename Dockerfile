FROM golang:1.24-bookworm AS build
WORKDIR /src
ENV GOMAXPROCS=2 CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
ARG TARGETARCH
RUN GOARCH=${TARGETARCH:-amd64} go build -p=2 -trimpath -ldflags='-s -w' -o /out/tzsingbox ./cmd/tzsingbox

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build --chown=65532:65532 /out/tzsingbox /tzsingbox
USER 65532:65532
EXPOSE 8080 8443
ENTRYPOINT ["/tzsingbox"]
