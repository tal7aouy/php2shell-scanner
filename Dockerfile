FROM golang:1-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/php2shell ./cmd/php2shell


FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=build /out/php2shell /usr/local/bin/php2shell
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/php2shell"]
