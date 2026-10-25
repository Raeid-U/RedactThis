FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/redactthis ./cmd/redactthis

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/redactthis /redactthis
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/redactthis"]

