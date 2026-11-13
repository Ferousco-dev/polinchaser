# One image, three binaries. Render picks the command per service.
ARG GO_VERSION=1.27.4
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/polinchaser ./cmd/polinchaser \
 && go build -trimpath -ldflags="-s -w" -o /out/polinchaser-worker ./cmd/polinchaser-worker \
 && go build -trimpath -ldflags="-s -w" -o /out/polinchaser-scan ./cmd/polinchaser-scan

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /
USER nonroot:nonroot
ENTRYPOINT ["/polinchaser"]
