FROM golang:1.27.2 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /tunneld ./cmd/tunneld
RUN sh scripts/third-party-licenses.sh /THIRD_PARTY_LICENSES.txt

FROM gcr.io/distroless/static:nonroot
COPY --from=build /tunneld /tunneld
COPY --from=build /THIRD_PARTY_LICENSES.txt /THIRD_PARTY_LICENSES.txt
ENTRYPOINT ["/tunneld", "serve"]
