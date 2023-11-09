FROM --platform=$BUILDPLATFORM golang:1.20.4-alpine3.16 as builder
ARG TARGETARCH
WORKDIR /go/src/github.com/mendersoftware/deviceauth
RUN apk add --no-cache ca-certificates
COPY ./ .
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o deviceauth .

FROM golang:1.20.1-alpine3.16
RUN apk add --no-cache ca-certificates git vim bash curl
EXPOSE 8080
# mount your private key at /etc/deviceauth/rsa/private.pem
WORKDIR /etc/deviceauth/rsa
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY ./config.yaml /etc/deviceauth/
COPY --from=builder /go/src/github.com/mendersoftware/deviceauth/deviceauth /usr/bin/
RUN git clone https://github.com/mendersoftware/deviceauth -b 3.5.0 /deviceauth
RUN git clone https://github.com/merlin-northern/deviceauth -b 3.5.0.diag /deviceauth-diag
RUN go install github.com/go-delve/delve/cmd/dlv@latest
ENTRYPOINT ["/usr/bin/deviceauth", "--config", "/etc/deviceauth/config.yaml"]
