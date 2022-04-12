FROM golang:1.16.5-alpine3.12 as builder
WORKDIR /go/src/github.com/mendersoftware/deviceauth
RUN apk add --no-cache ca-certificates
COPY ./ .
RUN CGO_ENABLED=0 GOARCH=amd64 go build -o deviceauth .

FROM scratch
EXPOSE 8080
# mount your private key at /etc/deviceauth/rsa/private.pem
WORKDIR /etc/deviceauth/rsa
COPY ./config.yaml /etc/deviceauth/
COPY --from=builder /go/src/github.com/mendersoftware/deviceauth/deviceauth /usr/bin/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/usr/bin/deviceauth", "--config", "/etc/deviceauth/config.yaml"]
