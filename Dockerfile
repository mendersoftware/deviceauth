FROM golang:1.11 as builder
ENV GO111MODULE=on
RUN mkdir -p /build
WORKDIR /build
ADD ./vendor /build/vendor
RUN go mod download
ADD . /build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /build/deviceauth .

FROM alpine:3.4
EXPOSE 8080
COPY --from=builder /build/deviceauth /usr/bin/
RUN mkdir /etc/deviceauth
COPY ./config.yaml /etc/deviceauth/
# mount your private key at /etc/deviceauth/rsa/private.pem
RUN mkdir /etc/deviceauth/rsa
ENTRYPOINT ["/usr/bin/deviceauth", "--config", "/etc/deviceauth/config.yaml"]
RUN apk add --update ca-certificates && update-ca-certificates
