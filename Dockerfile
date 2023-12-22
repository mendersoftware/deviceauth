FROM --platform=$BUILDPLATFORM golang:1.21.5-alpine3.19 as builder
ARG TARGETARCH
WORKDIR /go/src/github.com/mendersoftware/deviceauth
RUN mkdir -p /etc_extra
RUN echo "nobody:x:65534:" > /etc_extra/group
RUN echo "nobody:!::0:::::" > /etc_extra/shadow
RUN echo "nobody:x:65534:65534:Nobody:/:" > /etc_extra/passwd
RUN mkdir -p /tmp_extra && chown nobody:nobody /tmp_extra
RUN chown -R nobody:nobody /etc_extra
RUN apk add --no-cache ca-certificates
COPY ./ .
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -trimpath -o deviceauth .

FROM scratch
EXPOSE 8080
COPY --from=builder /etc_extra/ /etc/
COPY --from=builder --chown=nobody /tmp_extra/ /tmp/
USER 65534
# mount your private key at /etc/deviceauth/rsa/private.pem
WORKDIR /etc/deviceauth/rsa
COPY --from=builder --chown=nobody /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --chown=nobody ./config.yaml /etc/deviceauth/
COPY --from=builder --chown=nobody /go/src/github.com/mendersoftware/deviceauth/deviceauth /usr/bin/
ENTRYPOINT ["/usr/bin/deviceauth", "--config", "/etc/deviceauth/config.yaml"]
