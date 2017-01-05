FROM alpine:3.4

COPY ./deviceauth /usr/bin/

RUN mkdir /etc/deviceauth
COPY ./config.yaml /etc/deviceauth/

# mount your private key at /etc/deviceauth/rsa/private.pem
RUN mkdir /etc/deviceauth/rsa

ENTRYPOINT ["/usr/bin/deviceauth", "-config", "/etc/deviceauth/config.yaml"]
