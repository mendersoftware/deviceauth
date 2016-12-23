FROM alpine:3.4

COPY ./deviceauth /usr/bin/

RUN mkdir /etc/deviceauth
COPY ./config.yaml /etc/deviceauth/

# example server private key - only for testing purpose
# this key will be replaced with proper one later
RUN mkdir /etc/rsa
COPY ./testdata/private.pem /etc/rsa/

ENTRYPOINT ["/usr/bin/deviceauth", "-config", "/etc/deviceauth/config.yaml"]
