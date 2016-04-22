FROM iron/base

COPY ./deviceauth /usr/bin/

RUN mkdir /etc/deviceauth
COPY ./config.yaml /etc/deviceauth/

ENTRYPOINT ["/usr/bin/deviceauth", "-config", "/etc/deviceauth/config.yaml"]
