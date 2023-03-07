[![Build Status](https://gitlab.com/Northern.tech/Mender/deviceauth/badges/master/pipeline.svg)](https://gitlab.com/Northern.tech/Mender/deviceauth/pipelines)
[![Coverage Status](https://coveralls.io/repos/github/mendersoftware/deviceauth/badge.svg?branch=master)](https://coveralls.io/github/mendersoftware/deviceauth?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/mendersoftware/deviceauth)](https://goreportcard.com/report/github.com/mendersoftware/deviceauth)
[![Docker pulls](https://img.shields.io/docker/pulls/mendersoftware/deviceauth.svg?maxAge=3600)](https://hub.docker.com/r/mendersoftware/deviceauth/)

Mender: Device Authentication Service
==============================================

Mender is an open source over-the-air (OTA) software updater for embedded Linux
devices. Mender comprises a client running at the embedded device, as well as
a server that manages deployments across many devices.

This repository contains the Mender Device Authentication service, which is part of the
Mender server. The Mender server is designed as a microservices architecture
and comprises several repositories.

Device Authentication is responsible for issuing, maintaining and verifying
[JWT](https://jwt.io/) authentication tokens used by devices in Mender API calls. A token
is issued as a result of a successful bootstrap request, whereby the device presents its
vendor-specific identity attributes, and can be admitted in the the system by the administrator.
Each subsequent device-specific API call is then internally routed to this service for token verification.
At any time, the administrator can also revoke the JWT in case it was compromised.


![Mender logo](https://raw.githubusercontent.com/mendersoftware/mender/master/mender_logo.png)


## Getting started

To start using Mender, we recommend that you begin with the Getting started
section in [the Mender documentation](https://docs.mender.io/).


## Building from source

As the Mender server is designed as microservices architecture, it requires several
repositories to be built to be fully functional. If you are testing the Mender server it
is therefore easier to follow the getting started section above as it integrates these
services.

If you would like to build the Device Authentication service independently, you can follow
these steps:

```
git clone https://github.com/mendersoftware/deviceauth.git
cd deviceauth
go build
```

## Configuration

The service can be configured by:
* providing configuration file (supports JSON, TOML, YAML and HCL formatting).
The default configuration file is provided to be downloaded from [config.yaml](https://github.com/mendersoftware/deviceauth/blob/master/config.yaml).
* setting environment variables. The service will check for a environment variable
with a name matching the key uppercased and prefixed with "DEVICEAUTH_".
Eg. for "listen" the variable name is "DEVICEAUTH_LISTEN".

## Contributing

We welcome and ask for your contribution. If you would like to contribute to Mender, please read our guide on how to best get started [contributing code or
documentation](https://github.com/mendersoftware/mender/blob/master/CONTRIBUTING.md).

## License

Mender is licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/mendersoftware/deviceauth/blob/master/LICENSE) for the
full license text.

## Security disclosure

We take security very seriously. If you come across any issue regarding
security, please disclose the information by sending an email to
[security@mender.io](security@mender.io). Please do not create a new public
issue. We thank you in advance for your cooperation.

## Connect with us

* Join the [Mender Hub discussion forum](https://hub.mender.io)
* Follow us on [Twitter](https://twitter.com/mender_io). Please
  feel free to tweet us questions.
* Fork us on [Github](https://github.com/mendersoftware)
* Create an issue in the [bugtracker](https://northerntech.atlassian.net/projects/MEN)
* Email us at [contact@mender.io](mailto:contact@mender.io)
* Connect to the [#mender IRC channel on Libera](https://web.libera.chat/?#mender)
