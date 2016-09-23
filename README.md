[![Build Status](https://travis-ci.org/mendersoftware/deviceauth.svg?branch=master)](https://travis-ci.org/mendersoftware/deviceauth)
[![codecov](https://codecov.io/gh/mendersoftware/deviceauth/branch/master/graph/badge.svg)](https://codecov.io/gh/mendersoftware/deviceauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/mendersoftware/deviceauth)](https://goreportcard.com/report/github.com/mendersoftware/deviceauth)

Mender: Device Authentication Service
==============================================

Mender is an open source over-the-air (OTA) software updater for embedded Linux
devices. Mender comprises a client running at the embedded device, as well as
a server that manages deployments across many devices.

This repository contains the Mender Device Authentication service, which is part of the
Mender server. The Mender server is designed as a microservices architecture
and comprises several repositories.

Device Authentication is responsible for issuing, maintaining and verifying
[JWT](jwt.io) authentication tokens used by devices in Mender API calls. A token
is issued as a result of a successful bootstrap request, whereby the device presents its
vendor-specific identity attributes, and can be admitted in the the system by the administrator.
Each subsequent device-specific API call is then internally routed to this service for token verification.
At any time, the administrator can also revoke the JWT in case it was compromised.


![Mender logo](https://mender.io/user/pages/04.resources/_logos/logoS.png)


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

* Join our [Google
  group](https://groups.google.com/a/lists.mender.io/forum/#!forum/mender)
* Follow us on [Twitter](https://twitter.com/mender_io?target=_blank). Please
  feel free to tweet us questions.
* Fork us on [Github](https://github.com/mendersoftware)
* Email us at [contact@mender.io](mailto:contact@mender.io)
