# WebAuthn/FIDO2 proof of concept in ASP.NET Core

## Rewrite

> Currently undergoing a rewrite, moving away from a proof of concept towards more of a reference implementation for the core WebAuthn validation process, useful for demos, training, and WebuAuthn for MFA/passwordless (not usernameless).
> This was initially implemented over a weekend, so there are plenty of hard-coded values hanging about from the initial hack.

Current limitations:

- In-memory options store (future: challenge cookie implementation, binding FIDO ceremony to browser)
- In-memory key store
- Tested for ES256 and RS256 only
- Bytes sent to browser as int[] (for simple conversion to Uint8Array)

## Overview

This is a proof of concept implementation of a WebAuthn (FIDO2) relying party in ASP.NET Core.

A WebAuthn relying party is a web server that invokes the WebAuthn API for FIDO authentication.

This is a reference implementation that only includes the basic functionality required to handle the core registration and authentication process.
It is designed to get you up and running with WebAuthn and FIDO2 as quickly as possible, without the need for custom controllers/APIs or the management of temporary data and license keys.

It does not include the full enterprise features required for FIDO2 certification such as:

- attestation statement validation
- FIDO metadata validation

For enterprise-level features, consider [open source](https://github.com/passwordless-lib/fido2-net-lib) or [commercial](https://www.identityserver.com/products/fido2-for-aspnet) alternatives.
