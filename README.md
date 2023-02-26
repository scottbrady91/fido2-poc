# WebAuthn/FIDO2 proof of concept in ASP.NET Core

**Currently undergoing a rewrite, moving away from a proof of concept towards more of a reference implementation for the core WebAuthn validation process, useful for demos, training, and WebuAuthn for MFA/passwordless (not usernameless).
This was implemented over a weekend, so there are plenty of hard-coded values hanging about from the initial hack.**

This is a proof of concept implementation of a WebAuthn (FIDO2) relying party in ASP.NET Core.

A WebAuthn relying party is a web server that invokes the WebAuthn API for FIDO authentication.

This is a reference implementation that only includes the basic functionality required to handle the core registration and authentication process.
It does not include the full enterprise features required for FIDO2 certification such as:

- attestation statement validation
- FIDO metadata validation

For enterprise-level features, consider [open source](https://github.com/passwordless-lib/fido2-net-lib) or [commercial](https://www.identityserver.com/products/fido2-for-aspnet) alternatives.
