# WebAuthn/FIDO2 proof of concept in ASP.NET Core

## Rewrite

> This implementation is currently undergoing a rewrite, moving away from a proof of concept towards more of a reference implementation for the core WebAuthn validation process.
> This is useful for demos, training, and understanding the basics of WebAuthn.
> This was initially implemented over a weekend, so there are plenty of hard-coded values hanging about from the initial hack.

## Overview

This is a proof of concept implementation of a WebAuthn (FIDO2) relying party in ASP.NET Core.

A WebAuthn relying party is a web server that invokes the WebAuthn API for FIDO authentication.

This is a reference implementation that only includes the basic functionality required to handle the core registration and authentication process.
It is designed to get you up and running with WebAuthn and FIDO2 as quickly as possible, without the need for custom controllers/APIs or the management of temporary data and license keys.

## Limitations

To get started with this implementation, download the codebase and run the sample.
Step through the code and get a feel for how WebAuthn works.
**If there is demand, I will upload the library to nuget; however, I currently have no plans to do so.**

Current rewrite limitations:

- In-memory options store (future: challenge cookie implementation, binding FIDO ceremony to browser)
- JSON or in-memory key store
- Only tested for ES256 and RS256
- Bytes sent to browser as int[] (for simple conversion to Uint8Array)
- Woefully un-unit tested (somewhat intentionally)

This implementation does not include the full enterprise features required for FIDO2 certification such as:

- attestation statement validation
- FIDO metadata validation

These are no-fun to implement, and, in my opinion, aren't the main selling points of FIDO/WebAuthn.

For enterprise-level features, consider [open source](https://github.com/passwordless-lib/fido2-net-lib) or [commercial](https://www.identityserver.com/products/fido2-for-aspnet) alternatives.
