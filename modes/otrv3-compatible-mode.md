# OTR version 4: compatible mode

This document describes the version 4 of the Off-the-Record Messaging protocol,
in a operation that aims to provide a transition path from the previous version
of the protocol, namely OTRv3, to the current version.

## Mode description

An implementation of the OTRv4 protocol in compatible mode must be compliant
with the full "master" [OTRv4 protocol](../otrv4.md#table-of-contents). That
is, it must comply with every section in the "master" specification.

## Considerations

Unlike the other two modes, plaintext messages are part of the protocol. The
use of policies, similar to OTRv3, can be used to handle this safely when
transitions from "encrypted" to "plaintext" are allowed.

TODO: We may want to mention implications of this mode (is there any
improvement or diminishement in regard to security properties? any potential
pitfall for implementors?).
