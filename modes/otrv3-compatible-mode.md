# OTR version 4: compatible mode

This document describes the version 4 of the Off-the-Record Messaging protocol,
in a operation that aims to provide a transition path from the previous version
of the protocol, namely OTRv3, to the current version.

## Mode description

An implementation of the OTRv4 protocol in a OTRv3 compatible mode must be
compliant with the full protocol specification:
[OTRv4 protocol](../otrv4.md#table-of-contents). That
is, it must comply with every section on it.

## Considerations

Unlike the other two modes, plaintext messages are allowed in conversations with
OTRv4 compatible mode. The use of policies, similar to OTRv3, can be used to
safely handle the transition from an "encrypted" to a "plaintext" state.

Notice that in this mode, the security properties stated in the
[security properties](../otrv4.md#security-properties) section only hold for
when a conversation with OTRv4 is started. They do not hold for the previous
versions of the OTR protocol, meaning that if a user that supports version 3 and
4 starts a conversation with someone that only supports version 3, a
conversation with OTRv3 will start, and its security properties will not be the
ones stated in those paragraphs. The security properties will be those defined
by OTRv3.

The network model will also change when starting a conversation with OTRv3. If a
user that supports version 3 and 4 starts a conversation with someone that
only supports version 3, a conversation with OTRv3 will start, and its network
model will only provide in-order delivery of messages.