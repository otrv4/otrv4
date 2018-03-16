# OTR version 4: Interactive-Only Mode

[ADR 10](https://github.com/otrv4/otrv4/tree/master/architecture-decisions/010-modes.md)
defines the need for specifying alternative modes for the OTR protocol
version 4.

This document describes the version 4 of the Off-the-Record Messaging protocol,
in a operation mode that aims to provide a always encrypted mode that supports
only interactive conversations. This mode provides the highest security
properties in comparison with the other modes. It is not backwards compatible
with OTRv3.

## Mode description

An implementation of the OTRv4 protocol in an Interactive-Only mode must be
compliant with the OTRv4-Standalone mode, with exceptions described below.

Ignore the sections:

- "Offline Conversation Initialization".
- "Conversation started by a Non-Interactive DAKE".
- "Encrypted messages in DAKE's messages".
- "Sending a data message to an offline participant".
- "Receiving a Non-Interactive-Auth message".

The specification for this mode, as compared with the "OTRv4-standalone"
version, will differ in these sections:

- "Public keys, Shared Prekeys and Fingerprints": an OTRv4's public shared
  prekey will never be created.
- "Creating a User Profile": the `Public Shared Prekey` field is not allowed
  for this mode: there is no Public Shared Prekey generation or verification.
  When validating the user profile, this field must not be verified.
- The `ENCRYPTED_MESSAGES` state is the only state where a participant is
  allowed to send encrypted data messages.

Furthermore, ignore the whole OTRv4 Prekey Server specification.

### Scenarios and applications

This mode will work on the same kind of applications and scenarios defined
for the OTRv4-Standalone mode.

## Considerations

This mode will take into account the same kind considerations defined for the
OTRv4-Standalone mode.

Nevertheless, this mode achieves different security properties as the ones
described in the [security properties](../otrv4.md#security-properties) section,
as it does not include the security properties given by a non-interactive DAKE.
Therefore, it provides offline and online (participation) deniability for both
participants.