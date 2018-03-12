# OTR version 4: Interactive-Only Mode

This document describes the version 4 of the Off-the-Record Messaging protocol,
in a operation mode that aims to provide a always encrypted mode with only
interactive conversations. This aims to provide the highest security properties.

## Mode description

An implementation of the OTRv4 protocol in an interactive-only mode must be
compliant with the "standalone mode", with exceptions described below.

Ignore the sections:

- "Offline Conversation Initialization".
- "Conversation started by a Non-Interactive DAKE".
- "Sending an encrypted message to an offline participant".
- "Receiving a Non-Interactive-Auth message".

The specification for this mode, as compared with the "OTRv4-standalone"
version, will differ in these sections:

- "Public keys, Shared Prekeys and Fingerprints": an OTRv4's public shared
  prekey will never be created.
- "Creating a User Profile": the "Public Shared Prekey" field is not allowed
  for this mode: there is no Public Shared Prekey generation or verification.
  When validating the user profile, this field must not be verified.

## Considerations

This mode achieves different security properties as the ones described in the
[security properties](../otrv4.md#security-properties) section, as it does
not achieve the security properties given by a non-interactive DAKE. Therefore,
it provides offline and online (participation) deniability for both participants.