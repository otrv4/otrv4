# OTR version 4: standalone mode

This document describes the version 4 of the Off-the-Record Messaging protocol,
in an operation mode that aims to provide an always encrypted mode with higher
security properties than OTR version 3. This mode will be referred as
"standalone mode".

## Mode description

An implementation of the OTRv4 protocol in standalone mode must be compliant
with the protocol specification
[OTRv4 protocol](../otrv4.md#table-of-contents), with the following exceptions
and the following changes.

Ignore these sections:

- "User requests to start an OTR conversation", including "Query Messages" and
  "Whitespace Tags".
- "Receiving plaintext without the whitespace tag".
- "Receiving plaintext with the whitespace tag".
- "Receiving a Query Message".

The specification for this mode, as compared with the full version, will
differ in these sections:

- "High Level Overview": there is not a "Requests OTR conversation" step.
- "Creating a User Profile": the "Versions" field must only allow the 2-byte
  version string "4".
- "Creating a User Profile": the "Transitional Signature" field is not allowed
  for this mode: there is no DSA signature generation or verification. When
  validating the user profile, this signature must not be verified.
- "Establishing Versions": ignore the paragraph: "A compliant OTRv4
  implementation is required to support version 3 of OTR, but not versions
  1 and 2". This mode only allows version 4 of the protocol.
- "Online Conversation Initialization": ignore everything that refers to query
  messages and whitespace tags.
- "Fragmentation": only a OTRv4 fragmentation is allowed. Ignore this paragraph:
  "For fragmentation in OTRv3, refer to the "Fragmentation" section on OTRv3
  specification".
- "Protocol states": the `START` and `FINISHED` states of the protocol state
  machine should not allow any message to be sent, since plaintext messages are
  not allowed in this mode.

// TODO: how will the DAKE work.. send an identity message?

// TODO: the double ratchet will change.

// TODO: probably state how the state machine will change

## Considerations

Plaintext messages are not allowed in conversations with OTRv4 standalone mode.
This means that querry messages and whitespace tags are not allowed in this
mode.

This mode is compliant with the security properties described in the
[security properties](../otrv4.md#security-properties) section.
