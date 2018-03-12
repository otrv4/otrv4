# OTR version 4: Standalone Mode

[ADR#010](https://github.com/otrv4/otrv4/tree/master/architecture-decisions)
defines the need for specifying alternative modes for the OTR protocol
version 4.

This document describes the version 4 of the Off-the-Record Messaging protocol,
in an operation mode that aims to provide an always encrypted mode with higher
security properties than OTRv3. This mode will be referred as the "standalone
mode".

The 'OTRv4-standalone' mode is an always encrypted mode. It does not know how to
handle any kind of plaintext messages, including query messages and whitespace
tags. It supports both interactive and non-interactive conversations. It is
not backwards compatible with OTRv3.

## Mode description

An implementation of the OTRv4 protocol in standalone mode must be compliant
with the overall protocol specification
[OTRv4 protocol](../otrv4.md#table-of-contents), with the following exceptions
and the following changes.

Ignore these sections:

- "User requests to start an OTR conversation", including "Query Messages" and
  "Whitespace Tags".
- "Receiving plaintext without the whitespace tag".
- "Receiving plaintext with the whitespace tag".
- "Receiving a Query Message".

The specification for this mode, as compared with the overall version, will
differ in these sections:

- "High Level Overview": there is not a "Requests OTR conversation" step.
- "Conversation started by an Interactive DAKE": the conversation begins when
  a participant sends an identity message. In this mode, there is no
  advertisement of which version a participant supports as both parties
  only support OTRv4.
- "Creating a User Profile": the `Versions` field must only allow the 1-byte
  version string "4".
- "Creating a User Profile": the `Transitional Signature` field is not allowed
  in this mode: there is no DSA signature generation or verification. Therefore,
  when validating a user profile, the DSA signature must not be verified.
- "Establishing Versions": ignore the paragraph: "A compliant OTRv4
  implementation is required to support version 3 of OTR, but not versions
  1 and 2". This mode only allows version 4 of the protocol.
- "Online Conversation Initialization": ignore everything that refers to query
  messages and whitespace tags.
- "Fragmentation": only OTRv4 fragmentation is allowed. Ignore this paragraph:
  "For fragmentation in OTRv3, refer to the "Fragmentation" section on OTRv3
  specification".
- "Protocol states": the `START` and `FINISHED` states of the protocol state
  machine should not allow any message to be sent, since plaintext messages are
  not allowed in this mode.

// TODO: how will the DAKE work.. send an identity message?

// TODO: the double ratchet will change.

// TODO: probably state how the state machine will change

## Considerations

Plaintext messages are not allowed in conversations in OTRv4-standalone mode.
This means that querry messages and whitespace tags are not allowed in this
mode.

By always requiring encryption, this mode may encourage long-lived sessions.
The section "Session expiration" of the OTRv4 protocol specification outlines
how to mitigate the risks of long-lived sessions. For this reason, TLVs type 1
(Disconnected) are necessary in this mode.

Even though there is no need to prefix OTR messages with the five bytes "?OTR:",
since the protocol only handles OTR messages, this mode does not modify this
encoding for convenience.

This mode is compliant with the security properties described in the
[security properties](../otrv4.md#security-properties) section.
