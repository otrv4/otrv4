# OTR version 4: version 4 only mode ("standalone" mode?)

This document describes the version 4 of the Off-the-Record Messaging protocol,
in an operation mode that aims to provide an always encrypted mode with higher
security properties than OTR version 3.

## Mode description

An implementation of the OTRv4 protocol in compatible mode must be compliant
with the "master" [OTRv4 protocol](../otrv4.md#table-of-contents), with
exceptions described below.

Ignore the sections:

- "User requests to start an OTR conversation".
- "Receiving plaintext without the whitespace tag".
- "Receiving plaintext with the whitespace tag".
- "Receiving a Query Message".

The spec for this mode would be the same spec as per (current revision) except:

- "High Level Overview": there's no "Requests OTR conversation" step.
- "Creating a User Profile": "Versions" MUST be "4" only.
- "Establishing Versions": ignore the paragraph "A compliant OTRv4
  implementation is required to support version 3 of OTR, but not versions
  1 and 2.".
- "Online Conversation Initialization": Ignore everything about query messages
  and whitespace tags.
- "Protocol states": the START and FINISHED protocol states should not allow
  messages to be sent, since plaintext messages are not part of this mode.

## Considerations

TODO: We may want to mention implications of this mode (is there any
improvement or diminishement in regard to security properties? any potential
pitfall for implementors?).
