## ADR 11: "OTRv4 only" mode

### Context

ADR #010 defines the need for specifying alternative modes for the OTR protocol
version 4.

This document outlines the implications of having a "OTRv4 only" mode to the
spec as per revision 585ba0dfcecf6abc0d30ba0ff0524bce3795110a.

### Decision

(From ADR #010)

> OTRv4 only: a always encrypted mode. This mode will not know how to handle
> any kind of plain text, including query messages and whitespace tags.

> Furthermore, 'OTRv4 only' mode will only support version 4 of OTR. The User
> Profile, therefore will only allow the 1-byte version string "4". It will also
> not allow the Transition Signature parameter on the same profile.


### Consequences

