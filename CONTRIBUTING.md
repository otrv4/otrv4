# Contributing to OTRv4

If you have any questions, comments, doubts or concerns, please feel free to
reach us at the #otr channel on the OFTC IRC network. We are working on also
providing an slack channel for more contact. You can also contact us through
our [mailing list](https://lists.cypherpunks.ca/mailman/listinfo/otr-dev).

For requests, suggestions and bug reports, please open an issue on our Github,
on the appropriate repository. If you want to fix a bug or suggest something,
ask for mentoring to Sofía Celi at sofia@otr.im

## A few things everyone can do

* Spread the word around OTR and its new version. Tell your friends!
* We always look for examples of how OTR is used or how or how can it be used.
  If you know, let us know!

## Getting started with OTRv4

Thanks so much for your interest in collaborating!

This guide is not only about collaborating with the OTRv4 protocol; but rather
with the whole OTRv4 ecosystem!

The OTRv4 project is divided as follows:

* The OTRv4 core/main protocol, which can be
  found [here](https://github.com/otrv4/otrv4/blob/master/otrv4.md).
* The OTRv4 protocol in its interaction with the Prekey Server, which can be
  found [here](https://github.com/otrv4/otrv4-prekey-server/blob/master/otrv4-prekey-server.md).
* The OTRv4 main C library (libotr-ng), which can be
  found [here](https://github.com/otrv4/libotr-ng).
* The OTRv4 main Golang library (otr4), which can be
  found [here](https://github.com/otrv4/otr4)
  and [here](https://github.com/coyim/gotra).
* The OTRv4 implementation of the Prekey Server in Golang, which can be
  found [here](https://github.com/otrv4/otrng-prekey-server).
* The OTRv4 implementation of the XMPP Prekey Server in Golang, which can be
  found [here](https://github.com/otrv4/prekey-server-xmpp).
* The Prekey Server which can be used for testing. It can be
  found [here](https://github.com/otrv4/prekey-server-docker-compose).
* The OTRv4 plugin for the Pidgin client, which can be
  found [here](https://github.com/otrv4/pidgin-otrng).
* The OTRv4 toolkit for checking its properties, which can be
  found [here](https://github.com/otrv4/libotr-ng-toolkit).
* The ed448-Goldilocks Golang library used by OTRv4, which can be
  found [here](https://github.com/otrv4/ed448).
* The ed448-Goldilocks C library used by OTRv4, which can be
  found [here](https://github.com/otrv4/libgoldilocks).
* Recommendations for clients implementing OTRv4, which can be
  found [here](https://github.com/otrv4/otrv4-client-imp-recommendations).
* A list of OTRv4 properties and papers related to it, which can be
  found [here](https://github.com/otrv4/OTRv4-properties).
* A draft of OTRv4 XEP, which can be
  found [here](https://github.com/otrv4/OTRv4-over-XMPP).

## Required background

Knowledge of the OTRv4 protocol is needed, so it is encouraged to read the
protocols. Our libraries are manly written in C and in Golang, so you
will have some knowledge of them in order to contribute.

You should also have background knowledge of Git. Here is a
nice [tutorial](https://try.github.io/) if you want to learn it.

Our libraries manly work on UNIX-like systems. They are not ready to be
used in Windows.

## How to collaborate

Each OTRv4 repository has their own issues. That is the first step to look into.

1. Get the source code of the repository you want to collaborate with.
2. Find your way around the source code.
3. Find an issue you want to work on. You can also find bugs and related by
   yourself!
   If this is your first collaboration, find issues which have the `first good
   issue` label.
4. Meet the team! Chat with us on the IRC channel or send us an email!
5. Propose your patch and get feedback from us!
5. Write the code: remember to follow the standards of our source code.
6. Test, test and test! Don't forget to test.
7. Submit the patch in the form of a pull request and wait for us ;)
8. Review, revise and merge. Wait for out input, change what needs to be changed
   and wait for the merge!
9. Congratz! You have your first patch merged!

Remember that you don't have to be a developer to help us. There is help needed
on protocols, documents and specifications ;)

# Expected behavior while working on OTRv4

This is inspired on Mozillas [Community Participation Guidelines](https://www.mozilla.org/en-US/about/governance/policies/participation/).

* Be respectful
* Be direct and honest
* Be inclusive: understand other peoples background
* Have a feedback culture
* Strive for a non-hierarchical work
* Have a teaching culture

Remember, that we have zero tolerance with sexism, racism or any kind of
discrimination.

## Code of Conduct

We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct)
and base our ideals on the [Citizen Code of Conduct](http://citizencodeofconduct.org/).

If you believe someone is violating the code of conduct in any way, we ask that
you report it by sending an email to conduct@otr.im . Don't hesitate to reach us.

You can always use the pseudonym `cypherpunks` to report an issue or get in
contact with us in an anonymous way.

## Reporting

If you feel that someone from the OTRv4 community has violated the Code of
Conduct or any of the expected behaviors, send an email to report@otr.im.
The email should contain:

* Names of the people involved or knowledgeable identifiers.
* Description of the incident in the form of:
  <Specific time>
  <Observed behavior>
  <Impact>
* Relationship between the reporter/reportee.

We will not question you report; but rather research around it. There is no
retaliation that can happen to you if you report. It is your right to report and
it is our right to investigate it ;)

