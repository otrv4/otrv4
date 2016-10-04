# Meeting notes for OTRv4 Brainstorming Session

These notes are in working draft state and will likely be updated over the next
week.

## Topics discussed:

We specifically talked about:

1. Network model

2. When to reveal MAC keys

3. Superencryption

### 1. Network model

We talked about the implications of having a network model that allows
out-of-order messages, which is necessary for protocols such as SMS
and Yahoo messaging. We eventually decided that the cost of a network model
with out-of-order messaging outweighed what we would gain.

We reasoned that a network model that is in order, but assumes messages can be
dropped, is preferable.

### 2. When to reveal MAC keys

We discussed whether the sender or receiver should reveal MAC keys.

The sender cannot reveal MAC keys until they have received confirmation from
the receiver that the corresponding message has been received. However, if we
permit a network model that allows dropped messages, then we cannot rely on
this confirmation from the receiver. On the other hand, we should not place
full trust in the receiver to reveal MACs after receiving a message.

Therefore, the responsibility for revealing MAC keys should be shared by both
sides. The receiver should reveal MAC keys for messages that they have
received, while the sender should reveal MAC keys for messages which the
receiver has confirmed receiving.

TODO: decide how to handle dropped messages. Do we set a time limit so we don't
have to keep key material around forever?

TODO: decide whether we should reveal one MAC per message, or reveal a head
value for which every MAC in that chain can be derived.

TODO: define what receiver confirmation of having received a message means.

### 3. Superencryption

We talked about:
  - Mixing in quantum-resistant key material during the KDF versus adding an
extra layer of encryption

We decided that mixing in key material would achieve the same outcome and is
simpler overall and is therefore preferable.

  - 3072 bit Diffie-Hellman versus New Hope

We talked about how we wanted a "belt and suspenders" for ECDH, but how PQ
crypto like SIDH is not yet ready for use.

We talked about New Hope as a good alternative, as it provides actual quantum
resistance (unlike 3072 DH).

TODO: decide concretely on 3072 bit DH or New Hope. We left this leaning
more towards New Hope.

  - Message flow

At the end of our conversation, we ended up with this:


### 4. Triple Ratchet (Adding Quantum Resistance to the Double Ratchet Algorithm)

TODO: maybe we don't need a formal name, but it might be helpful as this does
depart from the Double Ratchet Algorithm. But we can think of a better name. It
might be good to reflect in the name that this adds quantum resistance. The term
"hybrid" seems to describe what we are trying to achieve.

TODO: It would also be good to differentiate why we add this. Is it enough to
say that it will add post-quantum security, or do we also want to emphasize that
it is an extra safeguard against potential classical weaknesses in ECC?

#### 4.1 Hybrid DAKE

At the initial DAKE, we will perform both 1) an Elliptic Curve Diffie-Hellman
key agreement, and 2) a post-quantum key agreement, such as New Hope.

We want to include both, as a post-quantum key agreement will protect against a
quantum adversary that has recorded the conversation. However, as New Hope is
still relatively new, we want to protect against possible weaknesses in this
that have not yet been discovered.

The DAKE will then look something like this (assuming we are using Spawn and
New Hope):

| Alice                                   | Bob                                |
|-----------------------------------------|------------------------------------|
|                                         | send {"I"; ECDH, newHope, Auth(I)} |
| send {"R", DRE(ECDH, newHope), Auth(R)} |                                    |
| verify Auth(I)                          | verify Auth(R                      |


TODO: have clearer way of showing DRE inputs

TODO: should we be referring to this as "transitionally-secure post-quantum?"

#### 4.2 Message Ratchet (Triple Ratchet)

TODO: find a better name

The Double Ratchet Algorithm consists of a root chain, a sending chain, and a
receiving chain.

To add protection against a quantum adversary, we will need to adapt the
Double Ratchet Algorithm, adding a third ratchet which will track our
"post-quantum insurance key."

TODO: I'm not sure if we want to say "insurance key," it seems to imply that
it might not ever be useful, which is not what I think we want to convey. It
would be stronger to say "post-quantum key," "hybrid key", "New Hope key," etc.
I'm going to just use post-quantum key for the remainder of this document, but
we can think of better terminology to describe this. I personally would be in
favor of using "New Hope key."

#### 4.3 Maintaining forward secrecy

If we only negotiate a post-quantum key in the initial DAKE, this would
compromise perfect-forward secrecy for the conversation. Specifically, if
a quantum adversary capable of breaking Elliptic Curve Diffie-Hellman were to
steal our post-quantum key and record all message traffic, all messages in our
past conversation would be compromised.

Therefore, we want to shorten the window of potential compromise and limit the
lifetime of our post-quantum key. However, because of New Hope's large key size,
we have performance limitations and in most cases will not be able to re-negotiate
a new key on every message that is sent.

Instead, we can re-negotiate the post-quantum key based on several possible
parameters, such as:

1. a fixed value,

2. randomly choosing a value between two bounds, or

3. dynamically setting this value based on a variable value, such as network
conditions

In short, we can re-negotiate our post-quantum key every *n* messages, where n
can be decided by a fixed or variable value.


#### 4.4 Triple Ratchet Algorithm

This scheme would look something like this, if n=2 (meaning we ratchet our
post-quantum key after every two messages exchanged):

                  Sending | Root key ratchet | Receiving  |   Post-Quantum key ratchet

                   MK  CK |         RK       | CK   MK    |            PQK

                      KDF(ECDH(A0,B0), newHope0)                    newHope0
                                    |                                   |
                                    |                                   |
    KDF(ECDH(A1,B0), RK, newHope0)  +                                   |
                                   /|                                   |
                                  / |                                   |
                                 /  + KDF(ECDH(A1,B1), RK, newHope1)    + newHope1
                         CK-A1-B0   |\                                  |
                             |      | \                                 |
                    MK-0 ----+      |  \                                |
                             |      |   CK-A1-B1                        |
                    MK-1 ----+      |       |                           |
                             |      |       +---- MK-0                  |
                    MK-2 ----+      |       |                           |
                                    |       +---- MK-1                  |
    KDF(ECDH(A2,B1), RK, newHope1)  +                                   |
                                   /|                                   |
                                  / |                                   |
                                 /  |                                   |
                         CK-A2-B1   |                                   |
                             |      + KDF(ECDH(A2,B2), RK, newHope2)    + newHope2
                    MK-0 ----+       \                                  |
                                      \                                 |
                                       \                                |
                                        CK-A2-B2                        |
                                            |                           |
                                            +---- MK-0                  |
                                            |                           |
                                            +---- MK-1                  |

(adapted from original documentation at [1])

TODO: verify when New Hope keys get mixed in & ratcheted

TODO: How do we re-derive the New Hope key when we are not re-negotiating on the
nth message? And why?


#### 4.5 Deriving Root Keys

Adding a post-quantum ratchet means that we will need to change how
root keys are derived, Rather than only deriving root keys from current ECDH
ephemeral keys, root keys will be derived from these values as well as our
post-quantum key.

```
RK-1 = KDF(An-Bn, RK-0, PQK-0)
```

#### 4.6 Deriving post-quantum keys

When we are not re-negotiating a new post-quantum key, post-quantum
keys will be derived on every message using a KDF:

```
PQK-1 = KDF(PQK-0)
```

TODO: verify this, also explain why this would be necessary

### 5. Message Format

When we are re-negotiating the post-quantum key, our message format will look
like:

    struct {
      sender_ecdh_ephemeral
      sender_pqk
      body
      mac
      old mac keys
    }

Otherwise, message formats will look like this:

    struct {
      sender_ecdh_ephemeral
      body
      mac
      old mac keys
    }

TODO: Add other message parts here (header, etc)

### 6. Further considerations

We talked about but need to investigate further:
  - How to differentiate adding a new device versus an adversary resetting a
session. One idea is to do key continuity.

### Acknowledgements

Thanks to those who were there & helped thinking this through!

TODO: It would be nice to give credit to specific people. Confirm who is
comfortable having their names here.

### References

1. https://whispersystems.org/blog/advanced-ratcheting/


