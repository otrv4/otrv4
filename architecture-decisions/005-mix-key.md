## ADR 5: Mix Keys

### Context

Because of potential weaknesses in elliptic curves and the potential of quantum
computers arriving earlier than predicted, we want an additional mechanism that
would protect against post-conversation decryption of transcripts using those
weaknesses.

We believe this can be achieved by mixing another key obtained from a
Diffie-Hellman exchange into the key material. This additional key will be
referred to as “mix key”.

This proposal specifies:

1. Adding an extra key to mix in with the ECDH key when deriving a new
root key.
2. An algorithm for ratcheting and deriving this mix key.

This proposal does not change the Double Ratchet algorithm with the
exception of how to derive root keys.

The first 3072-bit DH key agreement takes place in the DAKE.  See Nik Unger's
paper[1], which specifies Transitionally Secure Spawn. The difference to this
entry in the paper is that we are trying to protect against elliptic curve
weaknesses, and SIDH[2] is specific for postquantum resistance. So this will
instead use a classic Diffie Hellman key exchange.

The options for ratcheting/re-deriving this mix key are:

1. Obtain every mix key from a DH function which requires the other party to
contribute to the computation.
2. Obtain a mix key with DH functions which requires the other party to
contribute to the computation every n times. Between these derivations,
the mix keys are obtained using a KDF that is seeded with the last DH
key. We propose n = 3, but this can be adjusted depending on performance.

### Algorithm

*k_dh = A_i, a_i*

A mix key is a key that is added to the key derivation function used
to produce new root and chains keys. A mix key can be produced through
a DH function and through a key derivation function, both of which
produce a 3072-bit public key. This key has a 128 bit security level
according to Table 2: Comparable strengths in NIST’s Recommendation for Key
Management, page 53
(http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf).

*generateDH function - generateDH()*

Generates a `A_i` and a `a_i`.

*DH function - DH(a_i, B_i)*

Given `a_i`, a private key, and `B_i`, a public key, generates a shared secret value: `k_dh`.

*Key Derivation Function - SHA3-256(k_dh)*

Given `k_dh`, generates a 256 bit SHA3-256 algorithm. This is used
even when a DH shared secret is calculated (reducing it to 256 bits) because we
want to keep this value with a constant size. This generates the value `mix_key`.

#### Considerations

Transmitting the 3072-bit DH public key will increase the time to
exchange messages. To mitigate this, the key won’t be transmitted every
time the root and chain keys are changed. Instead, this key will be
computed with a DH function every third time and the interim keys will
be derived from previous `mix_key`. When generating new DH keys, the
public key will be sent in every message of that ratchet.

The mix key is to be mixed in at the root level with the ECDH key.

#### Implementation

Alice's DH keypair = `(a_i, A_i)`

Bob's DH keypair = `(b_i, B_i)`

`mix_key` = it will be referred as `M_i` for ease.

Every root key derivation requires both an ECDH key and a mix key. For
the purposes of this explanation, we will only discuss the mix key.

n is the number of root key derivations before performing a new DH
computation. The interim root key derivations will use a mix key
derived from a KDF using previous mix key as the seed.

_When n is configured to equal 3_
```
Alice                                                              Bob
-----------------------------------------------------------------------------------------------------------------------
Increases ratchet_id by one
Derives a new mix key from the one obtained in DAKE
    M_1 = pubDHa, secDHa = KDF(M_0)
Mixes M_1 into the KDF to generate root and chain keys
    R_1, Cs_0_1, Cr_0_1 = KDF(R_0, ECDH_1 || M_1)
Encrypts data message with Cs_0_1
Sends data_message_0_0 ----------------------------------------->
Encrypts data message with key derived from Cs_0_1
Sends data_message_0_1 ----------------------------------------->
                                                                   Derives a new mix key from the one obtained in DAKE
                                                                       M_1 = pubDHa, secDHa = KDF(M_0)
                                                                   Mixes DH_1 into the KDF to generate root and chain keys
                                                                       R_1, Cs_0_1, Cr_0_1 = KDF(pubECDHa, secECDHa || secDHa)
                                                                   Decrypts received message(s) with Cs_0_1
                                                                   Derives a new mix key from the one obtained in DAKE
                                                                       M_2 = pubDHa, secDHa = KDF(M_1)
                                                                   Mixes DH_2 into the KDF to generate root and chain keys
                                                                       R_1, Cs_1_0, Cr_1_0 = KDF(pubECDHa, secECDHa || secDHa)
                                                                   Encrypts data message with Cr_1_0
                       <----------------------------------------   Sends data_message_1_0
                                                                   Encrypts data message with key derived from Cr_1_0
                       <----------------------------------------   Sends data_message_1_1
```

**Alice or Bob sends the first message in a ratchet (a first reply)**

The ratchet identifier ratchet_id increases every time a greater
ratchet_id is received or a new message is being sent and signals
the machine to ratchet i.e. `ratchet_id += 1`

If `ratchet_id % 3 == 0 && sending the first message of a new ratchet`

  * Compute the new mix key from a new DH computation e.g. `M_i =
        SHA3-256(DH(our_DH.secret, their_DH.public))`
  * Send the new `mix_key`'s public key to the other party for further key computation.

Otherwise

  * Compute the new mix key `M_i = SHA3-256(M_(i-1))`

**Alice or Bob send a follow-up message**

When a new public key has been generated and sent in the first message
in a ratchet, all follow up messages in that ratchet will also need
the public key to ensure that the other party receives it.

If `ratchet_id % 6 == 3 || ratchet_id % 6 == 0`

   * Send public key

**Alice or Bob receive the first message in a ratchet**

The ratchet_id will need to be increased, so `ratchet_id += 1`

If `ratchet_id % 6 == 3 || ratchet_id % 6 == 0`

   * A new public key should be attached to the message. If it is not,
    reject the message.

Otherwise:

   * Compute the new mix key from a new DH computation e.g.
        `M_i = SHA3-256(DH(our_DH.secret, their_DH.public))`
   * Use `M_i` to decrypt the received message.

**Alice or Bob receive a follow up message**

If the ratchet_id is not greater than the current state of ratchet_id,
then this is not a new ratchet. In this case there is no further
action to be taken for the mix key.

**Diagram: Pattern of DH computations and key derivations in a conversation**

This diagram describes when public keys should be sent and when Alice
and Bob should compute the `mix_key` from a SHA3 or a new Diffie Hellman
computation.

Both parties share knowledge of `M_0`, which is a `mix_key` established in
the DAKE.

Given

    Alice's DH keypair = (a_i, A_i)
    Bob's DH keypair = (b_i, B_i)

If Alice sends the first message:

```
    Alice                 ratchet_id        public_key           Bob
---------------------------------------------------------------------------------------

M_1 = SHA3(M_0)            -----1----------------------->     M_1 = SHA3(M_0)
M_2 = SHA3(M_1)            <----2------------------------     M_2 = SHA3(M_1)
M_3 = SHA3(DH(a_1, B_0))   -----3--------------A_1------>     M_3 = SHA3(DH(b_0, A_1))
M_4 = SHA3(M_3)            <----4------------------------     M_4 = SHA3(M_3)
M_5 = SHA3(M_4)            -----5----------------------->     M_5 = SHA3(M_4)
M_6 = SHA3(DH(a_1, B_1))   <----6--------------B_1-------     M_6 = SHA3(DH(b_1, A_1))
M_7 = SHA3(M_6)            -----7----------------------->     M_7 = SHA3(M_6)
M_8 = SHA3(M_7)            <----8------------------------     M_8 = SHA3(M_7)
M_9 = SHA3(DH(a_2, B_1))   -----9--------------A_2------>     M_9 = SHA3(DH(b_1, A_2))
```

### Performance

Computation of g^a, g^b and g^a^b takes under a second using generator
g = 2 and exponents a and b are 3072 bits long in an “Intel Core i7
2.2GHz”

| Operation           | Repeat times | Time per Operation |
| ------------------- | ------------ | ------------------ |
| ComputeSharedSecret | 2000         | 22.198064 ms/op    |
| KeyGeneration       | 1000         | 31.607442 ms/op    |

### Decision

We’ve decide to use a 3072-bit key produced by

1. a DH function which takes as argument the other party’s exponent
   through a data message and produces a mix key.
2. a KDF (SHA3-256) function which takes as argument the previous mix key to
   produce a new one.

The DH function will run every n = 3 times because of the following reasons:

1. It is a small number so a particular key can only be compromised
   for a maximum of 2\*n ratchets. This means that the maximum ratchets
   that will use the mix key or a key derived from the mix key is 6.
2. The benefit of using an odd number is for simplicity of
   implementation. With an odd number, both Alice and Bob can generate
   a new public and secret key at the same time as sending the public
   key and compute a new mix key from a DH function. However, with an
   even number, Alice would need to generate and send a key in a
   different ratchet to the one where the public key would be
   used. This happens because the public key would only be used in a
   mix key computed from a new DH function on even numbers of
   ratchet_ids so only Bob would be the sender at these times.

From the IETF paper, RFC 3526[4]:

* Prime is: 2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }
* Hex value:
  ```
  FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
  29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
  EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
  E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
  EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
  C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
  83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
  670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
  E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
  DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
  15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
  ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
  ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
  F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
  BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
  43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
  ```
* Generator g3: 2
* The public keys should be 448-bit (56 bytes) long.

### Consequences

Using a 3072 DH function to produce the mix key extends data messages
size in 56 bytes of extra key material that may cause some transport
protocols to fragment these messages.

[1](http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf)
[2](https://eprint.iacr.org/2011/506.pdf)
[3](https://whispersystems.org/blog/advanced-ratcheting/)
[4](https://www.ietf.org/rfc/rfc3526.txt)
