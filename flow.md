# Flow of the conversation

## Interactive conversation

_Alice and Bob are honest_

### Setup:
Long term keys:

Bob: PKb, SKb := `GenCSKeyPair(g1)`

Alice: PKa, SKa := `GenCSKeyPair(g2)`

[](
[INSERT HERE DOWNGRADE ATTACK PROTECTION]
)

Alice starts conversation

`REQUEST_MESSAGE {
"?OTRv34?Bob I need to talk to you. In private."
}`

Bob starts the authenticated key exchange
ψ1 := ("I", g1^i)
[COMPUTE HERE DH-2048 KEY]

DH_COMMIT {
message : ψ1
selectedVersion: "?OTRv4?"
}

Alice completes the authenticated key exchange
γ := DREnc(PKa, PKb, "I" || "R" || g1^i || g1^r)
σ := Auth(Ai, ai, {S}, "I"||"R"|| g1^i ||γ || "?OTRv4?") where Ai, ai, and {S} are part of CS PK and SK.
ψ2 := ("R", γ, σ)
k := (g^i)^r
[COMPUTE HERE DH-2048 KEY]
[COMPUTE HERE k := KDF(k, DH-2048key)]

DH_MESSAGE {
message: ψ2
}

Bob verifies the authenticated key exchange and decrypts γ
Verify(σ)
k := (g^r)^i
[COMPUTE HERE k := KDF(k, DH-2048key)]

Alice and Bob initialize keys

State:
s: sender
r: responder
Rk: root key
Ck: chain keys
DHR: DH or ECDH ratchet keys
N: message counter
B1: Bob's initial ratchet key
Mk: message key

// TO DO: Correct this to the correct flow

Initialization:
Alice
Rk_1, Cks<none>, Ckr := KDF(k)
B1
Ns, Nr = 0, 0
pubDH_a, privDH_a := GenDH()
iAmSender := pubDHa > pubDHb

Bob
Rk_1, Cks, Ckr<none> := KDF(k)
Ns, Nr = 0, 0
B1 := pubDH_b, privDH_b := GenDH()
iAmSender := pubDHa > pubDHb

Exchange of messages

Alice sends message (s)
DHRs(pubDH_a, privDH_a), DHRr<B1>(pubDH_b)
Mk_1 := HMAC(CKs_1, "0")
c1 := Enc(Mk_1, p_1)
Ns = Ns + 1
Cks_2 = HMAC(Cks_1, "1")

DATA_MESSAGE {
message: c1
pk: pubDH_a
}

Alice sends a second message (in the same ratchet)
Mk_2 := HMAC(CKs_2, "0") // Ask about the KDF function, add MAC. 
c2 := Enc(Mk_2, p_2)
Ns = Ns + 1
Cks_3 = HMAC(Cks_2, "1")

DATA_MESSAGE {
message: c2
pk: pubDH_a
}

Bob reads messages (r)
Mk_1 := KDF(Ckr_1, "0") // Ask about the function
macP1 := get mac(Mk_1) // Rosalie
Verify(c1, macP1)
p1 := Dec(Mk_1, c1)
Ckr_1 = HMAC(Ckr_2, "1")

Bob sends heartbeat
DATA_MESSAGE {
message: macP1
}

Bob reads messages (r)
Mk_2 := KDF(Ckr_2, "0")
macP2 := get mac(Mk_2) // Rosalie
Verify(c2, macP2)
p2 := Dec(Mk_2, c2)

Bob sends heartbeat

DATA_MESSAGE {
message: macP2
}

Bob responses (new ratchet)
pubDHb, privDHb := genECDH() // Ask about the function
Rk_2, Cks := KDF(HMAC(Rk_1, privDHb, pubDHa)
Ns, Nr = 0, 0

// bis message sending pletora
