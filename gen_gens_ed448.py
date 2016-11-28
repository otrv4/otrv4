# -*- coding: utf-8 -*-
import hashlib
import binascii

b = 448
q = 2**448 - 2**224 - 1
l = 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
cofactor = 4

def H(m):
  return hashlib.sha512(m).digest()

def expmod(b,e,m):
  if e == 0: return 1
  t = expmod(b,e/2,m)**2 % m
  if e & 1: t = (t*b) % m
  return t

def inv(x):
  return expmod(x,q-2,q) # Why q-2?

# The d was for the twisted edwards 25519
d = -39081
I = expmod(2, (q-1)/4, q) # I = 2 ** (q-1)/4 mod q # Why 4?

def xrecover(y):
  xx = (1-y*y) * inv(1-d*y*y)
  x = expmod(xx, (q+3)/cofactor, q) # Whya was it 8? cofactor?
  if (x*x - xx) % q != 0: x = (x*I) % q
  if x % 2 != 0: x = q-x
  return x

# point addition
def edwards(P,Q):
  x1 = P[0]
  y1 = P[1]
  x2 = Q[0]
  y2 = Q[1]
  x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
  y3 = (y1*y2-x1*x2) * inv(1-d*x1*x2*y1*y2)
  return [x3 % q, y3 % q]

def scalarmult(P,e):
  if e == 0: return [0,1]
  Q = scalarmult(P,e/2)
  Q = edwards(Q,Q)
  if e & 1: Q = edwards(Q,P)
  return Q

def bit(h,i):
  return (ord(h[i/8]) >> (i%8)) & 1

# this is the formula for the twisted curve
def isoncurve(P):
  x = P[0]
  y = P[1]
  return (x*x + y*y - 1 - d*x*x*y*y) % q == 0

# similar to decodeLittleEndian from X25519, but works on bits rather than bytes
def decodeint(s):
  return sum(2**i * bit(s,i) for i in range(0,b))

# Is this the same as decodeUCoordinate from X25519?
def decodepoint(s):
  y = sum(2**i * bit(s,i) for i in range(0,b-1))
  x = xrecover(y)
  if x & 1 != bit(s,b-1): x = q-x
  P = [x,y]
  if not isoncurve(P): raise Exception("decoding point that is not on curve")
  return P

# Where does this second part comes from?
identity_element = [0,1]

def find_g(x):
    c = 0
    while True:
        ss = "%s%d" % (x, c)
        try:
            p = decodepoint(H(ss))
            g = scalarmult(p, cofactor) # why 8?
            is_id = scalarmult(g, l)
            if is_id == identity_element: # IF P^cofactor^primeOrder == [0, 1]
                return g, ss
        except Exception as e:
            pass
        c = c+1

generator1_x = "OTRv4 g1"
generator2_x = "OTRv4 g2"

g1, sg1 = find_g(generator1_x)
print("g1")
print("x = " + format(g1[0], '#04x'))
print("y = " + format(g1[1], '#04x'))
print("sg1 = " + sg1)

g2, sg2 = find_g(generator2_x)
print("g2")
print("x = " + format(g2[0], '#04x'))
print("y = " + format(g2[1], '#04x'))
print("sg2 = " + sg2)
