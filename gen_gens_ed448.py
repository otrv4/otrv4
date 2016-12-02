# -*- coding: utf-8 -*-
import hashlib
import binascii

b = 448
d = -39081
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

# Modular multiplicative inverse
def inv(x):
  return expmod(x,q-2,q)

def xrecover(y):
  xx = (1-y*y) * inv(1-d*y*y)
  x = expmod(xx, (q+1)/4, q) # x is now the candidate square root of x^2
  if (x*x - xx) % q != 0: raise Exception("no square root")
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

def decodepoint(s):
  y = sum(2**i * bit(s,i) for i in range(0,b-1))
  x = xrecover(y)
  if x & 1 != bit(s,b-1): x = q-x # select the right square root x
  P = [x,y]
  if not isoncurve(P): raise Exception("decoding point that is not on curve")
  return P

# Edward curve has identity_element as Point (0,1)
identity_element = [0,1]

def find_g(x):
    c = 0
    while True:
        ss = "%s%d" % (x, c)
        try:
            p = decodepoint(H(ss))
            g = scalarmult(p, cofactor)
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
