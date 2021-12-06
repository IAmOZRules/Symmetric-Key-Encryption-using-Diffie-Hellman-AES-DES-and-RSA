import random
import hashlib

class RSA(object):
    def __init__(self, generator=2, keylength=620):
        # Generate the public and private keys.

        self.generator = generator
        self.keyLength = keylength

        self.p, self.q = generateprime()
        self.public, self.private = generatekey(self.p, self.q)
        self.A = self.public
        self.B = self.private
        self.g = random.randint(50, 500)
        self.r, self.m = generateprime()

# function to find extended gcd
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


# function to find modular inverse
def inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return None
    else:
        return x % m


def generateprime():
    count = 0
    while count < 1:
        p = random.randint(50, 500)
        if is_probable_prime(p):
            count += 1
    while count < 2:
        q = random.randint(50, 500)
        if is_probable_prime(q):
            if q != p:
                count += 1
    return p, q


_mrpt_num_trials = 5  # number of bases to test


def is_probable_prime(n):
    assert n >= 2
    # special case 2
    if n == 2:
        return True
    # ensure n is odd
    if n % 2 == 0:
        return False
    # write n-1 as 2**s * d
    # repeatedly try to divide n-1 by 2
    s = 0
    d = n - 1
    while True:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient
    assert (2 ** s * d == n - 1)

    # test the base a to see whether it is a witness for the compositeness of n
    def try_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2 ** i * d, n) == n - 1:
                return False
        return True  # n is definitely composite

    for i in range(_mrpt_num_trials):
        a = random.randrange(2, n)
        if try_composite(a):
            return False

    return True  # no base tested showed n as composite


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def generatekey(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    g = 10
    while (g != 1):
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = inverse(e, phi)

    return (e, d)


def xor(s1, s2):
    return "".join([chr(ord(c1) ^ ord(c2)) for (c1, c2) in zip(s1, s2)])


def crypter(key, string):
    string = [c ^ key for c in asciiString]
    return string


def hybrid(message):
    p, q = generateprime()
    print(p, q)
    public, private = generatekey(p, q)
    A = public
    B = private
    print("public key:", public, "private key:", private)
    g = random.randint(50, 500)
    r, m = generateprime()
    print("shared prime ", r, "shared base ", g)
    X = (g ** A) % r
    Y = (g ** B) % r
    print("Alice sends", X, "Bob sends", Y)

    K1 = pow(Y, A, r)
    K2 = pow(X, B, r)
    Key1 = hashlib.sha256(str(K1).encode('utf-8')).hexdigest()
    Key2 = hashlib.sha256(str(K2).encode('utf-8')).hexdigest()

    print("Key I: ", Key1)
    print("Key II: ", Key2)

    ciphertext = xor(message, Key1)
    print("Cipher Text ", ciphertext)
    messagetext = xor(ciphertext, Key2)
    print("Message Text ", messagetext)

    return A,B,r,X,Y,Key1,Key2,ciphertext,messagetext
