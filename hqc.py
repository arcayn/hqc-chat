from codes import PublicCode
from Crypto.Hash import SHA3_256, SHA3_512, SHA512, HMAC
from Crypto.Cipher import AES
import secrets
import math

class DRBG(object):
    def __init__(self, seed):
        self.key = b'\x00' * 64
        self.val = b'\x01' * 64
        self.reseed(seed)

    def hmac(self, key, val):
        hm = HMAC.new(key, digestmod=SHA512)
        hm.update(val)
        return hm.digest()

    def reseed(self, data=b''):
        self.key = self.hmac(self.key, self.val + b'\x00' + data)
        self.val = self.hmac(self.key, self.val)

        if data:
            self.key = self.hmac(self.key, self.val + b'\x01' + data)
            self.val = self.hmac(self.key, self.val)

    def generate(self, n):
        xs = b''
        while len(xs) < n:
            self.val = self.hmac(self.key, self.val)
            xs += self.val

        self.reseed()

        return xs[:n]

class HQC:
    def __init__(self):
        self.omega = 133
        self.omega_e, self.omega_r = 153,153
        self.n = 59957
        self.n1n2 = 78 * 768
        self.n_bytes = (self.n//8) + 1
        self.n_random_bits = math.ceil(math.log(self.n, 2))
        self.n_random_bytes = math.ceil(self.n_random_bits/8)
        self.n_random_discard = (self.n_random_bytes * 8) - self.n_random_bits
        self.code = PublicCode()
    
    def _errorfy(self, v, n, random_source):
        ret = 0
        while n > 0:
            idx = v
            while idx > v - 1:
                idx = int.from_bytes(random_source.generate(math.ceil(self.n_random_bits/8)), 'big') >> self.n_random_discard
            if (ret >> idx) & 1 == 0:
                ret ^= 1 << idx
                n -= 1
        return ret

    def _convolute(self, b, a):
        out, i, l = 0, 1, self.n
        while a > 0:
            if a & 1:
                out ^= ((b & ((1 << (l - i)) - 1)) << i) | (b >> (l - i))
            a >>= 1
            i += 1
        return out

    def keygen(self):
        self.h = secrets.randbits(self.n)
        random_source = DRBG(secrets.randbits(2048).to_bytes(256, 'big'))
        random_source.generate(256)
        self.x = self._errorfy(self.n, self.omega, random_source)
        self.y = self._errorfy(self.n, self.omega, random_source)
        
        self.s = self.x ^ self._convolute(self.h, self.y)
    
    def get_private_key(self):
        return self.x.to_bytes(self.n_bytes, 'big'), self.y.to_bytes(self.n_bytes, 'big')
    
    def get_public_key(self):
        return self.h.to_bytes(self.n_bytes, 'big'), self.s.to_bytes(self.n_bytes, 'big')
    
    def set_public_key(self, h, s):
        self.h, self.s = int.from_bytes(h, 'big'), int.from_bytes(s, 'big')
    
    def set_private_key(self, x, y):
        self.x, self.y = int.from_bytes(x, 'big'), int.from_bytes(y, 'big')
    
    def encrypt(self, m, theta):
        random_source = DRBG(theta)
        random_source.generate(256)
        e = self._errorfy(self.n, self.omega_e, random_source)
        r1 = self._errorfy(self.n, self.omega_r, random_source)
        r2 = self._errorfy(self.n, self.omega_r, random_source)

        u = r1 ^ self._convolute(self.h, r2)
        codeword = int.from_bytes(self.code.encode(m), 'big')

        sr2 = self._convolute(self.s, r2)
        v = codeword ^ sr2 ^ e

        return u.to_bytes(self.n_bytes, 'big'), v.to_bytes(self.n_bytes, 'big')
    
    def decrypt(self, u, v):
        codeword = ((int.from_bytes(v, 'big') ^ self._convolute(int.from_bytes(u, 'big'), self.y)) & ((1 << self.n1n2) - 1)).to_bytes(self.n1n2//8, 'big')
        return self.code.decode(codeword)[0]
    
    def encapsulate(self):
        m = secrets.randbits(256).to_bytes(32, 'big')
        G = SHA3_512.new()
        G.update(m)
        theta = G.digest()

        u,v = self.encrypt(m, theta)
        K_generator = SHA3_512.new()
        K_generator.update(m + u + v)
        K = K_generator.digest()

        d_generator = SHA512.new()
        d_generator.update(m)
        d = d_generator.digest()

        return K, u, v, d
    
    def decapsulate(self, u, v, d):
        mbar = self.decrypt(u, v)
        
        G = SHA3_512.new()
        G.update(mbar)
        thetabar = G.digest()

        ubar, vbar = self.encrypt(mbar, thetabar)

        assert ubar == u and vbar == v

        d_generator = SHA512.new()
        d_generator.update(mbar)
        dbar = d_generator.digest()

        assert dbar == d

        K_generator = SHA3_512.new()
        K_generator.update(mbar + u + v)
        K = K_generator.digest()

        return K

