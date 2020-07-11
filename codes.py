import itertools
from functools import reduce
import operator
import math
from reedsolo import RSCodec, ReedSolomonError

def _matrix_multiply(a, b, mod=None):
    assert len(a[0]) == len(b)

    r = []

    for x in range(len(a)):
        row = []
        for y in range(len(b[0])):
            if mod:
                row.append(sum([a[x][z]*b[z][y] for z in range(len(b))]) % mod)
            else:
                row.append(sum([a[x][z]*b[z][y] for z in range(len(b))]))
        r.append(row)

    return r

# apply an and mask to a vector over GF(2)

def _bitwise_and(a,b):
    r = []

    for x in range(len(a)):
        r.append((a[x] * b[x%len(b)]) % 2)

    return r

# inductively apply an and mask to multiple vectors

def _bitwise_and_inductive(l):
    r = l[0]
    for x in range(1, len(l)):
        r = _bitwise_and(r, l[x])
    return r

def _binary_matrix_vector_multiply(v,m):
    return _matrix_multiply([v], m, 2)[0]
def _matrix_vector_multiply(v,m):
    return _matrix_multiply([v], m)[0]

def _bitvector_to_byte(b):
    return int(''.join([str(n) for n in b]), 2).to_bytes(len(b)//8, 'big')
def _byte_to_bitvector(b):
    return [int(c) for c in '{0:08b}'.format(b)]

class ReedMuller:
    def __init__(self, mult=1):
        # fix 1,7 as r,m
        self.r, self.m, self.mult = 1, 7, mult
        self.g = self._make_generator()
        self.n = self.mult * pow(2, self.m)
        self.HM = self._hadamard(self.m)

    # produces the generator matrix for the kth-order
    # hadamard code - this forms rows 1-m of the Reed-Muller
    # generator matrix
    
    def _hadamard_g(self, k):
        r = []

        for x in range(k):
            r.append([(math.floor(y/(2**x)))%2 for y in range(2**k)])

        r.reverse()
        
        return r

    # give all choices of length l from a set s
    
    def _get_idxs(self, s, c, l):
        return list(itertools.combinations(s, l))

    # builds the generator matrix

    def _make_generator(self):
        # get the hadamard matrix
        base_vs = self._hadamard_g(self.m)

        # add the top row of all 1s to this
        vs = [[1] * (2**self.m)] + base_vs

        # compute the wedge product of all possible combinations of the original
        # m vectors up to order r - where order is the number of original vectors
        # wedge-multiplied together - and append these rows to the matrix
        for l in range(2, self.r + 1):
            idxs = self._get_idxs(list(range(1, 1 + self.m)), [], l)
            for idx in idxs:
                vs.append(_bitwise_and_inductive([vs[i] for i in idx]))
        return vs
    
    def _bytewise_encode(self, b):
        return _bitvector_to_byte(_binary_matrix_vector_multiply(_byte_to_bitvector(b), self.g))
    
    def encode(self, msg):
        output = b''
        for c in msg:
            r = self._bytewise_encode(c) * self.mult
            output += r
        return output

    def _hadamardify(self, m):
        return [[m[y%len(m)][x%len(m[0])] * ( (-1) ** (x >= len(m[0]) and y >= len(m))) for x in range(len(m[0]) * 2)] for y in range(len(m) * 2)]
    
    def _hadamard(self, o, start=[[1]]):
        if o <= 0:
            return start
        return self._hadamard(o - 1, self._hadamardify(start))

    def _green_machine(self, cw):
        transformed = _matrix_vector_multiply(cw, self.HM)
        transformed[0] -= 64 * self.mult

        peak_abs, peak_val, peak_pos = 0,0,0
        for i in range(self.n//self.mult):
            t = transformed[i]
            ab = abs(t)
            if ab > peak_abs:
                peak_abs, peak_val, peak_pos = ab, t, i
        
        peak_pos |= 128 * (peak_val > 0)
        return peak_pos

    
    def decode(self, rcv):
        cwlen = self.n//8
        rda = [rcv[i:i+cwlen] for i in range(0, len(rcv), cwlen)]
        final = b''
        for r in rda:
            bvs = [[int(c) for c in '{0:0128b}'.format(int.from_bytes(r[i:i+(128//8)], 'big'))] for i in range(0, cwlen, 128//8)]
            cwbv = [sum([bvs[j][i] for j in range(self.mult)]) for i in range(128)]
            final += bytes([self._green_machine(cwbv)])
        
        return final

class PublicCode:
    def __init__(self):
        self.n = 78 * 768
        self.inner_code = RSCodec(78 - 32)
        self.outer_code = ReedMuller(6)
    
    def encode(self, msg):
        return self.outer_code.encode(self.inner_code.encode(msg))
    
    def decode(self, msg):
        return self.inner_code.decode(self.outer_code.decode(msg))