from sage.all import *
import numpy as np
import argparse
import math

# Default values in argparse is for dilithium
parser = argparse.ArgumentParser()
parser.add_argument('-q', dest='q', type=int, help='Modulus q', default=8380417)
parser.add_argument('-zeta', dest='zeta', type=int, help='2nth root of unity', default=1753)
parser.add_argument('-mont', dest='mont', type=int, help='Montgomery form scalar', default=32)
parser.add_argument('-n', dest='n', type=int, help='polynomial dimension', default=256)
parser.add_argument('-skip0', dest='skip0', type=bool, action=argparse.BooleanOptionalAction, help='insert 0 into zetas[0] and skip computation for i=0', default=True)
args = parser.parse_args()


def find_prime_of_size(size, n, p=None):
    if p is not None:
        p = next_prime(p)
    else:
        p = next_prime(2**size)
    while not p % (2*n) == 1 or gcd(p-1, 2*n) == 1:
        p = next_prime(p)
    return p


def bit_reverse(n, bit_length):
    s = bin(n)[2:].zfill(bit_length)
    s_reversed = s[::-1]
    return int(s_reversed, 2)

def print_c_array(name, data, size, per_line=8):
    print(f"static const char *const {name}[{size}] = {{")
    for i in range(0, len(data), per_line):
        chunk = data[i:i+per_line]
        chunk_str = ", ".join(f'"{x}"' for x in chunk)
        if i+per_line < len(data):
            print(f"\t{chunk_str},")
        else:
            print(f"\t{chunk_str}")
    print("};")

def compute_zetas(q, zeta, mont, n):
    bsize = int(np.log2(n))

    zetas = [(zeta**bit_reverse(i, bsize)) % q for i in range(1 if args.skip0 else 0,n)]
    zetas = [z*mont % q for z in zetas]
    zetas = [z if z < (q-1)/2 else z-q for z in zetas]
    if args.skip0:
        zetas.insert(0, 0)
    return zetas

def print_zetas(zetas):
    print_c_array("zetas_str", zetas, "N", 8)
    

def primitive_2nth_root(p, n):
    F = GF(p)
    w = F(-1)
    iterations = int(np.log2(n))
    for _ in range(iterations):
        w = F(sqrt(w, p))
    q = pow(w, n, p)
    if q == p - 1:
        return w

    return None

def print_c_format_params_and_consts(q, n, zeta, omont, small_q):
    qinv = inverse_mod(q, omont)
    qinv = qinv if qinv < omont//2 else qinv - omont
    mont = omont % q
    mont = mont if mont < q//2 else mont - q
    div = Integer((omont**2)//n % q)
    div = div if div < q//2 else div - q
    div_qinv = (div * qinv) % omont
    div_qinv = div_qinv if div_qinv < omont//2 else div_qinv - omont
    mont_bits = int(math.log2(omont))
    print(f'#define N {n}')
    print(f'#define MONT_BITS {mont_bits}')
    print(f'#define q {small_q}')
    print() # Extra for space
    print(f'#define Q "{q}"')
    print(f'#define QINV "{qinv}"')
    print(f'#define DIV "{div}"')
    print(f'#define MONT "{mont}"')
    print(f'#define DIV_QINV "{div_qinv}"')
    print(f'#define ROOT_OF_UNITY "{zeta}"')

if __name__ == "__main__":
    n = 256
    mont = 128
    small_q = 81623040078337
    q = 23473657271235664258052971185590273
    zeta = primitive_2nth_root(q, n)
    zeta = int(zeta)
    print_zetas(compute_zetas(q, zeta, 2**mont, n))
    print_c_format_params_and_consts(q, n, zeta, 2**mont, small_q) # For optimization for avx2

