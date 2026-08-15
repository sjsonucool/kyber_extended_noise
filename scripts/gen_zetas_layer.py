#!/usr/bin/env python3
"""
Generate Kyber-style zetas in layer-consumption order for the custom modulus.
Pattern:
  tmp[0] = MONT
  tmp[i] = mont_reduce(tmp[i-1] * (MONT*ROOT % q))
  zetas_tree[i] = tmp[tree[i]]
Then reorder to the forward DIF consumption order (k starts at 1, len=128).
ROOT must be a primitive 256-th root with ROOT^128 = -1 (mod q).
"""

Q = 18446744073709550593  # modulus
R = 1 << 64
QINV = 17292695568609442815      # -q^{-1} mod 2^64
ROOT = 12400524647368804660  # primitive 256-th root, ROOT^128 = -1 mod q

TREE = [
    0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120,
    4, 68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124,
    2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122,
    6, 70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126,
    1, 65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121,
    5, 69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125,
    3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123,
    7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127,
]


def montgomery_reduce(a: int) -> int:
    a_lo = a & (R - 1)
    a_hi = a >> 64
    t = (a_lo * QINV) & (R - 1)
    mq = t * Q
    mq_lo = mq & (R - 1)
    mq_hi = mq >> 64
    sum_hi = a_hi + mq_hi + ((a_lo + mq_lo) >> 64)
    if sum_hi >= Q:
        sum_hi -= Q
    return sum_hi


def gen_zetas():
    tmp = [0] * 128
    mont = R % Q
    tmp[0] = mont  # MONT
    root_mont = (mont * ROOT) % Q  # MONT * ROOT
    for i in range(1, 128):
        tmp[i] = montgomery_reduce(tmp[i - 1] * root_mont)
    zetas_tree = [tmp[idx] % Q for idx in TREE]
    # Build layer order for forward DIF: len starts 128, k starts at 1
    zetas_layer = [zetas_tree[0]]  # keep zetas[0] so table has 128 entries
    k = 1
    length = 128
    while length >= 2:
        for _ in range(0, 256, 2 * length):
            zetas_layer.append(zetas_tree[k])
            k += 1
        length //= 2
    return zetas_layer


def main():
    zetas = gen_zetas()
    with open("src/reference/zetas_new.rs", "w") as f:
        f.write("pub const ZETAS: [i128; 128] = [\n")
        for z in zetas:
            f.write(f"    {z}i128,\n")
        f.write("];\n")
    print(f"wrote {len(zetas)} entries to src/reference/zetas_new.rs")


if __name__ == "__main__":
    main()
