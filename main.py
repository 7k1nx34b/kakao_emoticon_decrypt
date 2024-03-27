import numpy as np

'''
// attributes: thunk
__int64 __fastcall decryptData(int a1, int a2, void *a3, size_t a4)
{
    return cryptData(a1, a2, a3, a4);
}

a3 # a271730728cbe141e47fd9d677e9006d 고정된 복호화 키 (void *src)
a4 # key size len(), (size_t n)


// attributes: thunk
__int64 __fastcall generateLFSR(void *src, size_t n)
{
    return generateLFSR(src, n);
} #
-----------------------
void *__fastcall generateLFSR(void *src, signed int n, pWORD *a3, pWORD *a4, pWORD *a5)
의

  *a3 = 301989938LL;
  *a4 = 623357073LL;
  *a5 = 2290881044LL; 상수 값 (__int64)
-----------------------
'''


def generate_lfsr(key: str):

    key_ascii = [ord(key[i]) for i in range(len(key))]

    p, q, k, _ = 0x12000032, 0x2527AC91, -2004086252, 0

    # p, q, k = a3, a4, a5
    '''
    void *__fastcall generateLFSR(void *src, signed int n, pWORD *a3, pWORD *a4, pWORD *a5)
    
    LABEL_9:
      *a3 = v21[0] | (*a3 << 8);
      *a4 = v21[4] | (*a4 << 8);
      *a5 = v21[8] | (*a5 << 8);
      *a3 = v21[1] | (*a3 << 8);
      *a4 = v21[5] | (*a4 << 8);
      *a5 = v21[9] | (*a5 << 8);
      *a3 = v21[2] | (*a3 << 8);
      *a4 = v21[6] | (*a4 << 8);
      *a5 = v21[10] | (*a5 << 8);
      *a3 = v21[3] | (*a3 << 8);
      *a4 = v21[7] | (*a4 << 8);
      *a5 = v21[11] | (*a5 << 8);

    2kawaii:
        *a3 = v21[0] | (*a3 << 8);
        *a3 = v21[2] | (*a3 << 8);
        *a3 = v21[3] | (*a3 << 8);
            
        *a4 = v21[4] | (*a4 << 8);
        *a4 = v21[5] | (*a4 << 8);
        *a4 = v21[7] | (*a4 << 8);
                
        *a5 = v21[8] | (*a5 << 8);
        *a5 = v21[9] | (*a5 << 8);
        *a5 = v21[11] | (*a5 << 8);
    '''

    while _ <= 3:
        p = np.left_shift(p, 8) | key_ascii[_ + 0]
        q = np.left_shift(q, 8) | key_ascii[_ + 4]
        k = np.left_shift(k, 8) | key_ascii[_ + 8]
        _ += 1

    return [p, q, k]


def decrypt_128_each(b, lfsr: list):

    p, q, k = 1, 0, 0

    for _ in range(0, 8):
        if lfsr[0] & 1 != 0:
            lfsr[0] = np.right_shift((0x80000062 ^ (lfsr[0])), 1) | 0x80000000
            if lfsr[1] & 1 != 0:
                p = 1
                lfsr[1] = np.right_shift((lfsr[1] ^ 0x40000020), 1) | 0xC0000000
            else:
                p = 0
                lfsr[1] = np.right_shift(lfsr[1], 1) & 0x3FFFFFFF
        else:

            lfsr[0] = np.right_shift(lfsr[0], 1) & 0x7FFFFFFF
            if lfsr[2] & 1 != 0:
                q = 1
                lfsr[2] = np.right_shift((lfsr[2] ^ 0x10000002), 1) | 0xF0000000
            else:
                q = 0
                lfsr[2] = np.right_shift(lfsr[2], 1) & 0xFFFFFFF

        k = np.left_shift(k, 1) | p ^ q

    return int(b ^ k)


if __name__ == '__main__':
    lfsr = generate_lfsr(key="a271730728cbe141e47fd9d677e9006d")  # 10L

    encrypted = bytearray(open('./encrypted.webp', 'rb').read())
    for _ in range(
        0, 128
    ):  # IDA Pro says: decryptData(a3, 128, "a271730728cbe141e47fd9d677e9006d", 32LL, 1LL); >> only encrypted 128 byte section...
        encrypted[_] = decrypt_128_each(encrypted[_], lfsr)

    decrypted = f"./decrypted.webp"
    with open(decrypted, "wb") as fd:
        fd.write(encrypted)
