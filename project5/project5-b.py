import hashlib
import secrets
from functools import partial
import binascii

# SM2椭圆曲线参数 (sm2p256v1)
P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2


class SM2:
    def __init__(self, ida=b"1234567812345678", entla=None):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.G = (Gx, Gy)
        self.ida = ida
        self.entla = entla or (len(ida) * 8).to_bytes(2, 'big')

    def _mod_inverse(self, a, mod=P):
        """扩展欧几里得算法求模逆"""
        old_r, r = a, mod
        old_s, s = 1, 0
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
        return old_s % mod

    def _point_add(self, P, Q):
        """椭圆曲线点加法"""
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and (y1 != y2 or y1 == 0):
            return (0, 0)

        if x1 == x2:
            l = ((3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1)) % self.p
        else:
            l = ((y2 - y1) * self._mod_inverse(x2 - x1)) % self.p

        x3 = (l * l - x1 - x2) % self.p
        y3 = (l * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def _point_double(self, P):
        """点倍加运算"""
        return self._point_add(P, P)

    def _scalar_mult(self, k, point=None):
        """标量乘法"""
        if point is None:
            point = self.G
        result = (0, 0)
        temp = point
        for bit in bin(k)[2:]:
            result = self._point_double(result)
            if bit == '1':
                result = self._point_add(result, temp)
        return result

    def _sm3(self, data):
        """SM3哈希函数简化版"""
        return hashlib.sha256(data).digest()

    def compute_za(self, public_key):
        """计算ZA值"""
        a_bytes = self.a.to_bytes(32, 'big')
        b_bytes = self.b.to_bytes(32, 'big')
        Gx_bytes = self.G[0].to_bytes(32, 'big')
        Gy_bytes = self.G[1].to_bytes(32, 'big')
        Px, Py = public_key
        Px_bytes = Px.to_bytes(32, 'big')
        Py_bytes = Py.to_bytes(32, 'big')

        z_data = (
                self.entla +
                self.ida +
                a_bytes + b_bytes +
                Gx_bytes + Gy_bytes +
                Px_bytes + Py_bytes
        )
        return self._sm3(z_data)

    def key_gen(self):
        """生成密钥对"""
        d = secrets.randbelow(self.n - 1) + 1
        P = self._scalar_mult(d)
        return d, P

    def sign(self, msg, private_key, public_key, k=None):
        """SM2签名"""
        za = self.compute_za(public_key)
        M = za + msg if isinstance(msg, bytes) else za + msg.encode()
        e = int.from_bytes(self._sm3(M), 'big') % self.n

        while True:
            if k is None:
                k = secrets.randbelow(self.n - 1) + 1

            x1, y1 = self._scalar_mult(k)
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                k = None
                continue

            s = (self._mod_inverse(1 + private_key, self.n) * (k - r * private_key)) % self.n
            if s == 0:
                k = None
                continue

            return (r, s), k

    def ecdsa_sign(self, msg, private_key, k=None):
        """ECDSA签名"""
        e = int.from_bytes(self._sm3(msg if isinstance(msg, bytes) else msg.encode()), 'big') % self.n

        while True:
            if k is None:
                k = secrets.randbelow(self.n - 1) + 1

            x1, y1 = self._scalar_mult(k)
            r = x1 % self.n
            if r == 0:
                k = None
                continue

            s = (self._mod_inverse(k, self.n) * (e + r * private_key)) % self.n
            if s == 0:
                k = None
                continue

            return (r, s), k


# 1. 验证同一个用户重复使用k的漏洞
def poc_reuse_k_same_user():
    print("=" * 50)
    print("POC 1: 同一个用户重复使用k")
    print("=" * 50)

    sm2 = SM2()
    dA, PA = sm2.key_gen()

    # 使用相同的k签名两个不同消息
    k = secrets.randbelow(sm2.n - 1) + 1
    msg1 = b"Message 1"
    msg2 = b"Message 2"

    (r1, s1), _ = sm2.sign(msg1, dA, PA, k)
    (r2, s2), _ = sm2.sign(msg2, dA, PA, k)

    # 推导私钥
    numerator = (s1 - s2) % sm2.n
    denominator = (r2 - r1 - s1 + s2) % sm2.n
    inv_denom = sm2._mod_inverse(denominator, sm2.n)
    dA_recovered = (numerator * inv_denom) % sm2.n

    print(f"原始私钥: {hex(dA)}")
    print(f"推导私钥: {hex(dA_recovered)}")
    print(f"验证结果: {'成功' if dA == dA_recovered else '失败'}")


# 2. 验证不同用户使用相同k的漏洞
def poc_reuse_k_different_users():
    print("\n" + "=" * 50)
    print("POC 2: 不同用户使用相同k")
    print("=" * 50)

    sm2 = SM2()
    k = secrets.randbelow(sm2.n - 1) + 1

    # 用户A
    dA, PA = sm2.key_gen()
    msgA = b"Alice's message"
    (rA, sA), _ = sm2.sign(msgA, dA, PA, k)

    # 用户B
    dB, PB = sm2.key_gen()
    msgB = b"Bob's message"
    (rB, sB), _ = sm2.sign(msgB, dB, PB, k)

    # Alice推导Bob的私钥
    numerator = (k - sB) % sm2.n
    denominator = (sB + rB) % sm2.n
    inv_denom = sm2._mod_inverse(denominator, sm2.n)
    dB_recovered = (numerator * inv_denom) % sm2.n

    # Bob推导Alice的私钥
    numerator = (k - sA) % sm2.n
    denominator = (sA + rA) % sm2.n
    inv_denom = sm2._mod_inverse(denominator, sm2.n)
    dA_recovered = (numerator * inv_denom) % sm2.n

    print(f"Alice的原始私钥: {hex(dA)}")
    print(f"Alice的推导私钥: {hex(dA_recovered)}")
    print(f"Bob的原始私钥: {hex(dB)}")
    print(f"Bob的推导私钥: {hex(dB_recovered)}")
    print(f"验证结果: {'成功' if dA == dA_recovered and dB == dB_recovered else '失败'}")


# 3. 验证相同私钥和k用于SM2和ECDSA的漏洞
def poc_same_dk_sm2_ecdsa():
    print("\n" + "=" * 50)
    print("POC 3: 相同私钥和k用于SM2和ECDSA")
    print("=" * 50)

    sm2 = SM2()
    d, P = sm2.key_gen()
    k = secrets.randbelow(sm2.n - 1) + 1
    msg = b"Same message for SM2 and ECDSA"

    # SM2签名
    (r_sm2, s_sm2), _ = sm2.sign(msg, d, P, k)

    # ECDSA签名
    (r_ecdsa, s_ecdsa), _ = sm2.ecdsa_sign(msg, d, k)

    # 计算哈希值
    za = sm2.compute_za(P)
    e_sm2 = int.from_bytes(sm2._sm3(za + msg), 'big') % sm2.n
    e_ecdsa = int.from_bytes(sm2._sm3(msg), 'big') % sm2.n

    # 推导私钥
    term1 = (e_ecdsa * sm2._mod_inverse(s_ecdsa, sm2.n)) % sm2.n
    term2 = (r_ecdsa * sm2._mod_inverse(s_ecdsa, sm2.n)) % sm2.n

    numerator = (s_sm2 - term1) % sm2.n
    denominator = (term2 - r_sm2 - s_sm2) % sm2.n
    inv_denom = sm2._mod_inverse(denominator, sm2.n)
    d_recovered = (numerator * inv_denom) % sm2.n

    print(f"原始私钥: {hex(d)}")
    print(f"推导私钥: {hex(d_recovered)}")
    print(f"验证结果: {'成功' if d == d_recovered else '失败'}")


if __name__ == "__main__":
    poc_reuse_k_same_user()
    poc_reuse_k_different_users()
    poc_same_dk_sm2_ecdsa()