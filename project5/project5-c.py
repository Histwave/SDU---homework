import hashlib
import math
from math import gcd


# 椭圆曲线运算实现
class EllipticCurve:
    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b

    def point_addition(self, P, Q):
        """椭圆曲线点加算法 - 重构实现"""
        # 处理无穷远点
        if P == "O":
            return Q
        if Q == "O":
            return P

        x1, y1 = P
        x2, y2 = Q

        # 处理点加倍
        if P == Q:
            if y1 == 0:
                return "O"  # 无穷远点
            numerator = 3 * pow(x1, 2, self.p) + self.a
            denominator = (2 * y1) % self.p
        else:
            if x1 == x2:  # 垂直切线
                return "O"
            numerator = (y2 - y1) % self.p
            denominator = (x2 - x1) % self.p

        inv_denom = self.modular_inverse(denominator)
        if inv_denom is None:
            return "O"
        lam = (numerator * inv_denom) % self.p

        x3 = (lam ** 2 - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def scalar_multiplication(self, k, point):
        """椭圆曲线标量乘法 - 使用改进的倍点算法"""
        if k == 0 or point == "O":
            return "O"

        result = "O"
        current = point

        # 使用二进制展开进行倍点运算
        while k:
            if k & 1:
                result = self.point_addition(result, current)
            current = self.point_addition(current, current)
            k >>= 1
        return result

    def modular_inverse(self, a):
        """改进的模逆元计算 - 使用欧拉定理"""
        if gcd(a, self.p) != 1:
            return None
        return pow(a, self.p - 2, self.p)


class ECDSA:

    def __init__(self, curve, n, G):
        self.curve = curve
        self.n = n
        self.G = G

    def sign(self, d, k, message):
        """ECDSA签名生成 - 重构实现"""
        R = self.curve.scalar_multiplication(k, self.G)
        if R == "O":
            raise ValueError("无效的随机数k")

        r = R[0] % self.n
        e = self.hash_message(message)
        s = (self.modular_inverse(k, self.n) * (e + d * r)) % self.n
        return (r, s)

    def verify(self, pub_key, message, signature):
        """验证ECDSA签名 - 重构实现"""
        r, s = signature
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False

        e = self.hash_message(message)
        w = self.modular_inverse(s, self.n)
        u1 = (e * w) % self.n
        u2 = (r * w) % self.n

        # 计算点 P = u1*G + u2*Q
        P1 = self.curve.scalar_multiplication(u1, self.G)
        P2 = self.curve.scalar_multiplication(u2, pub_key)
        P = self.curve.point_addition(P1, P2)

        return P != "O" and P[0] % self.n == r

    def hash_message(self, message):
        """消息哈希计算"""
        return int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big') % self.n

    def modular_inverse(self, a, m):
        """通用模逆元计算"""
        if gcd(a, m) != 1:
            return None
        return pow(a, m - 2, m)


def forge_satoshi_signature():
    """伪造中本聪签名的演示 - 重构实现但输出相同"""
    # 比特币使用的secp256k1曲线参数
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

    # 创建曲线和ECDSA实例
    curve = EllipticCurve(p, a, b)
    ecdsa = ECDSA(curve, n, G)

    # 中本聪的私钥（实际未知，用于演示）
    satoshi_d = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
    k = 0x3A780  # 重复使用的k值

    # 生成两个真实签名
    message1 = "无论沧桑岁月长 哪怕海角与天涯"
    message2 = "魂牵梦萦的眷恋 我的山大我的家"
    sig1 = ecdsa.sign(satoshi_d, k, message1)
    sig2 = ecdsa.sign(satoshi_d, k, message2)

    print("=" * 70)
    print("伪造中本聪数字签名演示")
    print("=" * 70)
    print(f"消息1: '{message1}'")
    print(f"签名1: (r={hex(sig1[0])}, s={hex(sig1[1])})")
    print(f"\n消息2: '{message2}'")
    print(f"签名2: (r={hex(sig2[0])}, s={hex(sig2[1])})")
    print("\n分析：两个签名使用了相同的随机数k（r值相同）")

    # 从签名中恢复k和私钥
    r1, s1 = sig1
    r2, s2 = sig2

    # 验证r值是否相同
    if r1 != r2:
        print("错误：签名没有使用相同的k值")
        return

    # 计算消息哈希
    e1 = ecdsa.hash_message(message1)
    e2 = ecdsa.hash_message(message2)

    # 改进的私钥恢复算法
    s_diff = (s1 - s2) % n
    s_diff_inv = ecdsa.modular_inverse(s_diff, n)
    k_recovered = ((e1 - e2) * s_diff_inv) % n
    d_recovered = ((s1 * k_recovered - e1) * ecdsa.modular_inverse(r1, n)) % n

    print("\n通过签名分析恢复的信息：")
    print(f"恢复的随机数k: {hex(k_recovered)}")
    print(f"恢复的中本聪私钥: {hex(d_recovered)}")

    # 验证恢复的私钥是否正确
    if d_recovered == satoshi_d:
        print("\n成功恢复中本聪的私钥！")
    else:
        print("\n私钥恢复失败")
        return

    # 使用恢复的私钥伪造新签名
    forged_message = "那是我的家 朴实又美丽"
    forged_signature = ecdsa.sign(d_recovered, k_recovered, forged_message)

    # 验证伪造的签名
    satoshi_pub = curve.scalar_multiplication(satoshi_d, G)
    is_valid = ecdsa.verify(satoshi_pub, forged_message, forged_signature)

    print("\n伪造新签名：")
    print(f"伪造的消息: '{forged_message}'")
    print(f"伪造的签名: (r={hex(forged_signature[0])}, s={hex(forged_signature[1])})")
    print(f"\n签名验证结果: {'有效' if is_valid else '无效'}")

    if is_valid:
        print("\n成功伪造中本聪的数字签名！")
        print("注意：在真实比特币网络中，这个签名将被视为有效交易")
    else:
        print("\n签名伪造失败")

    print("=" * 70)


if __name__ == '__main__':
    forge_satoshi_signature()