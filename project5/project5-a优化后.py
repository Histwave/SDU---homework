import hashlib
import secrets
import binascii
import time

# 定义SM2椭圆曲线参数 (sm2p256v1)
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class SM2:
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.G = (Gx, Gy)

        # 预计算G点的倍点 (窗口法优化)
        self.precomputed_G = self._precompute_points(self.G, window_size=4)

    def _precompute_points(self, point, window_size=4):
        """预计算点的倍点用于窗口法优化"""
        table = {}
        # 计算1*point到(2^window_size-1)*point
        table[1] = point
        # 计算2倍点
        table[2] = self._point_double(point)
        # 计算其他倍数点
        for i in range(3, 1 << window_size):
            table[i] = self._point_add(table[i - 1], table[1])
        return table

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
        """椭圆曲线点加法 (仿射坐标)"""
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and (y1 != y2 or y1 == 0):
            return (0, 0)  # 无穷远点

        if x1 == x2:
            # 点倍加
            l = ((3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1)) % self.p
        else:
            # 点相加
            l = ((y2 - y1) * self._mod_inverse(x2 - x1)) % self.p

        x3 = (l * l - x1 - x2) % self.p
        y3 = (l * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def _point_double(self, P):
        """点倍加运算"""
        if P == (0, 0):
            return (0, 0)
        x1, y1 = P
        if y1 == 0:
            return (0, 0)

        l = ((3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1)) % self.p
        x3 = (l * l - 2 * x1) % self.p
        y3 = (l * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def _point_double_jacobian(self, X, Y, Z):
        """Jacobian坐标下的点倍加 (优化核心)"""
        if Y == 0:
            return (0, 0, 0)

        # 临时变量
        Y2 = (Y * Y) % self.p
        S = (4 * X * Y2) % self.p
        M = (3 * X * X + self.a * pow(Z, 4, self.p)) % self.p

        # 计算新坐标
        X3 = (M * M - 2 * S) % self.p
        Y3 = (M * (S - X3) - 8 * pow(Y2, 2, self.p)) % self.p
        Z3 = (2 * Y * Z) % self.p
        return (X3, Y3, Z3)

    def _point_add_jacobian(self, X1, Y1, Z1, X2, Y2, Z2):
        """Jacobian坐标下的点加法"""
        if Z1 == 0:
            return (X2, Y2, Z2)
        if Z2 == 0:
            return (X1, Y1, Z1)

        # 转换Q到Jacobian坐标
        Z1_2 = (Z1 * Z1) % self.p
        Z2_2 = (Z2 * Z2) % self.p
        U1 = (X1 * Z2_2) % self.p
        U2 = (X2 * Z1_2) % self.p
        S1 = (Y1 * Z2_2 * Z2) % self.p
        S2 = (Y2 * Z1_2 * Z1) % self.p

        if U1 == U2:
            if S1 != S2:
                return (0, 0, 1)
            return self._point_double_jacobian(X1, Y1, Z1)

        # 计算差值
        H = (U2 - U1) % self.p
        R = (S2 - S1) % self.p
        H2 = (H * H) % self.p
        H3 = (H2 * H) % self.p

        # 计算新坐标
        X3 = (R * R - H3 - 2 * U1 * H2) % self.p
        Y3 = (R * (U1 * H2 - X3) - S1 * H3) % self.p
        Z3 = (H * Z1 * Z2) % self.p
        return (X3, Y3, Z3)

    def _jacobian_to_affine(self, X, Y, Z):
        """Jacobian坐标转仿射坐标"""
        if Z == 0:
            return (0, 0)
        Z_inv = self._mod_inverse(Z)
        Z_inv2 = (Z_inv * Z_inv) % self.p
        Z_inv3 = (Z_inv2 * Z_inv) % self.p
        x = (X * Z_inv2) % self.p
        y = (Y * Z_inv3) % self.p
        return (x, y)

    def _scalar_mult(self, k, point=None):
        """标量乘法 (使用Jacobian坐标和滑动窗口法)"""
        if point is None:
            # 使用预计算的基点G表
            return self._scalar_mult_with_table(k, self.precomputed_G)

        # 对于非基点，使用Jacobian坐标方法
        return self._scalar_mult_jacobian(k, point)

    def _scalar_mult_with_table(self, k, table):
        """使用预计算表的标量乘法 (高效方法)"""
        result = (0, 0)
        window_size = 4
        max_index = (1 << window_size) - 1

        # 将标量转换为二进制
        k_bin = bin(k)[2:]
        n = len(k_bin)
        i = 0

        while i < n:
            if k_bin[i] == '0':
                result = self._point_double(result)
                i += 1
            else:
                # 取最大窗口
                j = min(window_size, n - i)
                window_val = int(k_bin[i:i + j], 2)

                # 加倍j次
                for _ in range(j):
                    result = self._point_double(result)

                # 加上预计算表中的点
                if window_val > 0 and window_val <= max_index:
                    result = self._point_add(result, table[window_val])
                i += j

        return result

    def _scalar_mult_jacobian(self, k, point):
        """使用Jacobian坐标的标量乘法 (通用方法)"""
        X, Y = point
        Z = 1
        result = (0, 0, 0)  # Jacobian坐标的无穷远点

        # 将标量转换为二进制
        k_bin = bin(k)[2:]

        for bit in k_bin:
            # 加倍
            result = self._point_double_jacobian(*result)

            if bit == '1':
                # 加上基点
                result = self._point_add_jacobian(*result, X, Y, Z)

        return self._jacobian_to_affine(*result)

    def _kdf(self, Z, klen):
        """密钥派生函数 (基于SM3)"""
        v = 256  # SM3输出长度 (256位)
        ct = 0x00000001
        ha = b''
        for i in range((klen + v - 1) // v):
            data = Z + ct.to_bytes(4, 'big')
            ct += 1
            ha += self._sm3(data)
        return ha[:klen // 8]

    def _sm3(self, data):
        """SM3哈希函数 (简化版，实际应使用完整实现)"""
        # 实际应用中应使用完整的SM3实现
        return hashlib.sha256(data).digest()  # 简化示例

    def key_gen(self):
        """生成密钥对"""
        d = secrets.randbelow(self.n - 1) + 1
        P = self._scalar_mult(d)
        return d, P

    def encrypt(self, plaintext, public_key):
        """SM2加密"""
        msg = plaintext.encode('utf-8')
        klen = len(msg) * 8

        while True:
            # 生成随机数k
            k = secrets.randbelow(self.n)
            if k == 0: continue

            # 计算椭圆曲线点C1 = k*G
            C1 = self._scalar_mult(k)
            x1, y1 = C1
            C1_bytes = bytes.fromhex(f"04{x1:064x}{y1:064x}")

            # 计算椭圆曲线点S = k*P
            S = self._scalar_mult(k, public_key)
            x2, y2 = S
            x2_bytes = x2.to_bytes(32, 'big')
            y2_bytes = y2.to_bytes(32, 'big')

            # 密钥派生
            t = self._kdf(x2_bytes + y2_bytes, klen)
            if all(b == 0 for b in t):
                continue  # 确保t不为全0

            # 计算C2
            msg_bytes = bytes(msg)
            C2 = bytes(a ^ b for a, b in zip(msg_bytes, t))

            # 计算C3
            C3 = self._sm3(x2_bytes + msg_bytes + y2_bytes)

            # 返回密文 (C1 || C3 || C2)
            return C1_bytes + C3 + C2

    def decrypt(self, ciphertext, private_key):
        """SM2解密"""
        # 解析密文 (C1:65字节, C3:32字节, C2:剩余部分)
        if len(ciphertext) < 97:
            raise ValueError("无效的密文长度")

        C1_bytes = ciphertext[:65]
        C3 = ciphertext[65:97]
        C2 = ciphertext[97:]

        # 从C1恢复点
        if C1_bytes[0] != 0x04:
            raise ValueError("不支持的压缩格式")
        x1 = int.from_bytes(C1_bytes[1:33], 'big')
        y1 = int.from_bytes(C1_bytes[33:65], 'big')
        C1 = (x1, y1)

        # 计算点S = d * C1
        S = self._scalar_mult(private_key, C1)
        x2, y2 = S
        x2_bytes = x2.to_bytes(32, 'big')
        y2_bytes = y2.to_bytes(32, 'big')

        # 密钥派生
        klen = len(C2) * 8
        t = self._kdf(x2_bytes + y2_bytes, klen)
        if all(b == 0 for b in t):
            raise ValueError("KDF派生密钥失败")

        # 计算明文
        msg = bytes(a ^ b for a, b in zip(C2, t))

        # 验证C3
        u = self._sm3(x2_bytes + msg + y2_bytes)
        if u != C3:
            raise ValueError("C3验证失败")

        return msg.decode('utf-8', errors='ignore')

    def sign(self, msg, private_key, user_id=b"1234567812345678"):
        """SM2签名"""
        # 计算Z值
        entl = len(user_id) * 8
        a_bytes = self.a.to_bytes(32, 'big')
        b_bytes = self.b.to_bytes(32, 'big')
        Gx_bytes = self.G[0].to_bytes(32, 'big')
        Gy_bytes = self.G[1].to_bytes(32, 'big')
        Px, Py = self._scalar_mult(private_key)
        Px_bytes = Px.to_bytes(32, 'big')
        Py_bytes = Py.to_bytes(32, 'big')

        z_data = (
                entl.to_bytes(2, 'big') +
                user_id +
                a_bytes + b_bytes +
                Gx_bytes + Gy_bytes +
                Px_bytes + Py_bytes
        )
        Z = self._sm3(z_data)

        # 计算e = Hash(Z || M)
        M = msg.encode('utf-8')
        e_data = Z + M
        e = int.from_bytes(self._sm3(e_data), 'big')

        # 签名
        while True:
            k = secrets.randbelow(self.n)
            x1, y1 = self._scalar_mult(k)
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue

            s = (self._mod_inverse(1 + private_key, self.n) * (k - r * private_key)) % self.n
            if s == 0:
                continue

            return (r, s)

    def verify(self, msg, signature, public_key, user_id=b"1234567812345678"):
        """SM2验签"""
        r, s = signature
        if not (1 <= r < self.n) or not (1 <= s < self.n):
            return False

        # 计算Z值 (同签名过程)
        entl = len(user_id) * 8
        a_bytes = self.a.to_bytes(32, 'big')
        b_bytes = self.b.to_bytes(32, 'big')
        Gx_bytes = self.G[0].to_bytes(32, 'big')
        Gy_bytes = self.G[1].to_bytes(32, 'big')
        Px, Py = public_key
        Px_bytes = Px.to_bytes(32, 'big')
        Py_bytes = Py.to_bytes(32, 'big')

        z_data = (
                entl.to_bytes(2, 'big') +
                user_id +
                a_bytes + b_bytes +
                Gx_bytes + Gy_bytes +
                Px_bytes + Py_bytes
        )
        Z = self._sm3(z_data)

        # 计算e
        M = msg.encode('utf-8')
        e_data = Z + M
        e = int.from_bytes(self._sm3(e_data), 'big')

        # 计算t
        t = (r + s) % self.n
        if t == 0:
            return False

        # 计算椭圆曲线点
        point1 = self._scalar_mult(s)
        point2 = self._scalar_mult(t, public_key)
        x1, y1 = self._point_add(point1, point2)

        # 验证签名
        R = (e + x1) % self.n
        return R == r


# 测试示例
if __name__ == "__main__":
    sm2 = SM2()

    # 密钥生成
    private_key, public_key = sm2.key_gen()
    print(f"私钥: {hex(private_key)[:20]}...")
    print(f"公钥: (0x{public_key[0]:064x}, 0x{public_key[1]:064x})")

    # 性能测试
    start = time.time()
    for _ in range(10):
        sm2.key_gen()
    print(f"\n密钥生成平均时间: {(time.time() - start) / 10:.4f}秒")

    # 加密解密测试
    plaintext = "12 34 56 78 90"
    start = time.time()
    ciphertext = sm2.encrypt(plaintext, public_key)
    encrypt_time = time.time() - start

    start = time.time()
    decrypted = sm2.decrypt(ciphertext, private_key)
    decrypt_time = time.time() - start

    print(f"\n原始文本: {plaintext}")
    print(f"解密结果: {decrypted[:20]}")
    print(f"加解密 {'成功' if plaintext == decrypted else '失败'}")
    print(f"加密时间: {encrypt_time:.6f}秒, 解密时间: {decrypt_time:.6f}秒")

    # 签名验签测试
    message = "love sdu"
    start = time.time()
    signature = sm2.sign(message, private_key)
    sign_time = time.time() - start

    start = time.time()
    valid = sm2.verify(message, signature, public_key)
    verify_time = time.time() - start

    print(f"\n消息: {message[:20]}")
    print(f"签名验证 {'成功' if valid else '失败'}")
    print(f"签名时间: {sign_time:.6f}秒, 验签时间: {verify_time:.6f}秒")