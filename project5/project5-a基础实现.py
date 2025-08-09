import hashlib
import secrets
import time

# SM2椭圆曲线参数 (sm2p256v1)
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class SM2Base:
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.G = (Gx, Gy)

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

        # 处理无穷远点情况
        if x1 == x2 and (y1 != y2 or y1 == 0):
            return (0, 0)

        if x1 == x2:
            # 点倍加 (P == Q)
            l = ((3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1)) % self.p
        else:
            # 点相加 (P != Q)
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

    def _scalar_mult(self, k, point=None):
        """标量乘法 (基础double-and-add算法)"""
        if point is None:
            point = self.G

        result = (0, 0)  # 无穷远点
        temp = point

        # 将标量k转换为二进制
        k_bin = bin(k)[2:]

        # 从最高位开始处理
        for bit in k_bin:
            result = self._point_double(result)
            if bit == '1':
                result = self._point_add(result, temp)

        return result

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
        """SM3哈希函数 (简化版)"""
        # 实际应用中应使用完整的SM3实现
        return hashlib.sha256(data).digest()

    def key_gen(self):
        """生成密钥对"""
        d = secrets.randbelow(self.n - 1) + 1
        start_time = time.time()
        P = self._scalar_mult(d)
        keygen_time = time.time() - start_time
        return d, P, keygen_time

    def encrypt(self, plaintext, public_key):
        """SM2加密"""
        msg = plaintext.encode('utf-8')
        klen = len(msg) * 8

        total_time = 0
        attempts = 0
        while True:
            attempts += 1
            # 生成随机数k
            k = secrets.randbelow(self.n)
            if k == 0: continue

            # 计算椭圆曲线点C1 = k*G
            start_time = time.time()
            C1 = self._scalar_mult(k)
            x1, y1 = C1
            # 04表示未压缩格式
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

            # 计算C2 = M ⊕ t
            msg_bytes = bytes(msg)
            C2 = bytes(a ^ b for a, b in zip(msg_bytes, t))

            # 计算C3 = Hash(x2 || M || y2)
            C3 = self._sm3(x2_bytes + msg_bytes + y2_bytes)

            encrypt_time = time.time() - start_time
            total_time += encrypt_time

            # 返回密文和耗时
            return C1_bytes + C3 + C2, encrypt_time, attempts

    def decrypt(self, ciphertext, private_key):
        """SM2解密"""
        start_time = time.time()

        # 解析密文 (C1:65字节, C3:32字节, C2:剩余部分)
        if len(ciphertext) < 97:
            raise ValueError("无效的密文长度")

        C1_bytes = ciphertext[:65]
        C3 = ciphertext[65:97]
        C2 = ciphertext[97:]

        # 从C1恢复点 (04表示未压缩格式)
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

        # 计算明文 M = C2 ⊕ t
        msg = bytes(a ^ b for a, b in zip(C2, t))

        # 验证C3
        u = self._sm3(x2_bytes + msg + y2_bytes)
        if u != C3:
            raise ValueError("C3验证失败")

        decrypt_time = time.time() - start_time
        return msg.decode('utf-8', errors='ignore'), decrypt_time

    def sign(self, msg, private_key, user_id=b"1234567812345678"):
        """SM2签名"""
        start_time = time.time()

        # 计算Z值 = Hash(ENTL || ID || a || b || Gx || Gy || Px || Py)
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
        attempts = 0
        while True:
            attempts += 1
            k = secrets.randbelow(self.n)
            # 计算椭圆曲线点 (x1, y1) = k * G
            x1, y1 = self._scalar_mult(k)

            # r = (e + x1) mod n
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue

            # s = ((1 + d)^-1 * (k - r * d)) mod n
            s = (self._mod_inverse(1 + private_key, self.n) * (k - r * private_key)) % self.n
            if s == 0:
                continue

            sign_time = time.time() - start_time
            return (r, s), sign_time, attempts

    def verify(self, msg, signature, public_key, user_id=b"1234567812345678"):
        """SM2验签"""
        start_time = time.time()

        r, s = signature

        # 验证签名值范围
        if not (1 <= r < self.n) or not (1 <= s < self.n):
            return False, 0

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

        # 计算e = Hash(Z || M)
        M = msg.encode('utf-8')
        e_data = Z + M
        e = int.from_bytes(self._sm3(e_data), 'big')

        # 计算t = (r + s) mod n
        t = (r + s) % self.n
        if t == 0:
            return False, 0

        # 计算椭圆曲线点 (x1, y1) = s * G + t * P
        point1 = self._scalar_mult(s)
        point2 = self._scalar_mult(t, public_key)
        x1, y1 = self._point_add(point1, point2)

        # 验证R = (e + x1) mod n
        R = (e + x1) % self.n

        verify_time = time.time() - start_time
        return R == r, verify_time


# 测试示例
if __name__ == "__main__":
    sm2 = SM2Base()

    # 密钥生成测试
    print("=" * 50)
    print("SM2基础实现性能测试")
    print("=" * 50)

    keygen_times = []
    for i in range(5):
        private_key, public_key, keygen_time = sm2.key_gen()
        keygen_times.append(keygen_time)
        print(f"\n密钥对 {i + 1}:")
        print(f"私钥: {hex(private_key)[:20]}...")
        print(f"公钥: (0x{public_key[0]:064x}...")
        print(f"生成耗时: {keygen_time:.4f}秒")

    print(f"\n密钥生成平均耗时: {sum(keygen_times) / len(keygen_times):.4f}秒")

    # 使用最后一个密钥对进行加密解密和签名测试
    private_key, public_key, _ = sm2.key_gen()
    print(f"\n最终使用的私钥: {hex(private_key)[:20]}...")

    # 加密解密测试
    plaintext = "12 34 56 78 90"
    print(f"\n原始文本: {plaintext}")

    # 加密
    ciphertext, encrypt_time, encrypt_attempts = sm2.encrypt(plaintext, public_key)
    print(f"密文长度: {len(ciphertext)}字节")
    print(f"加密耗时: {encrypt_time:.4f}秒, 尝试次数: {encrypt_attempts}")

    # 解密
    decrypted, decrypt_time = sm2.decrypt(ciphertext, private_key)
    print(f"解密结果: {decrypted[:20]}...")
    print(f"解密耗时: {decrypt_time:.4f}秒")
    print(f"加解密 {'成功' if plaintext == decrypted else '失败'}")

    # 签名验签测试
    message = "love sdu" * 2  # 稍长的消息
    print(f"\n消息: {message[:30]}...")

    # 签名
    signature, sign_time, sign_attempts = sm2.sign(message, private_key)
    print(f"签名: (r={signature[0]},\n     s={signature[1]})")
    print(f"签名耗时: {sign_time:.4f}秒, 尝试次数: {sign_attempts}")

    # 验签
    valid, verify_time = sm2.verify(message, signature, public_key)
    print(f"签名验证 {'成功' if valid else '失败'}")
    print(f"验签耗时: {verify_time:.4f}秒")

    # 性能对比
    print("\n" + "=" * 50)
    print("性能总结:")
    print(f"密钥生成: {sum(keygen_times) / len(keygen_times):.4f}秒")
    print(f"加密: {encrypt_time:.4f}秒 (尝试次数: {encrypt_attempts})")
    print(f"解密: {decrypt_time:.4f}秒")
    print(f"签名: {sign_time:.4f}秒 (尝试次数: {sign_attempts})")
    print(f"验签: {verify_time:.4f}秒")
    print("=" * 50)