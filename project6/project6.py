import secrets
import hashlib
from math import gcd

# 群参数
MODULUS = 101  # 素数模数
ORDER = 25  # 子群的阶 (满足 (MODULUS-1) % ORDER == 0)
BASE = 2  # 生成元 (满足 BASE^ORDER ≡ 1 mod MODULUS)

# Paillier参数
PRIME1 = 127
PRIME2 = 131


def map_to_group(element):
    """将标识符映射到群元素"""
    digest = hashlib.blake2b(element.encode(), digest_size=16).digest()
    num = int.from_bytes(digest, 'big')
    exp = num % ORDER
    return pow(BASE, exp, MODULUS)


class SecureComputation:
    def __init__(self, private=None, public=None):
        """初始化加密系统"""
        if private:
            p, q = private
            self.N = p * q
            self.N2 = self.N * self.N
            φ = (p - 1) * (q - 1)
            self.λ = φ // gcd(p - 1, q - 1)
            self.g = self.N + 1  # 固定使用 g = n + 1
            self.μ = pow(self.λ, -1, self.N)
        elif public:
            self.N, self.g = public
            self.N2 = self.N * self.N
        else:
            raise ValueError("需要提供私钥或公钥参数")

    def encrypt(self, plaintext, r=None):
        """加密数值"""
        r = r or secrets.randbelow(self.N - 1) + 1
        term1 = pow(self.g, plaintext, self.N2)
        term2 = pow(r, self.N, self.N2)
        return (term1 * term2) % self.N2

    def decrypt(self, ciphertext):
        """解密数值"""
        num = pow(ciphertext, self.λ, self.N2)
        L = (num - 1) // self.N
        return (L * self.μ) % self.N

    def add_ciphertexts(self, c1, c2):
        """同态加法"""
        return c1 * c2 % self.N2

    def refresh(self, ciphertext):
        """重随机化密文"""
        r = secrets.randbelow(self.N - 1) + 1
        rerandom = pow(r, self.N, self.N2)
        return ciphertext * rerandom % self.N2


def perform_private_set_intersection():
    """执行隐私集合求交协议"""
    # 参与者数据集
    participant_A = ["天空", "牛马", "杯子", "李清照"]
    participant_B = [("天空", 10), ("李清照", 20), ("易安体", 30), ("绿肥红瘦", 40)]

    # 密钥初始化
    secret_A = secrets.randbelow(ORDER - 1) + 1
    secret_B = secrets.randbelow(ORDER - 1) + 1

    # 初始化加密系统
    crypto_B = SecureComputation(private=(PRIME1, PRIME2))
    pub_key = (crypto_B.N, crypto_B.g)
    print(f"同态加密公钥: N={pub_key[0]}, g={pub_key[1]}")

    # 阶段1: A → B (盲化元素)
    blinded_set = []
    for item in participant_A:
        h = map_to_group(item)
        blinded = pow(h, secret_A, MODULUS)
        blinded_set.append(blinded)
    secrets.SystemRandom().shuffle(blinded_set)

    # 阶段2: B → A (双重盲化+加密值)
    double_blinded = [pow(item, secret_B, MODULUS) for item in blinded_set]
    secrets.SystemRandom().shuffle(double_blinded)

    # B准备加密数据对
    encrypted_data = []
    for id_val, num in participant_B:
        h_id = map_to_group(id_val)
        h_kB = pow(h_id, secret_B, MODULUS)
        enc_num = crypto_B.encrypt(num)
        encrypted_data.append((h_kB, enc_num))
    secrets.SystemRandom().shuffle(encrypted_data)

    # 阶段3: A → B (计算交集和)
    crypto_A = SecureComputation(public=pub_key)

    # 初始化加密的零值
    total = crypto_A.encrypt(0)

    # 查找交集并累加
    for h_val, enc_val in encrypted_data:
        h_combined = pow(h_val, secret_A, MODULUS)
        if h_combined in double_blinded:
            total = crypto_A.add_ciphertexts(total, enc_val)

    # 重随机化最终结果
    randomized_total = crypto_A.refresh(total)

    # 解密结果
    result = crypto_B.decrypt(randomized_total)

    # 验证结果
    common_items = [id for id in participant_A if id in [d[0] for d in participant_B]]
    expected_sum = sum(val for id, val in participant_B if id in common_items)

    print("交集元素:", common_items)
    print("预期求和值:", expected_sum)
    print("协议计算结果:", result)
    print("验证结果:", "成功" if result == expected_sum else "失败")


if __name__ == "__main__":
    perform_private_set_intersection()