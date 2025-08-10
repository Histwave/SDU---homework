# Project6  Google Password Checkup验证
## 一、实验背景
通过阅读论文 https://eprint.iacr.org/2019/723.pdf 的 section 3.1，从中获得基于 DDH（Decisional Diffie-Hellman）的私密交集求和协议的内容：该协议用于在保护隐私的前提下计算两个参与方数据集的交集大小及关联值之和，适用于广告转化归因等场景。

协议核心是扩展了现有的私有集合交集（PSI）协议，使用满足 DDH 假设的群、加法同态加密方案和哈希函数（作为随机预言机）构建。其主要步骤包括：
-   准备阶段：双方选择私钥，持有值的 P2 生成同态加密密钥对并发送公钥给 P1；
-   多轮交互：P1 对自身标识符哈希后用私钥处理并乱序发送，P2 进一步处理后回传，同时 P2 加密关联值并发送；P1 确定交集后，同态累加交集对应的值并加密发送给 P2；
-   输出：P2 解密得到交集和，双方均能获得交集大小。

该协议针对半诚实攻击者，保证仅泄露交集大小和总和，且注重降低通信开销以减少成本。
## 二、实验原理
### 1. 核心目标

-   **隐私保护**：双方在不泄露各自私有数据的前提下协作
    
-   **集合求交**：确定两个集合的交集元素
    
-   **值求和**：对交集中元素在对方数据集中的关联值进行求和
    

### 2. 关键技术基础

#### (1) 离散对数难题

-   基于乘法群上的离散对数问题困难性
    
-   给定生成元 g 和结果 y，难以计算指数 x 使得 $g^x ≡ y \mod p$
    
-   为盲化操作提供安全保障
    

#### (2) Paillier同态加密

-   加法同态性：$E(m_1) \times E(m_2) = E(m_1 + m_2)$
    
-   标量乘法：$E(m)^k = E(k \cdot m)$
    
-   允许在密文状态下进行算术运算
    

#### (3) 双重盲化技术

-   双方各自持有私有盲化因子（$k_1$ 和 $k_2$）
    
-   元素标识符经过两次指数盲化：$h^{k_1k_2}$
    
-   确保只有双方合作才能恢复原始元素
    

### 3. 安全模型

-   **半诚实模型**：参与者遵守协议但会尝试学习额外信息
    
-   **隐私保证**：
    
    -   P1 无法得知 P2 的非交集元素及其值
        
    -   P2 无法得知 P1 的完整集合元素
        
    -   双方都无法得知对方的具体盲化因子
        
-   **前向安全**：每次会话使用临时密钥
## 三、实验思路和过程
### 实现思路

1.  **隐私保护**：
    
    -   元素标识符通过哈希映射到群元素
        
    -   使用双重指数盲化（k1 和 k2）隐藏原始值
        
    -   数值数据使用同态加密保护
        
2.  **安全计算**：
    
    -   P1 知道交集元素但不知道关联值
        
    -   P2 知道最终求和结果但不知道具体哪些元素在交集中
        
    -   双方都不知道对方的完整数据集
        
3.  **高效实现**：
    
    -   使用洗牌操作防止位置信息泄露
        
    -   优化同态加密计算
        
    -   使用固定生成元简化 Paillier 加密
        

### 具体过程

### 1. 初始设置

#### 群参数选择：
```python
MODULUS = 101  # 素数模数 (p)
ORDER = 25     # 子群阶 (q)，满足 (p-1) % q == 0
BASE = 2       # 生成元，满足 BASE^q ≡ 1 mod p
```
#### Paillier参数：
```python
PRIME1 = 127   # 大素数p
PRIME2 = 131   # 大素数q
```

### 2. 映射函数实现
```python
def map_to_group(element):
    """安全地将标识符映射到群元素"""
    # 使用BLAKE2b抗碰撞哈希
    digest = hashlib.blake2b(element.encode(), digest_size=16).digest()
    # 转换为整数
    num = int.from_bytes(digest, 'big')
    # 模子群阶得到指数
    exp = num % ORDER
    # 计算群元素
    return pow(BASE, exp, MODULUS)
```

### 3. Paillier加密系统
```python
class SecureComputation:
    def __init__(self, private=None, public=None):
        if private:
            p, q = private
            self.N = p * q  # 模数
            self.N2 = self.N * self.N  # 模数的平方
            φ = (p-1)*(q-1)  # 欧拉函数
            self.λ = φ // gcd(p-1, q-1)  # 卡迈克尔函数
            self.g = self.N + 1  # 简化设置
            self.μ = pow(self.λ, -1, self.N)  # 解密系数
            
        elif public:
            self.N, self.g = public
            self.N2 = self.N * self.N
    
    def encrypt(self, plaintext, r=None):
        """加密数值"""
        r = r or secrets.randbelow(self.N-1) + 1
        # 计算 (g^m * r^n) mod n^2
        term1 = pow(self.g, plaintext, self.N2)
        term2 = pow(r, self.N, self.N2)
        return (term1 * term2) % self.N2
    
    def decrypt(self, ciphertext):
        """解密数值"""
        # 计算 c^λ mod n^2
        num = pow(ciphertext, self.λ, self.N2)
        # 计算L函数: L(u) = (u-1)/n
        L_val = (num - 1) // self.N
        # 恢复明文: m = L(c^λ) * μ mod n
        return (L_val * self.μ) % self.N
    
    def add_ciphertexts(self, c1, c2):
        """同态加法"""
        return c1 * c2 % self.N2
    
    def refresh(self, ciphertext):
        """重随机化密文"""
        r = secrets.randbelow(self.N-1) + 1
        rerandom = pow(r, self.N, self.N2)
        return ciphertext * rerandom % self.N2
```

### 4. 协议执行流程

#### 步骤1：初始化
```python
# 参与者数据集
participant_A = ["天空", "牛马", "杯子", "李清照"]  
participant_B = [("天空", 10), ("李清照", 20), ("易安体", 30), ("绿肥红瘦", 40)]

# 生成私有盲化因子
k1 = secrets.randbelow(ORDER-1) + 1  # P1的私钥
k2 = secrets.randbelow(ORDER-1) + 1  # P2的私钥

# P2初始化加密系统
p2_crypto = SecureComputation(private=(PRIME1, PRIME2))
pub_key = (p2_crypto.N, p2_crypto.g)  # 公钥
```

#### 步骤2：P1 → P2 (盲化元素)
```python
blinded_set = []
for item in p1_items:
    h = map_to_group(item)          # 映射到群元素
    blinded = pow(h, k1, MODULUS)   # 用k1盲化
    blinded_set.append(blinded)

# 洗牌防止顺序分析
secrets.SystemRandom().shuffle(blinded_set)
```
#### 步骤3：P2 → P1 (双重盲化+加密值)
```python
# 处理P1的盲化元素
double_blinded = [pow(item, k2, MODULUS) for item in blinded_set]
secrets.SystemRandom().shuffle(double_blinded)

# 处理P2的数据
encrypted_data = []
for id_val, num in p2_data:
    h_id = map_to_group(id_val)      # 映射标识符
    h_kB = pow(h_id, k2, MODULUS)   # 用k2盲化
    enc_num = p2_crypto.encrypt(num) # 加密关联值
    encrypted_data.append((h_kB, enc_num))

secrets.SystemRandom().shuffle(encrypted_data)
```

#### 步骤4：P1 → P2 (计算交集和)
```python
# P1初始化加密系统
p1_crypto = SecureComputation(public=pub_key)

# 初始化加密的零值
total = p1_crypto.encrypt(0)

# 查找交集并累加
for h_val, enc_val in encrypted_data:
    h_combined = pow(h_val, k1, MODULUS)  # 应用k1完成双重盲化
    
    if h_combined in double_blinded:
        # 同态加法累加
        total = p1_crypto.add_ciphertexts(total, enc_val)

# 重随机化最终结果
randomized_total = p1_crypto.refresh(total)
```

## 四、实验结果
如图片project6 结果所示，最终验证结果成功，说明协议设计成功。
