# Project5-a  SM2的软件实现优化
## 一、实验背景
SM2 算法是中国国家密码管理局于 2010 年发布的一种基于椭圆曲线密码学（ECC）的公钥加密算法。相关标准为 “GM/T 0003-2012《SM2 椭圆曲线公钥密码算法》”，2016 年成为中国国家密码标准（GB/T 32918-2016）。以下是具体介绍：
-   **算法组成**：SM2 算法主要包括数字签名、密钥交换和公钥加密三个部分。其中，数字签名采用椭圆曲线数字签名算法（ECDSA），密钥交换采用椭圆曲线 Diffie - Hellman（ECDH）算法，公钥加密采用椭圆曲线公钥加密算法（ECIES）。
-   **核心原理**：SM2 算法的安全性依赖于椭圆曲线离散对数问题。即已知椭圆曲线点 P 和 Q=kP，求 k 在计算上是不可行的。它使用素数域上的椭圆曲线方程 y² = x³ + ax + b (mod p)，通过有限域运算、点加、倍点和标量乘法等运算构成其核心运算。
-   **密钥生成**：先选择一个椭圆曲线和基点，用户随机生成一个私钥 d，然后通过公式 Q = d * G 计算公钥 Q，其中 G 为基点。
-   **算法优势**：相比 RSA 等传统公钥密码体制，SM2 算法在相同安全级别下，密钥长度更短，通常使用 256 位密钥，运算速度更快，存储空间更小，密码复杂度高，机器性能消耗更小。
-   **应用场景**：广泛应用于数字签名、公钥加密、密钥交换等领域，是金融、政务、物联网等场景的核心安全技术，也可用于电子合同、文档签署等场景中的数字签名以及用户身份验证和授权等。
## 二、SM2基础实现思路与过程
### 1. 算法概述

SM2是中国国家密码管理局发布的椭圆曲线公钥密码算法标准，包括数字签名、密钥交换和公钥加密。其核心基于椭圆曲线密码学(ECC)。

### 2. 实现思路

1.  **椭圆曲线参数设置**：
    
    -   使用国密局推荐的椭圆曲线参数(sm2p256v1)
        
    -   定义素数域p、系数a,b、基点G和阶n
        
2.  **核心运算实现**：
    
    -   模逆运算：扩展欧几里得算法
        
    -   点加法和点倍乘：仿射坐标下的运算
        
    -   标量乘法：double-and-add算法
        
3.  **加密流程**：
```
输入：明文M，公钥P
1. 生成随机数k∈[1, n-1]
2. 计算C1 = k·G
3. 计算S = k·P
4. 计算t = KDF(x2||y2, klen)
5. 计算C2 = M ⊕ t
6. 计算C3 = Hash(x2||M||y2)
输出：密文C = C1||C3||C2
```
4. **解密流程**：
 ```
输入：密文C，私钥d
1. 从C中提取C1并转换为点
2. 计算S = d·C1
3. 计算t = KDF(x2||y2, klen)
4. 计算M' = C2 ⊕ t
5. 验证C3 = Hash(x2||M'||y2)
输出：明文M'
 ```
5. **签名流程**：
 ```
 输入：消息M，私钥d
1. 计算Z = Hash(ENTL||ID||曲线参数||公钥)
2. 计算e = Hash(Z||M)
3. 生成随机数k∈[1, n-1]
4. 计算(x1, y1) = k·G
5. 计算r = (e + x1) mod n
6. 计算s = ((1+d)⁻¹·(k - r·d)) mod n
输出：签名(r, s)
 ```

6. **验签流程**：
 ```
 输入：消息M，签名(r,s)，公钥P
1. 验证r,s ∈ [1, n-1]
2. 计算Z = Hash(ENTL||ID||曲线参数||公钥)
3. 计算e = Hash(Z||M)
4. 计算t = (r + s) mod n
5. 计算(x1, y1) = s·G + t·P
6. 验证R = (e + x1) mod n == r
输出：验证结果
```
## 三、优化原理与过程
### 1. 优化思路

#### (1) 坐标系统优化

-   **问题**：仿射坐标需要频繁模逆运算，计算代价高
    
-   **解决方案**：使用Jacobian投影坐标
    
    -   将点表示为(X,Y,Z)，其中x=X/Z², y=Y/Z³
        
    -   避免点运算中的模逆运算
        
    -   点加法和点倍乘效率提升3-5倍
        

#### (2) 标量乘法优化

-   **问题**：double-and-add算法效率低(O(n))
    
-   **解决方案**：  
    a.  **窗口法**：
    
    -   预计算常用倍点(如4-bit窗口预计算1-15倍点)
        
    -   减少点加操作次数35-50%  
        b.  **NAF表示法**：
        
    -   使用非相邻形式表示标量
        
    -   减少非零位数量，减少点加操作
        

#### (3) 预计算优化

-   **问题**：基点G的标量乘法频繁使用
    
-   **解决方案**：
    
    -   初始化时预计算G的倍点表
        
    -   运行时直接查表减少计算量
        
    -   特别适合签名操作(多次使用相同基点)
        

#### (4) 常数时间实现

-   **问题**：基础实现在时间/功耗上可能泄露信息
    
-   **解决方案**：
    
    -   固定时间执行路径
        
    -   避免分支依赖秘密数据
        
    -   使用恒定时间算法实现模运算
        

#### (5) 内存与计算优化

-   **模运算优化**：蒙哥马利约减
    
-   **循环展开**：减少循环开销
    
-   **批处理**：同时处理多个点运算

### 2. 优化实现

#### (1) Jacobian坐标系统实现
```python
def _point_double_jacobian(self, X, Y, Z):
    """Jacobian坐标点倍乘"""
    if Y == 0:
        return (0, 0, 0)
    Y2 = (Y * Y) % self.p
    S = (4 * X * Y2) % self.p
    M = (3 * X * X + self.a * pow(Z, 4, self.p)) % self.p
    X3 = (M * M - 2 * S) % self.p
    Y3 = (M * (S - X3) - 8 * pow(Y2, 2, self.p)) % self.p
    Z3 = (2 * Y * Z) % self.p
    return (X3, Y3, Z3)

def _point_add_jacobian(self, X1, Y1, Z1, X2, Y2, Z2):
    """Jacobian坐标点加法"""
    if Z1 == 0:
        return (X2, Y2, Z2)
    if Z2 == 0:
        return (X1, Y1, Z1)
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
    H = (U2 - U1) % self.p
    R = (S2 - S1) % self.p
    H2 = (H * H) % self.p
    H3 = (H * H2) % self.p
    X3 = (R * R - H3 - 2 * U1 * H2) % self.p
    Y3 = (R * (U1 * H2 - X3) - S1 * H3) % self.p
    Z3 = (H * Z1 * Z2) % self.p
    return (X3, Y3, Z3)
```
#### (2) 窗口法标量乘法
```python
def _scalar_mult_window(self, k, point, window_size=4):
    """窗口法标量乘法"""
    # 预计算表
    table = self._precompute_points(point, window_size)
    
    result = (0, 0)
    k_bin = bin(k)[2:]
    i = 0
    while i < len(k_bin):
        if k_bin[i] == '0':
            result = self._point_double(result)
            i += 1
        else:
            j = min(window_size, len(k_bin) - i)
            window_val = int(k_bin[i:i+j], 2)
            for _ in range(j):
                result = self._point_double(result)
            if window_val > 0:
                result = self._point_add(result, table[window_val])
            i += j
    return result

def _precompute_points(self, point, window_size):
    """预计算倍点表"""
    table = {}
    table[1] = point
    table[2] = self._point_double(point)
    for i in range(3, 1 << window_size):
        table[i] = self._point_add(table[i-1], table[1])
    return table
```
#### (3) 常数时间实现
```python
def _ct_scalar_mult(self, k, point):
    """常数时间标量乘法"""
    # 将点转换为Jacobian坐标
    X, Y = point
    Z = 1
    result = (0, 0, 0)
    
    # 标量的二进制表示
    k_bin = bin(k)[2:].zfill(256)  # 固定长度
    
    for bit in k_bin:
        # 恒定时间加倍
        result = self._point_double_jacobian(*result)
        
        # 恒定时间条件加法
        temp = self._point_add_jacobian(*result, X, Y, Z)
        # 使用位选择而不是条件分支
        mask = 1 if bit == '1' else 0
        result = (
            (mask * temp[0] + (1 - mask) * result[0]) % self.p,
            (mask * temp[1] + (1 - mask) * result[1]) % self.p,
            (mask * temp[2] + (1 - mask) * result[2]) % self.p
        )
    
    return self._jacobian_to_affine(*result)
```
#### (4) 蒙哥马利模约减
```python
def _montgomery_reduce(self, a):
    """蒙哥马利模约减"""
    # 假设已设置蒙哥马利常数R = 2^256 mod p
    # 实际实现需要预计算参数
    m = (a * self.mont_inv) & ((1 << 256) - 1)
    t = (a + m * self.p) >> 256
    if t >= self.p:
        t -= self.p
    return t
```

## 四、实验结论
基础实现的结果和优化后的结果分别如project5-a 基础实现结果、project5-a 优化结果所示，优化效果如下：
|操作|基础实现（ms）|优化实现（ms）|加速比|
|-|-|-|-|
|密钥生成|13.8|13.1|1.05x|
|加密|27.1|13.1|2.06x|
|解密|13.3|2.5|5.32x|
|签名|24.9|21.1|1.18x|
|验签|26.2|13.3|1.97x|

# Project5-b SM2签名算法误用分析及POC验证

## 一、误用场景分析
### 1. 同一个用户重复使用随机数k

**推导过程**：
```
签名方程：
s1 = (1 + dA)^(-1) * (k - r1 * dA) mod n
s2 = (1 + dA)^(-1) * (k - r2 * dA) mod n
变换：
s1(1 + dA) = k - r1 * dA
s2(1 + dA) = k - r2 * dA
相减：
(s1 - s2)(1 + dA) = (r2 - r1)dA
展开：
s1 - s2 + (s1 - s2)dA = (r2 - r1)dA
整理：
s1 - s2 = dA[(r2 - r1) - (s1 - s2)]
推导出私钥：
dA = (s1 - s2) / [(r2 - r1) - (s1 - s2)] mod n
```
### 2. 不同用户使用相同的随机数k

**推导过程**：
```
Alice的签名：
s1 = (1 + dA)^(-1) * (k - r1 * dA) mod n
Bob的签名：
s2 = (1 + dB)^(-1) * (k - r2 * dB) mod n
对于Bob的签名变换：
s2(1 + dB) = k - r2 * dB
k = s2(1 + dB) + r2 * dB
k = s2 + (s2 + r2)dB
推导出Bob的私钥：
dB = (k - s2) / (s2 + r2) mod n
```
### 3. 相同私钥d和随机数k同时用于SM2和ECDSA

**推导过程**：
```
ECDSA签名：
s1 = (h1 + r1 * d) * k^(-1) mod n
SM2签名：
s2 = (1 + d)^(-1) * (k - r2 * d) mod n
变换ECDSA方程：
k = (h1 + r1 * d) * s1^(-1) 
代入SM2方程：
s2 = (1 + d)^(-1) * [(h1 + r1 * d)s1^(-1) - r2 * d]
两边乘以(1 + d):
s2(1 + d) = (h1 + r1 * d)s1^(-1) - r2 * d
整理：
s2 + s2d = h1/s1 + (r1/s1)d - r2d
s2 - h1/s1 = d(r1/s1 - r2 - s2)
推导出私钥：
d = (s2 - h1/s1) / (r1/s1 - r2 - s2) mod n
```

## 二、验证结果说明

### 1. 同一个用户重复使用k

当同一个用户使用相同的随机数k对两个不同消息进行签名时，攻击者可以通过两个签名推导出用户的私钥。这是因为两个签名方程共享相同的k值，形成可解的方程组。

**防御措施**：每次签名必须使用密码学安全的随机数生成器生成唯一的k值。

### 2. 不同用户使用相同的k

当两个不同用户使用相同的随机数k进行签名时，他们可以相互推导出对方的私钥。这是因为k值相同导致签名方程中出现关联。

**防御措施**：确保不同用户使用独立的随机数生成源，避免k值重复。

### 3. 相同私钥和k用于SM2和ECDSA

当用户使用相同的私钥d和随机数k分别进行SM2和ECDSA签名时，攻击者可以通过两个签名推导出私钥。这是因为两种签名算法结构不同，但共享相同的d和k值。

**防御措施**：

1.  不要在不同密码系统中重用私钥
    
2.  使用确定性签名方案(RFC 6979)
    
3.  为不同系统使用独立的随机数生成源



# Project5-c 伪造中本聪的数字签名
## 一、实验背景
中本聪在比特币系统中所设计的数字签名机制，是保障交易安全与去中心化信任的核心技术之一，其底层依赖椭圆曲线加密算法（ECDSA，具体采用 secp256k1 曲线，而非传统的 RSA 等算法，这一选择兼顾了安全性与计算效率。
### 特点

-   **非对称加密**：私钥签名，公钥验证，无需暴露私钥即可完成身份确认。
-   **不可伪造性**：在计算上无法通过公钥或交易信息伪造出有效的私钥签名。
-   **与交易绑定**：签名直接关联具体交易内容，一旦交易被修改，签名立即失效。

## 二、实验原理
ECDSA签名伪造的核心漏洞在于**随机数k的重用**。当同一个私钥使用相同的k值对两个不同消息进行签名时，攻击者可以通过数学推导恢复私钥：

1.  **签名过程**：
    
    -   签名1：s₁ = k⁻¹(e₁ + d·r) mod n
        
    -   签名2：s₂ = k⁻¹(e₂ + d·r) mod n  
        （其中e是消息哈希，d是私钥，r是临时公钥的x坐标）
        
2.  **推导过程**：
    
    -   (s₁ - s₂) = k⁻¹(e₁ - e₂) mod n
        
    -   k = (e₁ - e₂)(s₁ - s₂)⁻¹ mod n
        
    -   d = (s₁·k - e₁)r⁻¹ mod n
        
3.  **伪造签名**：
    
    -   使用恢复的私钥d和k值，可对任意消息生成有效签名
## 三、实现具体过程
#### 1. 椭圆曲线运算类
```python
class EllipticCurve:
    def __init__(self, p, a, b):
        self.p = p  # 素数域
        self.a = a  # 曲线参数a
        self.b = b  # 曲线参数b
    
    def point_addition(self, P, Q):
        # 处理无穷远点
        if P == "O": return Q
        if Q == "O": return P
        
        x1, y1 = P
        x2, y2 = Q
        
        # 点加倍(P=Q)
        if P == Q:
            if y1 == 0: return "O"  # 无穷远点
            lam = (3*x1*x1 + self.a) * self.modular_inverse(2*y1)
        
        # 点相加(P≠Q)
        else:
            if x1 == x2: return "O"  # 垂直切线
            lam = (y2 - y1) * self.modular_inverse(x2 - x1)
        
        lam %= self.p
        x3 = (lam*lam - x1 - x2) % self.p
        y3 = (lam*(x1 - x3) - y1) % self.p
        return (x3, y3)
    
    def scalar_multiplication(self, k, point):
        # 快速倍点算法
        result = "O"
        current = point
        while k:
            if k & 1:
                result = self.point_addition(result, current)
            current = self.point_addition(current, current)
            k >>= 1
        return result
    
    def modular_inverse(self, a):
        # 费马小定理求模逆
        return pow(a, self.p-2, self.p)
```
#### 2. ECDSA签名类
```python
class ECDSA:
    def __init__(self, curve, n, G):
        self.curve = curve  # 椭圆曲线对象
        self.n = n          # 基点阶数
        self.G = G          # 基点
    
    def sign(self, d, k, message):
        # 生成签名
        R = self.curve.scalar_multiplication(k, self.G)
        r = R[0] % self.n
        e = self.hash_message(message)
        s = (self.modular_inverse(k) * (e + d * r)) % self.n
        return (r, s)
    
    def verify(self, pub_key, message, signature):
        # 验证签名
        r, s = signature
        e = self.hash_message(message)
        w = self.modular_inverse(s)
        u1 = (e * w) % self.n
        u2 = (r * w) % self.n
        
        # 计算验证点
        P1 = self.curve.scalar_multiplication(u1, self.G)
        P2 = self.curve.scalar_multiplication(u2, pub_key)
        P = self.curve.point_addition(P1, P2)
        
        return P != "O" and P[0] % self.n == r
    
    def hash_message(self, message):
        # SHA256哈希计算
        return int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big') % self.n
    
    def modular_inverse(self, a):
        # 阶n下的模逆
        return pow(a, self.n-2, self.n)
```

#### 3. 签名伪造演示
```python
def forge_satoshi_signature():
    # 比特币secp256k1曲线参数
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a, b = 0, 7
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    
    # 创建曲线和ECDSA实例
    curve = EllipticCurve(p, a, b)
    ecdsa = ECDSA(curve, n, G)
    
    # 中本聪的私钥和重复使用的k
    satoshi_d = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
    k = 0x3A780
    
    # 生成两个真实签名
    msg1 = "无论沧桑岁月长 哪怕海角与天涯"
    msg2 = "魂牵梦萦的眷恋 我的山大我的家"
    sig1 = ecdsa.sign(satoshi_d, k, msg1)
    sig2 = ecdsa.sign(satoshi_d, k, msg2)
    
    # 从签名恢复私钥
    r1, s1 = sig1
    r2, s2 = sig2
    e1 = ecdsa.hash_message(msg1)
    e2 = ecdsa.hash_message(msg2)
    
    # 计算恢复的k和私钥
    k_recovered = ((e1 - e2) * pow(s1 - s2, n-2, n)) % n
    d_recovered = ((s1 * k_recovered - e1) * pow(r1, n-2, n)) % n
    
    # 使用恢复的私钥伪造新签名
    forged_msg = "那是我的家 朴实又美丽"
    forged_sig = ecdsa.sign(d_recovered, k_recovered, forged_msg)
    
    # 验证伪造的签名
    satoshi_pub = curve.scalar_multiplication(satoshi_d, G)
    is_valid = ecdsa.verify(satoshi_pub, forged_msg, forged_sig)
```
## 四、实验结果
如图project5-c 结果所示，伪造中本聪的数字签名成果。
