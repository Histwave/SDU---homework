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



