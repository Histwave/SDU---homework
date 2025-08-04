# Project1-a SM4的软件实现和优化
## 一、引言
SM4算法是用于WAPI的分组密码算法，是2006年我国国家密码管理局公布的国内第一个商用密码算法，原名SMS4，2012年正式成为国家标准（GB/T 32907-2016），2021年成为国际标准（ISO/IEC 18033-3:2021/AMD1:2021）。

SM4算法的设计目标是替代国际通用的AES算法，适用于无线局域网、金融支付、物联网等场景的数据加密。
## 二、SM4加密过程
###  密钥扩展：
-   将128位的初始密钥通过密钥扩展算法生成32个32位的轮密钥。
-   密钥扩展过程中使用了固定参数（CK）和系统参数（FK），确保密钥与轮函数之间的强关联性。
### 轮函数（F函数）：
-   每轮迭代使用一个轮密钥，通过非线性变换（S盒）和线性变换（L函数）对数据进行处理。
-   S盒替换：将8位输入通过复合域S盒进行非线性替换，增强抗差分攻击能力。
-   线性变换：包括循环左移和异或操作，实现数据的高分支数扩散
### 加密过程：
-   将128位的明文分组分为4个32位的字（X₀, X₁, X₂, X₃）。
-   通过32轮迭代，每轮使用一个轮密钥，生成新的中间状态。
-   最后一轮后，将4个字逆序拼接，得到128位的密文。
## 三、基础SM4实现
### 密钥扩展

-   输入：128位密钥（16字节）
    
-   步骤：  
    a. 将密钥分成4个32位字：MK₀, MK₁, MK₂, MK₃  
    b. 与系统参数FK异或：Kᵢ = MKᵢ ⊕ FKᵢ (i=0-3)  
    c. 32轮迭代生成轮密钥：
   
    -   rk[i] = Kᵢ ⊕ T'(Kᵢ₊₁ ⊕ Kᵢ₊₂ ⊕ Kᵢ₊₃ ⊕ CKᵢ)
        
    -   T'变换：S盒替换 + 线性变换L'（循环左移13/23位）
        
-   输出：32个32位轮密钥（rk[0]-rk[31]）
### 加密过程

-   输入：128位明文（16字节）
    
-   步骤：  
    a. 初始状态：将明文分成4个32位字：X₀, X₁, X₂, X₃  
    b. 32轮迭代：
    
    -   Xᵢ₊₄ = Xᵢ ⊕ T(Xᵢ₊₁ ⊕ Xᵢ₊₂ ⊕ Xᵢ₊₃ ⊕ rk[i])
        
    -   T变换：S盒替换 + 线性变换L（循环左移2/10/18/24位）  
        c. 反序输出：Y = (X₃₅, X₃₄, X₃₃, X₃₂)
        
-   输出：128位密文
    
### 核心组件实现

1.  S盒替换：
    
   ```cpp 
    uint32_t b0 = Sbox[(x >> 24) & 0xFF];
    uint32_t b1 = Sbox[(x >> 16) & 0xFF];
    uint32_t b2 = Sbox[(x >> 8) & 0xFF];
    uint32_t b3 = Sbox[x & 0xFF];
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
  ```
    
2.  线性变换L（加密轮函数）：
```cpp
    return s ^ rotl(s, 2) ^ rotl(s, 10) ^ rotl(s, 18) ^ rotl(s, 24);
```
    
3.  线性变换L'（密钥扩展）：
    
```cpp
    return s ^ rotl(s, 13) ^ rotl(s, 23);
```
4.  循环左移：
   
```cpp
    return (x << n) | (x >> (32 - n));
```
## 四、利用T-table优化SM4
### 原理
T-table 优化是一种通过**空间换时间**的软件优化方法，核心思想是预计算 SM4 算法中最耗时的非线性变换和线性变换组合结果：

- T 函数包含 S 盒替换（非线性变换）和循环左移异或（线性变换），这两个步骤在每次加密迭代中都需要执行。提前计算 S 盒中所有 256 个可能输入值经过完整 T 函数（S 盒替换 + 线性变换）后的结果。将这些结果存储在一个 256 项的表（T-table）中。

- 加密时直接查表获取结果，避免了实时计算 S 盒替换和线性变换，减少了约 50% 的计算量，无需特殊硬件支持，时间复杂度从 O (n) 降低为 O (1)（对于 T 函数操作）
### 具体实现
-   **T-table 初始化**：`initTTable`函数对 0~255 所有字节，预计算其经过 S 盒替换和线性变换后的 32 位结果，存储在`T_table`数组中。
```cpp
void initTTable() {
    for (int i = 0; i < 256; i++) {
        uint32_t x = Sbox[i];
        T_table[i] = x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24);
    }
}
```
-   **优化的 T 函数**：`T_table_opt`直接从`T_table`中读取每个字节的预计算结果，组合后得到最终值（无需实时执行 S 盒替换和线性变换）。
```cpp
inline uint32_t T_table_opt(uint32_t x) {
    return T_table[(x >> 24) & 0xFF] ^
        (T_table[(x >> 16) & 0xFF] << 8) ^
        (T_table[(x >> 8) & 0xFF] << 16) ^
        (T_table[x & 0xFF] << 24);
}
```
-   **密钥扩展与加密**：`keyExpansionTTable`和`sm4EncryptTTable`分别替换基础版本中的 T 函数为`T_table_opt`，通过查表加速计算。
```cpp
void keyExpansionTTable(const uint8_t* key, uint32_t rk[32]) {
    uint32_t MK[4];
    for (int i = 0; i < 4; i++) {
        MK[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    uint32_t K[36];
    K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];

    for (int i = 0; i < 32; i++) {
        K[i + 4] = K[i] ^ T_table_opt(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        rk[i] = K[i + 4];
    }
}

// T-table优化的加密函数
void sm4EncryptTTable(const uint8_t* plaintext, const uint32_t rk[32], uint8_t* ciphertext) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = (plaintext[4 * i] << 24) | (plaintext[4 * i + 1] << 16) | (plaintext[4 * i + 2] << 8) | plaintext[4 * i + 3];
    }

    for (int i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ T_table_opt(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    }

    for (int i = 0; i < 4; i++) {
        uint32_t val = X[35 - i];
        ciphertext[4 * i] = (val >> 24) & 0xFF;
        ciphertext[4 * i + 1] = (val >> 16) & 0xFF;
        ciphertext[4 * i + 2] = (val >> 8) & 0xFF;
        ciphertext[4 * i + 3] = val & 0xFF;
    }
}
```
## 五、利用AES-NI优化SM4
### 原理
AES-NI（AES 指令集）是 Intel/AMD 处理器提供的专用加密指令集，通过硬件加速实现 SM4 优化：

- 使用`_mm_aesenc_si128`指令模拟 SM4 的 S 盒替换（AES 加密指令中的字节替换与 SM4 的 S 盒原理相似），利用 128 位向量寄存器（`__m128i`）同时处理 4 个 32 位数据块，通过`_mm_slli_epi32`和`_mm_srli_epi32`等向量指令高效实现循环左移。
-  一次操作可处理 128 位数据（SM4 分组大小），相比标量实现提高了数据吞吐量，所有运算在寄存器内完成，减少内存访问开销。
- 相比基础版本可获得 3-5 倍加速，需支持 AES-NI 的 CPU（2010 年后的大部分处理器）
### 具体实现
-   **优化的 T 函数**：`T_aesni`使用`_mm_aesenc_si128`（AES 加密指令）模拟 S 盒替换（通过空密钥加密实现），再用`_mm_slli_epi32`和`_mm_srli_epi32`并行实现循环左移，最后通过 SIMD 异或指令组合结果。
```cpp
inline __m128i T_aesni(__m128i x) {
    // 使用AES指令进行S盒替换
    __m128i s = _mm_aesenc_si128(x, _mm_setzero_si128());

    // 线性变换 - 使用AESNI指令进行循环移位
    __m128i s2 = _mm_or_si128(_mm_slli_epi32(s, 2), _mm_srli_epi32(s, 30));
    __m128i s10 = _mm_or_si128(_mm_slli_epi32(s, 10), _mm_srli_epi32(s, 22));
    __m128i s18 = _mm_or_si128(_mm_slli_epi32(s, 18), _mm_srli_epi32(s, 14));
    __m128i s24 = _mm_or_si128(_mm_slli_epi32(s, 24), _mm_srli_epi32(s, 8));

    return _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(s, s2), s10), _mm_xor_si128(s18, s24));
}
```
-   **密钥扩展与加密**：`keyExpansionAESNI`和`sm4EncryptAESNI`使用 128 位 SIMD 寄存器（`__m128i`）存储数据，通过向量指令并行处理 4 个 32 位字的运算，减少循环次数和内存访问。
```cpp
void keyExpansionAESNI(const uint8_t* key, __m128i rk[32]) {
    __m128i MK = _mm_loadu_si128((const __m128i*)key);
    __m128i FK_vec = _mm_set_epi32(FK[3], FK[2], FK[1], FK[0]);
    __m128i K[36];

    K[0] = _mm_xor_si128(MK, FK_vec);
    K[1] = _mm_shuffle_epi32(K[0], _MM_SHUFFLE(0, 3, 2, 1));
    K[2] = _mm_shuffle_epi32(K[1], _MM_SHUFFLE(0, 3, 2, 1));
    K[3] = _mm_shuffle_epi32(K[2], _MM_SHUFFLE(0, 3, 2, 1));

    for (int i = 0; i < 32; i++) {
        __m128i ck = _mm_set_epi32(0, 0, 0, CK[i]);
        __m128i temp = _mm_xor_si128(_mm_xor_si128(K[i + 1], K[i + 2]), _mm_xor_si128(K[i + 3], ck));
        K[i + 4] = _mm_xor_si128(K[i], T_aesni(temp));
        rk[i] = K[i + 4];
    }
}

// AESNI优化的加密函数
void sm4EncryptAESNI(const uint8_t* plaintext, const __m128i rk[32], uint8_t* ciphertext) {
    __m128i X = _mm_loadu_si128((const __m128i*)plaintext);
    __m128i X1 = _mm_shuffle_epi32(X, _MM_SHUFFLE(0, 3, 2, 1));
    __m128i X2 = _mm_shuffle_epi32(X1, _MM_SHUFFLE(0, 3, 2, 1));
    __m128i X3 = _mm_shuffle_epi32(X2, _MM_SHUFFLE(0, 3, 2, 1));

    for (int i = 0; i < 32; i++) {
        __m128i temp = _mm_xor_si128(_mm_xor_si128(X1, X2), _mm_xor_si128(X3, rk[i]));
        __m128i newX = _mm_xor_si128(X, T_aesni(temp));

        X = X1;
        X1 = X2;
        X2 = X3;
        X3 = newX;
    }

    __m128i result = _mm_shuffle_epi32(_mm_xor_si128(_mm_xor_si128(X, X1), _mm_xor_si128(X2, X3)),
        _MM_SHUFFLE(1, 0, 3, 2));
    _mm_storeu_si128((__m128i*)ciphertext, result);
}
```
## 六、利用GFNI优化SM4
### 原理
GFNI（Galois Field New Instructions）是较新的处理器指令集（2019 年后支持），专为有限域运算设计，对 SM4 优化更直接：

-   使用`_mm_gf2p8affine_epi64_epi8`指令直接实现 SM4 的 S 盒替换，无需像 AES-NI 那样模拟，配合`_mm_rol_epi32`（VPROLD 指令）直接完成循环左移，比 AES-NI 的移位组合更高效。
- GFNI 指令原生支持伽罗瓦域内的仿射变换，与 SM4 的 S 盒数学原理完全匹配，单条指令即可完成 8 字节的并行替换，效率高于 AES-NI 的模拟实现。
- 相比 AES-NI 优化可再提升 30-50%，是目前 SM4 软件实现的最优方案之一。
### 具体实现
-   **优化的 T 函数**：`T_gfni`使用`_mm_gf2p8affine_epi64_epi8`（GFNI 指令）直接完成 8 字节并行 S 盒替换，再用`_mm_rol_epi32`（VPROLD 指令）高效实现 32 位字的循环左移，最后通过 SIMD 异或组合结果。
```cpp
inline __m128i T_gfni(__m128i x) {
    // 使用GFNI指令进行S盒替换
    __m128i mask = _mm_set1_epi64x(0x8000000000000000);
    __m128i s = _mm_gf2p8affine_epi64_epi8(x, mask, 1);

    // 使用VPROLD指令进行循环左移
    __m128i s2 = _mm_rol_epi32(s, 2);
    __m128i s10 = _mm_rol_epi32(s, 10);
    __m128i s18 = _mm_rol_epi32(s, 18);
    __m128i s24 = _mm_rol_epi32(s, 24);

    return _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(s, s2), s10), _mm_xor_si128(s18, s24));
}
```
-   **密钥扩展与加密**：`keyExpansionGFNI`和`sm4EncryptGFNI`基于 GFNI 指令集特性，进一步提升并行处理效率，相比 AESNI 优化减少了模拟 S 盒的开销。
## 七、实验结果
- 实验结果如project1-a结果.png所示，明文：01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10、密钥：01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10。密文68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46正确。
- T-table优化加速了三倍以上，但内存访问开销增大；AES-NI优化显著减小了内存访问开销；GFNI优化在速度和内存访问开销上都提升很多。
# Project1-b SM4-GCM工作模式的软件优化实现
## 引言

## 优化原理与介绍

