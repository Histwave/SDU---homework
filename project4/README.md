# Project4-a SM3的软件实现与优化 
## 一、实验背景
SM3 算法是中国国家密码管理局发布的消息摘要算法，全称为 “商用密码 SM3 杂凑算法”。2010 年正式发布，2016 年发布了正式的国家标准 GB/T 32905-2016。它类似于国际上广泛应用的 SHA-256 算法，具有中国自主知识产权，用于提供数据完整性校验和安全性认证。以下是具体介绍：
-   **算法原理**：
    -   **消息填充**：将输入消息填充至长度为 512 位的倍数。具体是先在消息末尾添加比特 “1”，再添加若干比特 “0”，使消息长度对 512 取模余 448，最后再添加一个 64 位比特串，用于表示原始消息的长度。
    -   **消息扩展**：对填充后的消息进行扩展，将每个 512 位的消息分组扩展成 132 个 32 位的字，用于后续的迭代压缩运算。
    -   **迭代压缩**：将扩展后的消息分块并逐块迭代压缩，通过特定的压缩函数进行 64 轮迭代运算，最后输出 256 位的摘要。
-   **算法特点**：
    -   **抗碰撞性**：通过优化的消息扩展和压缩算法，SM3 提高了抗碰撞能力，能有效抵抗碰撞攻击，其设计抗碰撞能力达到\(2^{128}\)。
    -   **抗篡改性**：输出的 256 位摘要长度及算法特性，使得 SM3 能敏锐地检测数据是否被篡改，只要数据有任何变动，生成的摘要就会截然不同。
    -   **高效性**：SM3 算法在硬件和软件上都能实现高效的摘要计算，无论是在普通计算机上，还是各种嵌入式系统和移动设备中，都能快速执行。
-   **应用场景**：
    -   **数字签名**：可作为数字签名算法的一部分，用于生成消息摘要并参与签名过程。例如在基于 SM2 的签名体系中，通常先使用 SM3 对消息进行摘要，然后再使用 SM2 进行签名。
    -   **身份认证**：在用户登录等场景中，可对用户密码进行 SM3 哈希处理，将哈希值存储在服务器中。用户登录时，输入的密码同样经过 SM3 哈希后与服务器中的值对比，以此验证密码正确性。
    -   **电子支付**：可用于对交易明细等重要信息进行哈希计算，确保交易数据的完整性与不可篡改性，保障电子支付的安全。
    -   **区块链领域**：常用于区块数据的哈希计算和链上数据的完整性验证，有助于维护区块链的安全和稳定。

## 二、SM3实现思路与过程
### 实现思路
1.  **数据预处理（消息填充）**
    
    -   首先计算原始消息的比特长度，将其转换为 64 位无符号整数
    -   在消息末尾追加一个 "1" 比特，再填充若干 "0" 比特，使总长度模 512 等于 448
    -   最后追加 64 位原始消息长度（小端或大端需符合标准）
2.  **消息分组与扩展**
    
    -   将填充后的消息按 512 位分组，逐组处理
    -   每组扩展为 132 个 32 位字：前 68 个通过特定变换生成，后 64 个由前 68 个计算得出
    -   扩展过程需实现 P0、P1 等置换函数，以及循环左移等操作
3.  **迭代压缩**
    
    -   初始化 8 个 32 位寄存器（IV 值固定）
    -   对每个 512 位分组进行 64 轮压缩运算，每轮使用不同的常量和扩展字
    -   实现压缩函数中的布尔函数（FF、GG）和置换函数（P0、P1）
    -   每轮更新寄存器状态，完成一组处理后与原始寄存器值相加
4.  **结果输出**
    
    -   所有分组处理完成后，将 8 个寄存器的值按顺序拼接
    -   转换为 64 位十六进制字符串，即为最终的 256 位哈希值
 
### 实现过程
### 1. 初始化

设置8个32位初始状态值（IV）：
```cpp
state[0] = 0x7380166F;
state[1] = 0x4914B2B9;
// ... 其他状态值
```
### 2. 消息填充

-   添加比特"1"（0x80字节）
    
-   填充0直到长度满足 mod 512 = 448
    
-   添加64位消息长度（大端序）

### 3. 消息扩展
```cpp
for (int i = 0; i < 16; ++i) {
    W[i] = (block[i*4+0] << 24) | ...;
}

for (int i = 16; i < 68; ++i) {
    W[i] = P1(W[i-16] ^ W[i-9] ^ ROTL(W[i-3], 15)) ^ ...;
}
```
### 4. 压缩函数（64轮迭代）
```cpp
for (int j = 0; j < 64; ++j) {
    // 计算SS1, SS2
    // 根据轮次选择布尔函数
    // 更新工作变量A-H
}
```

### 5. 更新状态
```cpp
state[0] ^= A; state[1] ^= B; ...;
```
### 6. 输出哈希值

将8个32位状态值转换为32字节大端序输出
## 三、优化思路与过程
### 优化思路

1.  **减少寄存器置换**：
    
    -   4轮展开避免每轮寄存器移位
        
    -   保持状态变量位置相对固定
        
2.  **提高指令级并行**：
    
    -   展开循环减少分支预测失败
        
    -   减少数据依赖链
        
3.  **优化消息扩展**：
    
    -   使用SIMD并行计算（原方案）
        
    -   减少中间变量存储
        
4.  **内存访问优化**：
    
    -   优先使用寄存器而非内存
        
    -   减少不必要的内存读写
        
5.  **循环展开**：
    
    -   4轮一组处理，减少循环开销
        
    -   平衡代码大小和性能
### 优化实现过程

### 1. 4轮展开压缩函数
```cpp
for (int j = 0; j < 64; j += 4) {
    // 第1轮计算...
    // 第2轮计算...
    // 第3轮计算...
    // 第4轮计算...
}
```
-   减少75%的寄存器置换操作
    
-   保持寄存器位置相对稳定
### 2. 布尔函数动态选择
```cpp
bool useFF0 = (j < 16);
uint32_t TT1 = useFF0 ? 
    (FF0(A, B, C) + ...) :
    (FF1(A, B, C) + ...);
```
-   根据轮次动态选择布尔函数
    
-   保持算法正确性
### 3. 循环移位优化
```cpp
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
```
-   单表达式完成循环移位
    
-   避免分支和函数调用
### 4. 减少内存访问
```cpp
uint32_t A = state[0], B = state[1], ...;
// ... 计算过程 ...
state[0] ^= A; state[1] ^= B; ...;
```
-   使用局部变量减少类成员访问
    
-   CPU寄存器访问快于内存访问
## 四、实验结果
如图project4-a 结果.png所示，优化效果明显。


# Project4-b 基于sm3的实现，验证length-extension attack

## 一、实验背景
SM3 的长度扩展攻击是一种针对 SM3 哈希算法的安全威胁，它基于 SM3 的 Merkle Damgard 结构特性展开。以下是具体介绍：
-   **攻击原理**：长度扩展攻击是指攻击者利用已知数据的散列值，在不知道原始数据具体内容的情况下，计算出原数据外加一段延展数据后的散列值。对于 SM3 算法，如果知道 h (S|M)（S 为机密数据，M 为公开数据），就可以计算 h (S|M|N)，其中 N 是追加的延展数据。
-   **攻击条件**：当 SM3 用于计算 HMAC（哈希消息认证码）时，若攻击者仅知道密钥 k 的长度、消息 m1 及其对应的 HMAC1 值，就具备了实施长度扩展攻击的条件。
-   **攻击步骤**：假设攻击者已知密钥 k 的长度、原消息 m1 和对应的 HMAC1，预期扩展消息 m2。首先，攻击者根据 k 的长度和 m1 的长度计算出 hmac1 计算过程中的填充值 padding1。然后，构造 k||m1||padding1||m2，并计算出消息 m2 需填充的 padding2。接着，将 hmac1 作为初始状态值，对 m2||padding2 进行迭代计算，得到扩展后的哈希值 hmac2，即得到消息 m1||padding1||m2 采用原 k 计算出的 hmac2 值。
## 二、实验原理
### SM3算法基础

SM3是中国国家密码管理局发布的商用密码哈希算法，采用Merkle-Damgård结构，包含以下关键组件：

-   **填充规则**：消息末尾添加比特"1"，然后添加k个"0"，最后添加64位消息长度
    
-   **压缩函数**：处理512位消息块，更新8个32位状态变量
    
-   **迭代结构**：将消息分块，每个块通过压缩函数处理，前一块的输出作为下一块的输入
    

### 长度扩展攻击原理

长度扩展攻击利用Merkle-Damgård结构的特性：

1.  **最终状态暴露**：哈希值H(m)实际上是处理完消息m后的内部状态
    
2.  **状态重用**：攻击者可以使用H(m)作为新的初始向量(IV)
    
3.  **填充可预测**：知道原始消息长度后，可以正确计算填充块
    
4.  **扩展计算**：从H(m)开始，继续处理任意附加消息m2
    

攻击者无需知道原始消息m1，只需知道：

-   H(m1) - 原始消息的哈希值
    
-   len(m1) - 原始消息长度
    
-   要附加的消息m2
    

即可伪造H(m1 || padding || m2)
## 三、具体过程
### 1. 核心组件实现

#### 字节序处理函数
```cpp
// 32位整数大小端转换
inline uint32_t swap_uint32(uint32_t val) {
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | (val >> 16);
}

// 64位整数大小端转换
inline uint64_t swap_uint64(uint64_t val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}
```
#### SM3压缩函数
```cpp
void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    // 消息扩展
    uint32_t w[68], w1[64];
    for (int i = 0; i < 16; i++) {
        uint32_t val;
        memcpy(&val, block + i * 4, 4);
        w[i] = swap_uint32(val);
    }
    
    for (int i = 16; i < 68; i++) {
        w[i] = p1(w[i-16] ^ w[i-9] ^ left_rotate(w[i-3], 15)) 
                ^ left_rotate(w[i-13], 7) ^ w[i-6];
    }
    
    for (int i = 0; i < 64; i++) {
        w1[i] = w[i] ^ w[i+4];
    }
    
    // 迭代压缩
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    
    for (int j = 0; j < 64; j++) {
        uint32_t t1 = left_rotate(a, 12);
        uint32_t ss1 = left_rotate(t1 + e + left_rotate((j < 16) ? T1 : T2, j % 32), 7);
        uint32_t ss2 = ss1 ^ t1;
        uint32_t tt1 = ff(a, b, c, j) + d + ss2 + w1[j];
        uint32_t tt2 = gg(e, f, g, j) + h + ss1 + w[j];
        
        d = c;
        c = left_rotate(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = left_rotate(f, 19);
        f = e;
        e = p0(tt2);
    }
    
    // 更新状态
    state[0] ^= a; state[1] ^= b; state[2] ^= c; state[3] ^= d;
    state[4] ^= e; state[5] ^= f; state[6] ^= g; state[7] ^= h;
}
```
#### 标准SM3哈希函数
```cpp
vector<uint8_t> sm3_hash(const vector<uint8_t>& msg) {
    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));
    
    uint64_t bit_len = msg.size() * 8;
    uint64_t bit_len_be = swap_uint64(bit_len);
    
    vector<uint8_t> padded = msg;
    padded.push_back(0x80); // 添加比特"1"
    
    // 计算并添加填充0
    size_t zero_padding = (56 - (msg.size() + 1) % 64) % 64;
    padded.insert(padded.end(), zero_padding, 0);
    
    // 添加消息长度
    uint8_t len_bytes[8];
    memcpy(len_bytes, &bit_len_be, 8);
    padded.insert(padded.end(), len_bytes, len_bytes + 8);
    
    // 处理消息块
    for (size_t i = 0; i < padded.size(); i += 64) {
        sm3_compress(state, &padded[i]);
    }
    
    // 转换状态为字节数组
    vector<uint8_t> hash(32);
    for (int i = 0; i < 8; i++) {
        uint32_t val = swap_uint32(state[i]);
        memcpy(&hash[i*4], &val, 4);
    }
    
    return hash;
}
```
### 2. 长度扩展攻击实现
```cpp
vector<uint8_t> length_extension_attack(const vector<uint8_t>& original_hash,
                                        uint64_t original_len_bits,
                                        const vector<uint8_t>& extension) {
    // 将原始哈希转换为状态变量
    uint32_t state[8];
    for (int i = 0; i < 8; i++) {
        uint32_t val;
        memcpy(&val, &original_hash[i*4], 4);
        state[i] = swap_uint32(val);
    }
    
    // 计算原始填充长度
    size_t padding_len_bits = (512 - (original_len_bits % 512) - 1 - 64) % 512;
    if (original_len_bits % 512 >= 448) {
        padding_len_bits += 512;
    }
    uint64_t total_len_bits = original_len_bits + 1 + padding_len_bits + 64;
    
    // 计算新消息总长度
    uint64_t new_total_bits = total_len_bits + extension.size() * 8;
    uint64_t new_total_bits_be = swap_uint64(new_total_bits);
    
    // 构造扩展消息的填充
    vector<uint8_t> padded = extension;
    padded.push_back(0x80);
    
    // 添加填充0
    size_t zero_padding = (56 - (extension.size() + 1) % 64) % 64;
    padded.insert(padded.end(), zero_padding, 0);
    
    // 添加新长度字段
    uint8_t len_bytes[8];
    memcpy(len_bytes, &new_total_bits_be, 8);
    padded.insert(padded.end(), len_bytes, len_bytes + 8);
    
    // 处理扩展消息
    for (size_t i = 0; i < padded.size(); i += 64) {
        sm3_compress(state, &padded[i]);
    }
    
    // 返回结果哈希
    vector<uint8_t> hash(32);
    for (int i = 0; i < 8; i++) {
        uint32_t val = swap_uint32(state[i]);
        memcpy(&hash[i*4], &val, 4);
    }
    
    return hash;
}
```
### 3. 验证流程
```cpp
int main() {
    // 原始消息
    vector<uint8_t> original_msg = {'s', 'e', 'c', 'r', 'e', 't'};
    
    // 计算原始哈希
    vector<uint8_t> original_hash = sm3_hash(original_msg);
    
    // 扩展消息
    vector<uint8_t> extension = {'a', 't', 't', 'a', 'c', 'k'};
    
    // 执行长度扩展攻击
    vector<uint8_t> attack_hash = length_extension_attack(
        original_hash, 
        original_msg.size() * 8, 
        extension
    );
    
    // 构造实际拼接消息
    vector<uint8_t> actual_msg = original_msg;
    actual_msg.push_back(0x80);
    size_t zero_padding = (56 - (original_msg.size() + 1) % 64) % 64;
    actual_msg.insert(actual_msg.end(), zero_padding, 0);
    uint64_t bit_len = original_msg.size() * 8;
    uint64_t bit_len_be = swap_uint64(bit_len);
    uint8_t len_bytes[8];
    memcpy(len_bytes, &bit_len_be, 8);
    actual_msg.insert(actual_msg.end(), len_bytes, len_bytes + 8);
    actual_msg.insert(actual_msg.end(), extension.begin(), extension.end());
    
    // 计算实际哈希
    vector<uint8_t> actual_hash = sm3_hash(actual_msg);
    
    // 验证结果
    if (attack_hash == actual_hash) {
        cout << "攻击成功!" << endl;
    } else {
        cout << "攻击失败" << endl;
    }
    
    return 0;
}
```
### 4.安全性影响与防御

### 攻击影响

长度扩展攻击允许攻击者：

1.  在不知道原始消息内容的情况下扩展消息
    
2.  伪造合法哈希值
    
3.  可能绕过某些基于哈希的认证机制
## 四、实验结果
如图project4-b 结果.png，验证通过，通过长度扩展攻击伪造合法的哈希值成功。

# Project4-c 构建Merkle树
## 一、实验背景
基于 SM3 哈希算法和 RFC6962 标准构建 Merkle 树（以 10 万叶子节点为例）的实现，核心在于遵循 RFC6962 对节点哈希计算的规范，并结合 SM3 的 256 位哈希特性完成树的逐层构建。
RFC6962 是证书透明度（Certificate Transparency）的标准，其中定义的 Merkle 树（又称 “Merkle 哈希树”）用于验证数据的存在性和完整性，核心规则包括：
-   **节点类型区分**：通过前缀字节区分叶子节点和内部节点，避免哈希碰撞：
    -    叶子节点：前缀为`0x00`（单字节`00`）；
    -   内部节点：前缀为`0x01`（单字节`01`）。
-   **树结构**：完全二叉树，若某层节点数为奇数，最后一个节点将被复制作为其右兄弟，确保上层节点数为整数。
## 二、实验原理
1.  **SM3实现**：
    
    -   完整实现SM3哈希算法
        
    -   符合国家标准GB/T 32905-2016
        
    -   支持任意长度输入数据
        
2.  **RFC6962兼容的Merkle树**：
    
    -   叶子节点使用前缀  `0x00`
        
    -   内部节点使用前缀  `0x01`
        
    -   处理奇数节点（最后一个节点与自己组合）
        
3.  **存在性证明**：
    
    -   生成从目标叶子到根节点的路径
        
    -   路径包含兄弟节点的哈希和位置信息
        
    -   支持验证证明的有效性
        
4.  **不存在性证明**：
    
    -   查找目标值的前驱（小于目标的最大叶子）
        
    -   查找目标值的后继（大于目标的最小叶子）
        
    -   提供前驱和后继的存在性证明
        
5.  **性能优化**：
    
    -   使用分层结构存储节点，加速证明生成
        
    -   支持10万叶子节点的大规模树
        
    -   避免递归导致栈溢出
## 三、具体过程
#### 1. SM3哈希函数实现
```cpp
// SM3核心函数
uint32_t P0(uint32_t x) { /*...*/ }
uint32_t P1(uint32_t x) { /*...*/ }

std::string sm3_hash(const std::string& data) {
    // 1. 初始化状态变量
    uint32_t V[8] = { /*SM3_IV值*/ };
    
    // 2. 消息填充
    //   - 添加位'1'
    //   - 填充0
    //   - 添加消息长度(64位大端表示)
    
    // 3. 处理每个512位块
    for (size_t i = 0; i < blocks; i++) {
        // 3.1 消息扩展
        //   - 将块分为16个32位字
        //   - 扩展到68个字(W)
        //   - 计算W1数组
        
        // 3.2 压缩函数
        //   - 8个工作变量(A-H)
        //   - 64轮迭代
        //   - 每轮更新工作变量
    }
    
    // 4. 生成最终哈希值
    //   - 拼接状态变量
    return hash;
}
```
#### 2. Merkle树实现
```cpp
class MerkleTree {
private:
    // 树结构
    MerkleNode* root;
    std::vector<MerkleNode*> leaves;
    std::vector<std::vector<MerkleNode*>> levels;
    
    // RFC6962哈希封装
    std::string rfc6962_hash_leaf(const std::string& data) {
        return sm3_hash("\x00" + data);
    }
    
    std::string rfc6962_hash_node(const std::string& left, const std::string& right) {
        return sm3_hash("\x01" + left + right);
    }
    
    // 构建树
    void buildTree() {
        // 分层构建
        while (current_level.size() > 1) {
            // 处理每对节点
            for (每对节点) {
                if (有右节点) {
                    hash = hash_node(left, right);
                } else {
                    // 奇数节点：与自己组合
                    hash = hash_node(left, left);
                }
            }
            // 添加新层级
            levels.push_back(next_level);
        }
    }
    
public:
    // 存在性证明
    std::vector<std::pair<std::string, bool>> getExistenceProof(size_t index) {
        // 从叶子向上遍历
        while (未到根节点) {
            // 确定兄弟节点位置
            bool is_right = (当前索引 % 2 == 1);
            size_t sibling_index = 计算兄弟索引;
            
            // 处理边界情况
            if (兄弟索引越界) {
                sibling_index = 当前索引; // 与自己组合
            }
            
            // 添加兄弟节点哈希和位置
            proof.push_back(兄弟节点哈希, 位置);
            
            // 上移到父层
            current_index /= 2;
        }
        return proof;
    }
    
    // 不存在性证明
    std::pair<证明, 证明> getNonExistenceProof(uint32_t target) {
        // 1. 创建排序索引
        std::vector<uint32_t> sorted_indices;
        
        // 2. 查找目标位置
        auto it = std::lower_bound(sorted_indices.begin(), sorted_indices.end(), target);
        
        // 3. 获取前驱和后继索引
        size_t pred_index = (it != begin) ? *(it-1) : 无效值;
        size_t succ_index = (it != end) ? *it : 无效值;
        
        // 4. 生成存在性证明
        auto pred_proof = getExistenceProof(pred_index);
        auto succ_proof = getExistenceProof(succ_index);
        
        return {pred_proof, succ_proof};
    }
};
```
#### 3. 关键算法细节

1.  **叶子节点处理**：
```cpp
// 叶子数据：8字节大端整数
std::string leaf = int_to_bytes(i); 
// 哈希计算：H(0x00 || data)
std::string leaf_hash = sm3_hash("\x00" + leaf);
```
2. **内部节点处理**：
```cpp
// 正常节点：H(0x01 || left_hash || right_hash)
hash = sm3_hash("\x01" + left + right);

// 奇数节点：H(0x01 || left_hash || left_hash)
hash = sm3_hash("\x01" + left + left);
```
3. **存在性证明验证**：
```cpp
bool verifyExistenceProof(...) {
    // 初始化为叶子哈希
    current = hash_leaf(leaf_data);
    
    for (每个证明步骤) {
        if (兄弟在右侧) {
            current = hash_node(current, sibling);
        } else {
            current = hash_node(sibling, current);
        }
    }
    
    return current == root_hash;
}
```
4.  **不存在性证明验证**：
    
    -   验证前驱存在性证明有效
        
    -   验证后继存在性证明有效
        
    -   确认目标值在前驱和后继之间
        
    -   边界情况处理（目标小于所有值或大于所有值）
## 四、实验结果
实验结果如图project4-c 结果.png所示。
