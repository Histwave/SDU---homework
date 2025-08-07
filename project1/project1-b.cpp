#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <random>
#include <windows.h>
using namespace std;

// SM4常量定义 

// SM4标准S盒
static const uint8_t kSbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// 固定主密钥 (128位)
static const uint8_t kMasterKey[16] = {
    0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10
};

// 密钥扩展常量
static const uint32_t kFK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// 轮常量
static const uint32_t kCK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

// 核心算法组件 

// 循环左移函数
static inline constexpr uint32_t RotateLeft(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

// 线性变换函数 (用于T表生成)
static inline constexpr uint32_t LinearTransform(uint32_t value) {
    return value ^ RotateLeft(value, 2) ^ RotateLeft(value, 10)
        ^ RotateLeft(value, 18) ^ RotateLeft(value, 24);
}

// T表 (预计算S盒+线性变换)
static uint32_t kTTable[256];

// 初始化T表
void InitializeTTable() {
    for (int i = 0; i < 256; i++) {
        // 将S盒输出扩展为32位值
        uint32_t sbox_output = kSbox[i];
        uint32_t expanded = (sbox_output << 24) |
            (sbox_output << 16) |
            (sbox_output << 8) |
            sbox_output;
        // 应用线性变换
        kTTable[i] = LinearTransform(expanded);
    }
}

// S盒非线性变换 (32位输入->32位输出)
static inline uint32_t ApplySBox(uint32_t input) {
    uint32_t result = 0;
    // 分4字节处理
    result |= (uint32_t)kSbox[(input >> 24) & 0xFF] << 24;
    result |= (uint32_t)kSbox[(input >> 16) & 0xFF] << 16;
    result |= (uint32_t)kSbox[(input >> 8) & 0xFF] << 8;
    result |= (uint32_t)kSbox[input & 0xFF];
    return result;
}

// 密钥扩展函数
void ExpandKey(const uint8_t key[16], uint32_t round_keys[32]) {
    uint32_t key_state[36];  // 密钥状态缓冲区

    // 初始化前4个密钥字
    for (int i = 0; i < 4; i++) {
        key_state[i] = ((uint32_t)key[4 * i] << 24) |
            ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) |
            key[4 * i + 3];
        key_state[i] ^= kFK[i];  // 异或FK常量
    }

    // 生成32轮密钥 (每次处理4轮)
    for (int round = 0; round < 32; round += 4) {
        for (int sub_round = 0; sub_round < 4; sub_round++) {
            // 非线性部分
            uint32_t tmp = key_state[round + sub_round + 1] ^
                key_state[round + sub_round + 2] ^
                key_state[round + sub_round + 3] ^
                kCK[round + sub_round];

            // S盒变换 + 线性变换
            uint32_t transformed = ApplySBox(tmp);
            transformed = transformed ^ RotateLeft(transformed, 13) ^
                RotateLeft(transformed, 23);

            // 生成轮密钥
            round_keys[round + sub_round] = key_state[round + sub_round] ^ transformed;
            key_state[round + sub_round + 4] = round_keys[round + sub_round];
        }
    }
}

// SM4加密函数 (单块)
void EncryptBlock(const uint8_t input[16], uint8_t output[16], const uint32_t round_keys[32]) {
    uint32_t state[4];  // 加密状态寄存器

    // 加载输入数据 (大端序)
    state[0] = ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
        ((uint32_t)input[2] << 8) | input[3];
    state[1] = ((uint32_t)input[4] << 24) | ((uint32_t)input[5] << 16) |
        ((uint32_t)input[6] << 8) | input[7];
    state[2] = ((uint32_t)input[8] << 24) | ((uint32_t)input[9] << 16) |
        ((uint32_t)input[10] << 8) | input[11];
    state[3] = ((uint32_t)input[12] << 24) | ((uint32_t)input[13] << 16) |
        ((uint32_t)input[14] << 8) | input[15];

    // 32轮加密 (每次处理4轮)
    for (int round = 0; round < 32; round += 4) {
        // 第1轮
        uint32_t tmp = state[1] ^ state[2] ^ state[3] ^ round_keys[round];
        uint32_t next = state[0] ^ kTTable[(tmp >> 24) & 0xFF] ^
            kTTable[(tmp >> 16) & 0xFF] ^
            kTTable[(tmp >> 8) & 0xFF] ^
            kTTable[tmp & 0xFF];
        // 更新状态
        state[0] = state[1];
        state[1] = state[2];
        state[2] = state[3];
        state[3] = next;

        // 第2轮 (重复结构，编译器会优化)
        tmp = state[1] ^ state[2] ^ state[3] ^ round_keys[round + 1];
        next = state[0] ^ kTTable[(tmp >> 24) & 0xFF] ^
            kTTable[(tmp >> 16) & 0xFF] ^
            kTTable[(tmp >> 8) & 0xFF] ^
            kTTable[tmp & 0xFF];
        state[0] = state[1];
        state[1] = state[2];
        state[2] = state[3];
        state[3] = next;

        // 第3轮
        tmp = state[1] ^ state[2] ^ state[3] ^ round_keys[round + 2];
        next = state[0] ^ kTTable[(tmp >> 24) & 0xFF] ^
            kTTable[(tmp >> 16) & 0xFF] ^
            kTTable[(tmp >> 8) & 0xFF] ^
            kTTable[tmp & 0xFF];
        state[0] = state[1];
        state[1] = state[2];
        state[2] = state[3];
        state[3] = next;

        // 第4轮
        tmp = state[1] ^ state[2] ^ state[3] ^ round_keys[round + 3];
        next = state[0] ^ kTTable[(tmp >> 24) & 0xFF] ^
            kTTable[(tmp >> 16) & 0xFF] ^
            kTTable[(tmp >> 8) & 0xFF] ^
            kTTable[tmp & 0xFF];
        state[0] = state[1];
        state[1] = state[2];
        state[2] = state[3];
        state[3] = next;
    }

    // 最终输出 (逆序)
    output[0] = (state[3] >> 24) & 0xFF;
    output[1] = (state[3] >> 16) & 0xFF;
    output[2] = (state[3] >> 8) & 0xFF;
    output[3] = state[3] & 0xFF;

    output[4] = (state[2] >> 24) & 0xFF;
    output[5] = (state[2] >> 16) & 0xFF;
    output[6] = (state[2] >> 8) & 0xFF;
    output[7] = state[2] & 0xFF;

    output[8] = (state[1] >> 24) & 0xFF;
    output[9] = (state[1] >> 16) & 0xFF;
    output[10] = (state[1] >> 8) & 0xFF;
    output[11] = state[1] & 0xFF;

    output[12] = (state[0] >> 24) & 0xFF;
    output[13] = (state[0] >> 16) & 0xFF;
    output[14] = (state[0] >> 8) & 0xFF;
    output[15] = state[0] & 0xFF;
}

// GCM模式组件 

// 128位整数结构 (高位在前)
struct UInt128 {
    uint64_t high;  // 高64位
    uint64_t low;   // 低64位
};

// GF(2^128)乘法 (带模约简)
UInt128 GF128Multiply(const UInt128& X, const UInt128& Y) {
    UInt128 Z = { 0, 0 };
    UInt128 V = X;  // 被乘数

    // 逐位处理乘数
    for (int i = 0; i < 128; i++) {
        // 检查当前位
        uint8_t bit = (i < 64) ?
            ((Y.high >> (63 - i)) & 1) :  // 高位部分
            ((Y.low >> (127 - i)) & 1);   // 低位部分

        // 如果位为1，则异或当前V
        if (bit) {
            Z.high ^= V.high;
            Z.low ^= V.low;
        }

        // 检测是否需模约简
        bool carry = V.low & 1;

        // V右移1位
        V.low = (V.low >> 1) | (V.high << 63);
        V.high = V.high >> 1;

        // 如果溢出则应用约简多项式
        if (carry) {
            V.high ^= 0xE100000000000000ULL; // x^128 + x^7 + x^2 + x + 1
        }
    }
    return Z;
}

// GHASH函数 (认证核心)
UInt128 ComputeGHASH(const UInt128& H, const vector<uint8_t>& data) {
    UInt128 Y = { 0, 0 };  // 初始状态
    const uint8_t* data_ptr = data.data();
    size_t total_bytes = data.size();
    size_t full_blocks = total_bytes / 16;
    size_t remaining_bytes = total_bytes % 16;

    // 处理完整块
    for (size_t i = 0; i < full_blocks; i++) {
        UInt128 block = { 0, 0 };

        // 构建128位块 (大端序)
        for (int j = 0; j < 8; j++)
            block.high = (block.high << 8) | *data_ptr++;
        for (int j = 0; j < 8; j++)
            block.low = (block.low << 8) | *data_ptr++;

        // GHASH更新: Y = (Y XOR block) • H
        Y.high ^= block.high;
        Y.low ^= block.low;
        Y = GF128Multiply(Y, H);
    }

    // 处理剩余部分
    if (remaining_bytes) {
        UInt128 last_block = { 0, 0 };

        // 填充剩余字节
        for (size_t i = 0; i < remaining_bytes; i++) {
            if (i < 8)
                last_block.high = (last_block.high << 8) | *data_ptr++;
            else
                last_block.low = (last_block.low << 8) | *data_ptr++;
        }

        // 对齐剩余数据
        last_block.high <<= (8 - (remaining_bytes % 8)) * 8;

        // 最后更新
        Y.high ^= last_block.high;
        Y.low ^= last_block.low;
        Y = GF128Multiply(Y, H);
    }

    return Y;
}

// 32位计数器递增 (大端序处理)
void IncrementCounter(uint8_t counter[16]) {
    // 定位计数器位置 (最后32位)
    uint32_t* counter_ptr = reinterpret_cast<uint32_t*>(counter + 12);

    // 大端序转换->递增->转回大端序
    *counter_ptr = _byteswap_ulong(_byteswap_ulong(*counter_ptr) + 1);
}

// GCM模式加密 

void SM4_GCM_Encrypt(
    const uint32_t round_keys[32],    // 扩展后的轮密钥
    const vector<uint8_t>& iv,        // 初始化向量
    const vector<uint8_t>& plaintext, // 明文
    vector<uint8_t>& ciphertext,      // 输出密文
    uint8_t auth_tag[16]              // 输出认证标签
) {
    // 步骤1: 计算认证密钥H = E_K(0^128)
    uint8_t zero_block[16] = { 0 };
    uint8_t H_block[16];
    EncryptBlock(zero_block, H_block, round_keys);

    // 转换为128位整数
    UInt128 H = { 0, 0 };
    for (int i = 0; i < 8; i++) H.high = (H.high << 8) | H_block[i];
    for (int i = 0; i < 8; i++) H.low = (H.low << 8) | H_block[8 + i];

    // 步骤2: 生成初始计数器值J0
    vector<uint8_t> counter(16, 0);
    if (iv.size() == 12) {
        // 标准IV处理: IV || 0x00000001
        memcpy(counter.data(), iv.data(), 12);
        counter[15] = 1;
    }
    else {
        // 非标准IV: GHASH(H, IV)
        UInt128 hash_result = ComputeGHASH(H, iv);
        for (int i = 0; i < 8; i++)
            counter[i] = (hash_result.high >> (56 - 8 * i)) & 0xFF;
        for (int i = 0; i < 8; i++)
            counter[8 + i] = (hash_result.low >> (56 - 8 * i)) & 0xFF;
    }

    // 步骤3: CTR模式加密
    ciphertext.resize(plaintext.size());
    uint8_t current_counter[16];
    memcpy(current_counter, counter.data(), 16);
    IncrementCounter(current_counter);  // J0 + 1

    const size_t data_size = plaintext.size();
    for (size_t offset = 0; offset < data_size; offset += 16) {
        // 生成密钥流
        uint8_t keystream[16];
        EncryptBlock(current_counter, keystream, round_keys);

        // 计算当前块大小
        size_t block_size = min(static_cast<size_t>(16), data_size - offset);

        // 异或加密
        for (size_t i = 0; i < block_size; i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
        }

        // 更新计数器
        IncrementCounter(current_counter);
    }

    // 步骤4: 计算认证标签
    // 构建认证数据: ciphertext || len(ciphertext)
    vector<uint8_t> auth_data = ciphertext;

    // 填充到16字节边界
    if (auth_data.size() % 16 != 0) {
        auth_data.resize(auth_data.size() + (16 - auth_data.size() % 16), 0);
    }

    // 添加长度域 (64位0 + 64位长度)
    uint64_t ciphertext_bits = static_cast<uint64_t>(ciphertext.size()) * 8;
    for (int i = 0; i < 8; i++) auth_data.push_back(0);  // 填充64位0
    for (int i = 0; i < 8; i++) {  // 大端序长度
        auth_data.push_back(static_cast<uint8_t>(ciphertext_bits >> (56 - 8 * i)));
    }

    // 计算GHASH结果
    UInt128 ghash_result = ComputeGHASH(H, auth_data);

    // 加密初始计数器值
    uint8_t encrypted_counter[16];
    EncryptBlock(counter.data(), encrypted_counter, round_keys);

    // 生成认证标签: E_K(J0) XOR GHASH
    for (int i = 0; i < 16; i++) {
        if (i < 8) {
            auth_tag[i] = encrypted_counter[i] ^
                ((ghash_result.high >> (56 - 8 * i)) & 0xFF);
        }
        else {
            auth_tag[i] = encrypted_counter[i] ^
                ((ghash_result.low >> (120 - 8 * i)) & 0xFF);
        }
    }
}

// 主函数 

int main() {
    // 初始化算法组件
    InitializeTTable();

    // 密钥扩展
    uint32_t round_keys[32];
    ExpandKey(kMasterKey, round_keys);

    // 生成随机IV (12字节)
    vector<uint8_t> iv(12);
    random_device rd;
    uniform_int_distribution<int> dist(0, 255);
    for (auto& byte : iv) byte = dist(rd);

    // 测试数据
    string plaintext_str = "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10";
    vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());
    vector<uint8_t> ciphertext;
    uint8_t auth_tag[16];

    // 性能测试
    LARGE_INTEGER frequency, start_time, end_time;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start_time);

    // 执行GCM加密
    SM4_GCM_Encrypt(round_keys, iv, plaintext, ciphertext, auth_tag);

    QueryPerformanceCounter(&end_time);
    double elapsed_time = (end_time.QuadPart - start_time.QuadPart) * 1000.0 / frequency.QuadPart;

    // 输出结果
    cout << "输入明文: " << plaintext_str << endl;
    cout << "优化后SM4-GCM加密用时: " << elapsed_time << " ms" << endl;
    cout << "输出密文: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(auth_tag[i]);
    }
    cout << dec << endl;  // 切回十进制输出

    return 0;

}
