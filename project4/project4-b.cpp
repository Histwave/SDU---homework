#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <algorithm>

using namespace std;

// SM3常量定义
const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 常量Tj
const uint32_t T1 = 0x79CC4519;
const uint32_t T2 = 0x7A879D8A;

// 自定义字节序转换函数
inline uint32_t swap_uint32(uint32_t val) {
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | (val >> 16);
}

inline uint64_t swap_uint64(uint64_t val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

// 循环左移
inline uint32_t left_rotate(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// 布尔函数FFj
inline uint32_t ff(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
    if (j < 16) {
        return x ^ y ^ z;
    }
    else {
        return (x & y) | (x & z) | (y & z);
    }
}

// 布尔函数GGj
inline uint32_t gg(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
    if (j < 16) {
        return x ^ y ^ z;
    }
    else {
        return (x & y) | ((~x) & z);
    }
}

// 置换函数P0
inline uint32_t p0(uint32_t x) {
    return x ^ left_rotate(x, 9) ^ left_rotate(x, 17);
}

// 置换函数P1
inline uint32_t p1(uint32_t x) {
    return x ^ left_rotate(x, 15) ^ left_rotate(x, 23);
}

// SM3压缩函数
void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[68];
    uint32_t w1[64];

    // 消息扩展
    for (int i = 0; i < 16; i++) {
        uint32_t val;
        memcpy(&val, block + i * 4, 4);
        w[i] = swap_uint32(val); // 转换为大端序
    }

    for (int i = 16; i < 68; i++) {
        w[i] = p1(w[i - 16] ^ w[i - 9] ^ left_rotate(w[i - 3], 15))
            ^ left_rotate(w[i - 13], 7) ^ w[i - 6];
    }

    for (int i = 0; i < 64; i++) {
        w1[i] = w[i] ^ w[i + 4];
    }

    // 迭代压缩
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

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
    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

// 标准SM3哈希函数
vector<uint8_t> sm3_hash(const vector<uint8_t>& msg) {
    // 初始化状态
    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));

    // 计算消息长度(比特)
    uint64_t bit_len = msg.size() * 8;
    uint64_t bit_len_be = swap_uint64(bit_len); // 转换为大端序

    // 创建填充后的消息
    vector<uint8_t> padded = msg;
    padded.push_back(0x80); // 添加比特"1"

    // 添加填充0
    size_t zero_padding = (56 - (msg.size() + 1) % 64) % 64;
    padded.insert(padded.end(), zero_padding, 0);

    // 添加消息长度(64位大端序)
    uint8_t len_bytes[8];
    memcpy(len_bytes, &bit_len_be, 8);
    padded.insert(padded.end(), len_bytes, len_bytes + 8);

    // 处理消息块
    for (size_t i = 0; i < padded.size(); i += 64) {
        sm3_compress(state, &padded[i]);
    }

    // 将状态转换为字节数组
    vector<uint8_t> hash(32);
    for (int i = 0; i < 8; i++) {
        uint32_t val = swap_uint32(state[i]); // 转换回小端序存储
        memcpy(&hash[i * 4], &val, 4);
    }

    return hash;
}

// 长度扩展攻击函数
vector<uint8_t> length_extension_attack(const vector<uint8_t>& original_hash,
    uint64_t original_len_bits,
    const vector<uint8_t>& extension) {
    // 将原始哈希值转换为状态
    uint32_t state[8];
    for (int i = 0; i < 8; i++) {
        uint32_t val;
        memcpy(&val, &original_hash[i * 4], 4);
        state[i] = swap_uint32(val); // 转换为大端序
    }

    // 计算原始消息的填充长度(比特)
    size_t padding_len_bits = (512 - (original_len_bits % 512) - 1 - 64) % 512;
    if (original_len_bits % 512 >= 448) {
        padding_len_bits += 512;
    }
    uint64_t total_len_bits = original_len_bits + 1 + padding_len_bits + 64;

    // 计算扩展消息的总长度(包括新填充)
    uint64_t new_total_bits = total_len_bits + extension.size() * 8;
    uint64_t new_total_bits_be = swap_uint64(new_total_bits); // 转换为大端序

    // 创建包含扩展和填充的消息
    vector<uint8_t> padded = extension;
    padded.push_back(0x80); // 添加比特"1"

    // 添加填充0
    size_t zero_padding = (56 - (extension.size() + 1) % 64) % 64;
    padded.insert(padded.end(), zero_padding, 0);

    // 添加新消息长度(64位大端序)
    uint8_t len_bytes[8];
    memcpy(len_bytes, &new_total_bits_be, 8);
    padded.insert(padded.end(), len_bytes, len_bytes + 8);

    // 处理消息块
    for (size_t i = 0; i < padded.size(); i += 64) {
        sm3_compress(state, &padded[i]);
    }

    // 将状态转换为字节数组
    vector<uint8_t> hash(32);
    for (int i = 0; i < 8; i++) {
        uint32_t val = swap_uint32(state[i]); // 转换回小端序存储
        memcpy(&hash[i * 4], &val, 4);
    }

    return hash;
}

// 字节数组转十六进制字符串
string bytes_to_hex(const vector<uint8_t>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for (uint8_t b : bytes) {
        ss << setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

int main() {
    // 原始消息
    vector<uint8_t> original_msg = { 's', 'e', 'c', 'r', 'e', 't' };
    cout << "Original message: " << string(original_msg.begin(), original_msg.end()) << endl;

    // 计算原始消息的哈希
    vector<uint8_t> original_hash = sm3_hash(original_msg);
    cout << "Original hash: " << bytes_to_hex(original_hash) << endl;

    // 扩展消息
    vector<uint8_t> extension = { 'a', 't', 't', 'a', 'c', 'k' };
    cout << "Extension: " << string(extension.begin(), extension.end()) << endl;

    // 执行长度扩展攻击
    vector<uint8_t> attack_hash = length_extension_attack(
        original_hash,
        original_msg.size() * 8,
        extension
    );
    cout << "Attack hash: " << bytes_to_hex(attack_hash) << endl;

    // 计算实际拼接消息的哈希
    vector<uint8_t> actual_msg = original_msg;

    // 添加原始填充
    actual_msg.push_back(0x80);
    size_t zero_padding = (56 - (original_msg.size() + 1) % 64) % 64;
    actual_msg.insert(actual_msg.end(), zero_padding, 0);
    uint64_t bit_len = original_msg.size() * 8;
    uint64_t bit_len_be = swap_uint64(bit_len);
    uint8_t len_bytes[8];
    memcpy(len_bytes, &bit_len_be, 8);
    actual_msg.insert(actual_msg.end(), len_bytes, len_bytes + 8);

    // 添加扩展消息
    actual_msg.insert(actual_msg.end(), extension.begin(), extension.end());

    // 计算实际哈希
    vector<uint8_t> actual_hash = sm3_hash(actual_msg);
    cout << "Actual hash:  " << bytes_to_hex(actual_hash) << endl;

    // 验证结果
    if (attack_hash == actual_hash) {
        cout << "\nSUCCESS: Length extension attack works!" << endl;
    }
    else {
        cout << "\nFAILURE: Attack hash doesn't match actual hash" << endl;
    }

    return 0;
}