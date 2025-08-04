#include <iostream>
#include <cstdint>
#include <iomanip>
#include <chrono>
#include <immintrin.h>

using namespace std;
using namespace chrono;

// SM4算法常量定义
const uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
const uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// S盒替换表
const uint8_t Sbox[256] = {
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

// 循环左移函数
inline uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// -------------------------- 基础版本 --------------------------

// 基础T函数
inline uint32_t T_basic(uint32_t x) {
    uint32_t b0 = Sbox[(x >> 24) & 0xFF];
    uint32_t b1 = Sbox[(x >> 16) & 0xFF];
    uint32_t b2 = Sbox[(x >> 8) & 0xFF];
    uint32_t b3 = Sbox[x & 0xFF];
    uint32_t s = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;  // 正确组合字节

    // 线性变换 
    return s ^ rotl(s, 2) ^ rotl(s, 10) ^ rotl(s, 18) ^ rotl(s, 24);
}

// 基础T'函数 (用于密钥扩展)
inline uint32_t T_prime_basic(uint32_t x) {
    uint32_t b0 = Sbox[(x >> 24) & 0xFF];
    uint32_t b1 = Sbox[(x >> 16) & 0xFF];
    uint32_t b2 = Sbox[(x >> 8) & 0xFF];
    uint32_t b3 = Sbox[x & 0xFF];
    uint32_t s = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;  // 正确组合字节

    // 线性变换 
    return s ^ rotl(s, 13) ^ rotl(s, 23);
}
// 基础密钥扩展
void keyExpansionBasic(const uint8_t* key, uint32_t rk[32]) {
    uint32_t MK[4];
    for (int i = 0; i < 4; i++) {
        MK[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) |
            (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    uint32_t K[36];
    K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];

    for (int i = 0; i < 32; i++) {
        K[i + 4] = K[i] ^ T_prime_basic(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        rk[i] = K[i + 4];
    }
}

// 基础加密函数
void sm4EncryptBasic(const uint8_t* plaintext, const uint32_t rk[32], uint8_t* ciphertext) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = (plaintext[4 * i] << 24) | (plaintext[4 * i + 1] << 16) |
            (plaintext[4 * i + 2] << 8) | plaintext[4 * i + 3];
    }

    for (int i = 0; i < 32; i++) {
        // 状态更新逻辑
        X[i + 4] = X[i] ^ T_basic(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    }

    // 输出顺序 (修复索引)
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[35 - i];
        ciphertext[4 * i] = (val >> 24) & 0xFF;
        ciphertext[4 * i + 1] = (val >> 16) & 0xFF;
        ciphertext[4 * i + 2] = (val >> 8) & 0xFF;
        ciphertext[4 * i + 3] = val & 0xFF;
    }
}

// -------------------------- T-table优化版本 --------------------------

// 预计算T-table
uint32_t T_table[256];

// 初始化T-table
void initTTable() {
    for (int i = 0; i < 256; i++) {
        uint32_t x = Sbox[i];
        T_table[i] = x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24);
    }
}

// T-table优化的T函数
inline uint32_t T_table_opt(uint32_t x) {
    return T_table[(x >> 24) & 0xFF] ^
        (T_table[(x >> 16) & 0xFF] << 8) ^
        (T_table[(x >> 8) & 0xFF] << 16) ^
        (T_table[x & 0xFF] << 24);
}

// T-table优化的密钥扩展
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

// -------------------------- AESNI优化版本 --------------------------

// 只有在支持AES指令集的情况下才编译AESNI优化代码
#ifdef __AES__
// AESNI优化的T函数
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

// AESNI优化的密钥扩展
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
#endif // __AES__

// -------------------------- GFNI和VPROLD优化版本 --------------------------

// 只有在支持GFNI指令集的情况下才编译相关代码
#ifdef __GFNI__
// GFNI和VPROLD优化的T函数
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

// GFNI和VPROLD优化的密钥扩展
void keyExpansionGFNI(const uint8_t* key, __m128i rk[32]) {
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
        K[i + 4] = _mm_xor_si128(K[i], T_gfni(temp));
        rk[i] = K[i + 4];
    }
}

// GFNI和VPROLD优化的加密函数
void sm4EncryptGFNI(const uint8_t* plaintext, const __m128i rk[32], uint8_t* ciphertext) {
    __m128i X = _mm_loadu_si128((const __m128i*)plaintext);
    __m128i X1 = _mm_shuffle_epi32(X, _MM_SHUFFLE(0, 3, 2, 1));
    __m128i X2 = _mm_shuffle_epi32(X1, _MM_SHUFFLE(0, 3, 2, 1));
    __m128i X3 = _mm_shuffle_epi32(X2, _MM_SHUFFLE(0, 3, 2, 1));

    for (int i = 0; i < 32; i++) {
        __m128i temp = _mm_xor_si128(_mm_xor_si128(X1, X2), _mm_xor_si128(X3, rk[i]));
        __m128i newX = _mm_xor_si128(X, T_gfni(temp));

        X = X1;
        X1 = X2;
        X2 = X3;
        X3 = newX;
    }

    __m128i result = _mm_shuffle_epi32(_mm_xor_si128(_mm_xor_si128(X, X1), _mm_xor_si128(X2, X3)),
        _MM_SHUFFLE(1, 0, 3, 2));
    _mm_storeu_si128((__m128i*)ciphertext, result);
}
#endif // __GFNI__

// 辅助函数：打印字节数组
void printBytes(const uint8_t* data, int length, const string& label) {
    cout << label << ": ";
    for (int i = 0; i < length; i++) {
        cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
    }
    cout << dec << endl;
}

// 性能测试函数 - 添加KeyType参数以辅助模板推导
template<typename Func, typename KeyGen, typename KeyType>
double testPerformance(Func encryptFunc, KeyGen keyGen, const uint8_t* key, const uint8_t* plaintext,
    uint8_t* ciphertext, int iterations, KeyType) {
    KeyType rk[32];
    keyGen(key, rk);

    // 预热
    for (int i = 0; i < 1000; i++) {
        encryptFunc(plaintext, rk, ciphertext);
    }

    auto start = high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        encryptFunc(plaintext, rk, ciphertext);
    }

    auto end = high_resolution_clock::now();
    duration<double> elapsed = end - start;

    return elapsed.count();
}

int main() {
    // 初始化T-table
    initTTable();

    // 测试数据
    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

    uint8_t plaintext[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

    uint8_t ciphertext[16];
    const int iterations = 1000000; // 100万次迭代

    // 基础版本测试 - 传递类型参数辅助推导
    double basicTime = testPerformance(sm4EncryptBasic, keyExpansionBasic, key, plaintext, ciphertext, iterations, uint32_t());

    uint8_t basicResult[16];
    uint32_t rkBasic[32];
    keyExpansionBasic(key, rkBasic);
    sm4EncryptBasic(plaintext, rkBasic, basicResult);

    // T-table优化版本测试
    double ttableTime = testPerformance(sm4EncryptTTable, keyExpansionTTable, key, plaintext, ciphertext, iterations, uint32_t());

    // AESNI优化版本测试（仅在支持AES指令集的情况下）
#ifdef __AES__
    double aesniTime = testPerformance(sm4EncryptAESNI, keyExpansionAESNI, key, plaintext, ciphertext, iterations, __m128i());
#else
    cout << "\n注意: 编译器不支持AES指令集，跳过AESNI优化版本测试" << endl;
#endif

    // GFNI优化版本测试（仅在支持GFNI指令集的情况下）
#ifdef __GFNI__
    double gfniTime = testPerformance(sm4EncryptGFNI, keyExpansionGFNI, key, plaintext, ciphertext, iterations, __m128i());
#else
    cout << "注意: 编译器不支持GFNI指令集，跳过GFNI优化版本测试" << endl;
#endif

    // 输出结果
    printBytes(plaintext, 16, "明文");
    printBytes(key, 16, "密钥");
    printBytes(basicResult, 16, "密文");

    // 输出性能比较
    cout << "\n性能测试 (" << iterations << " 次加密):" << endl;
    cout << "基础版本: " << fixed << setprecision(4) << basicTime << " 秒, "
        << (iterations * 16 * 8) / (basicTime * 1024 * 1024) << " Mbps" << endl;
    cout << "T-table优化: " << fixed << setprecision(4) << ttableTime << " 秒, "
        << (iterations * 16 * 8) / (ttableTime * 1024 * 1024) << " Mbps, "
        << "加速比: " << basicTime / ttableTime << "x" << endl;

#ifdef __AES__
    cout << "AESNI优化: " << fixed << setprecision(4) << aesniTime << " 秒, "
        << (iterations * 16 * 8) / (aesniTime * 1024 * 1024) << " Mbps, "
        << "加速比: " << basicTime / aesniTime << "x" << endl;
#endif

#ifdef __GFNI__
    cout << "GFNI优化: " << fixed << setprecision(4) << gfniTime << " 秒, "
        << (iterations * 16 * 8) / (gfniTime * 1024 * 1024) << " Mbps, "
        << "加速比: " << basicTime / gfniTime << "x" << endl;
#endif

    return 0;
}
