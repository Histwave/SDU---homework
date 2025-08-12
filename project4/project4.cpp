#include <iostream>
#include <cstring>
#include <chrono>
#include <immintrin.h>

// 跨平台的字节序转换函数
inline uint32_t byteswap32(uint32_t x) {
#if defined(_MSC_VER)
    return _byteswap_ulong(x);
#elif defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(x);
#else
    return ((x & 0xFF000000) >> 24) |
        ((x & 0x00FF0000) >> 8) |
        ((x & 0x0000FF00) << 8) |
        ((x & 0x000000FF) << 24);
#endif
}

// SM3常量定义
const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

const uint32_t T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, // 0-15
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, // 16-63
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    // ... 重复填充至64个
};

// 基础函数
inline uint32_t ROTL32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

inline uint32_t FF0(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

inline uint32_t FF1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (x & z) | (y & z);
}

inline uint32_t GG0(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

inline uint32_t GG1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}

inline uint32_t P0(uint32_t x) {
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}

inline uint32_t P1(uint32_t x) {
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}

// ==================== 基础实现 ====================
void sm3_basic(const uint8_t* data, size_t len, uint8_t* digest) {
    // 消息填充
    size_t block_len = ((len + 8 + 63) / 64) * 64;
    uint8_t* padded = new uint8_t[block_len]();
    memcpy(padded, data, len);
    padded[len] = 0x80;
    uint64_t bit_len = len * 8;
    memcpy(padded + block_len - 8, &bit_len, 8);

    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    for (size_t i = 0; i < block_len; i += 64) {
        uint32_t W[68] = { 0 };
        uint32_t W1[64] = { 0 };

        // 消息扩展
        for (int j = 0; j < 16; j++) {
            uint32_t word;
            memcpy(&word, padded + i + j * 4, 4);
            W[j] = byteswap32(word);
        }

        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15))
                ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
        }
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }

        // 压缩函数
        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(T[j], j % 32), 7);
            uint32_t SS2 = SS1 ^ ROTL32(A, 12);
            uint32_t TT1 = (j < 16) ?
                (FF0(A, B, C) + D + SS2 + W1[j]) :
                (FF1(A, B, C) + D + SS2 + W1[j]);
            uint32_t TT2 = (j < 16) ?
                (GG0(E, F, G) + H + SS1 + W[j]) :
                (GG1(E, F, G) + H + SS1 + W[j]);

            D = C;
            C = ROTL32(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL32(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    // 大端输出
    for (int i = 0; i < 8; i++) {
        uint32_t word = byteswap32(V[i]);
        memcpy(digest + i * 4, &word, 4);
    }
    delete[] padded;
}

// ==================== SIMD优化实现 ====================
void sm3_optimized(const uint8_t* data, size_t len, uint8_t* digest) {
    // 消息填充（同基础版）
    size_t block_len = ((len + 8 + 63) / 64) * 64;
    uint8_t* padded = new uint8_t[block_len]();
    memcpy(padded, data, len);
    padded[len] = 0x80;
    uint64_t bit_len = len * 8;
    memcpy(padded + block_len - 8, &bit_len, 8);

    alignas(32) uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    for (size_t i = 0; i < block_len; i += 64) {
        // 使用SIMD寄存器处理消息扩展
        __m128i w0 = _mm_loadu_si128((__m128i*)(padded + i));
        __m128i w1 = _mm_loadu_si128((__m128i*)(padded + i + 16));
        __m128i w2 = _mm_loadu_si128((__m128i*)(padded + i + 32));
        __m128i w3 = _mm_loadu_si128((__m128i*)(padded + i + 48));

        // 字节序转换
        const __m128i bswap_mask = _mm_set_epi8(
            12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
        );
        w0 = _mm_shuffle_epi8(w0, bswap_mask);
        w1 = _mm_shuffle_epi8(w1, bswap_mask);
        w2 = _mm_shuffle_epi8(w2, bswap_mask);
        w3 = _mm_shuffle_epi8(w3, bswap_mask);

        // 压缩函数寄存器
        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        // 循环展开+寄存器优化
        uint32_t W[68], W1[64];
        _mm_store_si128((__m128i*) & W[0], w0);
        _mm_store_si128((__m128i*) & W[4], w1);
        _mm_store_si128((__m128i*) & W[8], w2);
        _mm_store_si128((__m128i*) & W[12], w3);

        // 优化的消息扩展
        for (int j = 16; j < 68; j++) {
            uint32_t temp = W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15);
            W[j] = P1(temp) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
        }
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }

        // 4轮展开压缩
        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(T[j], j % 32), 7);
            uint32_t SS2 = SS1 ^ ROTL32(A, 12);
            uint32_t TT1, TT2;

            if (j < 16) {
                TT1 = FF0(A, B, C) + D + SS2 + W1[j];
                TT2 = GG0(E, F, G) + H + SS1 + W[j];
            }
            else {
                TT1 = FF1(A, B, C) + D + SS2 + W1[j];
                TT2 = GG1(E, F, G) + H + SS1 + W[j];
            }

            D = C;
            C = ROTL32(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL32(F, 19);
            F = E;
            E = P0(TT2);

            // 每4轮进行寄存器轮转
            if (j % 4 == 3) {
                uint32_t tmp = E;
                E = D; D = C; C = B; B = A; A = H;
                H = G; G = F; F = tmp;
            }
        }

        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    // 结果输出
    for (int i = 0; i < 8; i++) {
        uint32_t word = byteswap32(V[i]);
        memcpy(digest + i * 4, &word, 4);
    }
    delete[] padded;
}

// ==================== 性能测试 ====================
void test_performance() {
    const size_t SIZE = 64 * 1024 * 1024; // 64MB
    uint8_t* data = new uint8_t[SIZE];
    memset(data, 0x61, SIZE); // 填充测试数据

    uint8_t digest[32];

    // 测试基础实现
    auto start = std::chrono::high_resolution_clock::now();
    sm3_basic(data, SIZE, digest);
    auto end = std::chrono::high_resolution_clock::now();
    double basic_time = std::chrono::duration<double>(end - start).count();
    std::cout << "Basic SM3: " << (SIZE / (1024.0 * 1024.0)) / basic_time << " MB/s\n";

    // 测试优化实现
    start = std::chrono::high_resolution_clock::now();
    sm3_optimized(data, SIZE, digest);
    end = std::chrono::high_resolution_clock::now();
    double opt_time = std::chrono::duration<double>(end - start).count();
    std::cout << "Optimized SM3: " << (SIZE / (1024.0 * 1024.0)) / opt_time << " MB/s\n";
    std::cout << "Speedup: " << basic_time / opt_time << "x\n";

    delete[] data;
}

int main() {
    test_performance();
    return 0;
}