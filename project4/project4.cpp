#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <chrono>
#include <algorithm>

// 循环左移
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 布尔函数
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

// 置换函数
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

class SM3Base {
public:
    SM3Base() { reset(); }

    void reset() {
        state[0] = 0x7380166F;
        state[1] = 0x4914B2B9;
        state[2] = 0x172442D7;
        state[3] = 0xDA8A0600;
        state[4] = 0xA96F30BC;
        state[5] = 0x163138AA;
        state[6] = 0xE38DEE4D;
        state[7] = 0xB0FB0E4E;
        count = 0;
        buffer.clear();
    }

    void update(const uint8_t* data, size_t len) {
        buffer.insert(buffer.end(), data, data + len);
        count += len * 8;
    }

    void finalize() {
        uint64_t bitCount = count;
        buffer.push_back(0x80);

        // 计算填充长度
        size_t paddingSize = (56 - (buffer.size() % 64)) % 64;
        if (paddingSize > 0) {
            buffer.insert(buffer.end(), paddingSize, 0);
        }

        // 添加消息长度（64位，大端序）
        for (int i = 7; i >= 0; --i) {
            buffer.push_back(static_cast<uint8_t>(bitCount >> (i * 8)));
        }

        // 处理每个512位块
        for (size_t i = 0; i < buffer.size(); i += 64) {
            compress(&buffer[i]);
        }
    }

    std::vector<uint8_t> digest() {
        std::vector<uint8_t> result(32);
        for (int i = 0; i < 8; ++i) {
            result[i * 4 + 0] = static_cast<uint8_t>(state[i] >> 24);
            result[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            result[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            result[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }
        return result;
    }

protected:
    virtual void compress(const uint8_t* block) {
        uint32_t W[68], W1[64];

        // 消息扩展
        for (int i = 0; i < 16; ++i) {
            W[i] = (block[i * 4 + 0] << 24) | (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        }

        for (int i = 16; i < 68; ++i) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^
                ROTL(W[i - 13], 7) ^ W[i - 6];
        }

        for (int i = 0; i < 64; ++i) {
            W1[i] = W[i] ^ W[i + 4];
        }

        uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
        uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

        // 压缩函数
        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T(j), j)), 7);
            uint32_t SS2 = SS1 ^ ROTL(A, 12);
            uint32_t TT1 = (j < 16) ?
                (FF0(A, B, C) + D + SS2 + W1[j]) :
                (FF1(A, B, C) + D + SS2 + W1[j]);
            uint32_t TT2 = (j < 16) ?
                (GG0(E, F, G) + H + SS1 + W[j]) :
                (GG1(E, F, G) + H + SS1 + W[j]);

            D = C;
            C = ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }

        state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
        state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
    }

    uint32_t T(int j) const {
        return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
    }

    uint32_t state[8];
    uint64_t count;
    std::vector<uint8_t> buffer;
};

class SM3Opt : public SM3Base {
protected:
    void compress(const uint8_t* block) override {
        uint32_t W[68];

        // 消息扩展
        for (int i = 0; i < 16; i++) {
            W[i] = (block[i * 4 + 0] << 24) | (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        }

        for (int i = 16; i < 68; i++) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^
                ROTL(W[i - 13], 7) ^ W[i - 6];
        }

        // 压缩函数 - 应用4轮展开优化
        uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
        uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

        for (int j = 0; j < 64; j += 4) {
            // 第1轮
            uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T(j), j)), 7);
            uint32_t SS2 = SS1 ^ ROTL(A, 12);
            uint32_t TT1 = FF0(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
            uint32_t TT2 = GG0(E, F, G) + H + SS1 + W[j];
            D = C; C = ROTL(B, 9); B = A; A = TT1;
            H = G; G = ROTL(F, 19); F = E; E = P0(TT2);

            // 第2轮
            SS1 = ROTL((ROTL(D, 12) + H + ROTL(T(j + 1), j + 1)), 7);
            SS2 = SS1 ^ ROTL(D, 12);
            TT1 = FF0(D, A, B) + C + SS2 + (W[j + 1] ^ W[j + 5]);
            TT2 = GG0(H, E, F) + G + SS1 + W[j + 1];
            C = B; B = ROTL(A, 9); A = D; D = TT1;
            G = F; F = ROTL(E, 19); E = H; H = P0(TT2);

            // 第3轮
            SS1 = ROTL((ROTL(C, 12) + G + ROTL(T(j + 2), j + 2)), 7);
            SS2 = SS1 ^ ROTL(C, 12);
            TT1 = FF0(C, D, A) + B + SS2 + (W[j + 2] ^ W[j + 6]);
            TT2 = GG0(G, H, E) + F + SS1 + W[j + 2];
            B = A; A = ROTL(D, 9); D = C; C = TT1;
            F = E; E = ROTL(H, 19); H = G; G = P0(TT2);

            // 第4轮
            SS1 = ROTL((ROTL(B, 12) + F + ROTL(T(j + 3), j + 3)), 7);
            SS2 = SS1 ^ ROTL(B, 12);
            TT1 = FF0(B, C, D) + A + SS2 + (W[j + 3] ^ W[j + 7]);
            TT2 = GG0(F, G, H) + E + SS1 + W[j + 3];
            A = D; D = ROTL(C, 9); C = B; B = TT1;
            E = H; H = ROTL(G, 19); G = F; F = P0(TT2);
        }

        state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
        state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
    }
};

// 性能测试函数
void test_performance(const char* name, SM3Base& sm3, const std::vector<uint8_t>& data) {
    const int iterations = 1000;
    const int data_size = data.size();

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        sm3.reset();
        sm3.update(data.data(), data_size);
        sm3.finalize();
        auto digest = sm3.digest();
    }
    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> diff = end - start;
    double total_bytes = static_cast<double>(iterations) * data_size;
    double speed = total_bytes / (diff.count() * 1024 * 1024); // MB/s

    std::cout << name << " 速度: " << std::fixed << std::setprecision(2)
        << speed << " MB/s" << std::endl;
}

// 打印十六进制
void print_hex(const std::vector<uint8_t>& bytes) {
    for (uint8_t b : bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
}

// 生成长文本
std::vector<uint8_t> generate_long_text(size_t length) {
    std::vector<uint8_t> data(length);
    for (size_t i = 0; i < length; i++) {
        data[i] = 'a' + (i % 26);
    }
    return data;
}

int main() {
    // 测试数据
    std::vector<uint8_t> empty;
    std::vector<uint8_t> abc = { 'a', 'b', 'c' };
    std::vector<uint8_t> long_text = generate_long_text(100000); // 100KB

    // 创建实例
    SM3Base base;
    SM3Opt opt;

    // 测试空字符串
    base.update(empty.data(), 0);
    base.finalize();
    auto base_digest = base.digest();
    std::cout << "基础版 SM3(\"\") = ";
    print_hex(base_digest);

    opt.update(empty.data(), 0);
    opt.finalize();
    auto opt_digest = opt.digest();
    std::cout << "优化版 SM3(\"\") = ";
    print_hex(opt_digest);
    std::cout << std::endl;

    // 测试"abc"
    base.reset();
    base.update(abc.data(), abc.size());
    base.finalize();
    base_digest = base.digest();
    std::cout << "基础版 SM3(\"abc\") = ";
    print_hex(base_digest);

    opt.reset();
    opt.update(abc.data(), abc.size());
    opt.finalize();
    opt_digest = opt.digest();
    std::cout << "优化版 SM3(\"abc\") = ";
    print_hex(opt_digest);
    std::cout << std::endl;

    // 性能测试
    std::cout << "\n性能测试 (100KB数据, 1000次迭代):" << std::endl;
    test_performance("基础版", base, long_text);
    test_performance("优化版", opt, long_text);

    return 0;
}
