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

        // 消息扩展：将512位块转换为16个32位字
        for (int i = 0; i < 16; ++i) {
            W[i] = (block[i * 4 + 0] << 24) | (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        }

        // 扩展生成68个字
        for (int i = 16; i < 68; ++i) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^
                ROTL(W[i - 13], 7) ^ W[i - 6];
        }

        // 生成64个W'字
        for (int i = 0; i < 64; ++i) {
            W1[i] = W[i] ^ W[i + 4];
        }

        uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
        uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

        // 64轮压缩函数
        for (int j = 0; j < 64; ++j) {
            // 计算SS1和SS2
            uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T(j), j)), 7);
            uint32_t SS2 = SS1 ^ ROTL(A, 12);

            // 根据轮次选择布尔函数
            uint32_t TT1 = (j < 16) ?
                (FF0(A, B, C) + D + SS2 + W1[j]) :
                (FF1(A, B, C) + D + SS2 + W1[j]);

            uint32_t TT2 = (j < 16) ?
                (GG0(E, F, G) + H + SS1 + W[j]) :
                (GG1(E, F, G) + H + SS1 + W[j]);

            // 更新寄存器（标准顺序）
            D = C;
            C = ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 更新状态
        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }

    // 常量生成函数
    uint32_t T(int j) const {
        return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
    }

    uint32_t state[8];     // 哈希状态
    uint64_t count;        // 消息总比特数
    std::vector<uint8_t> buffer; // 输入缓冲区
};

class SM3Opt : public SM3Base {
protected:
    void compress(const uint8_t* block) override {
        uint32_t W[68];

        // 消息扩展：大端序处理
        for (int i = 0; i < 16; i++) {
            W[i] = (block[i * 4 + 0] << 24) | (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        }

        // 扩展生成68个字
        for (int i = 16; i < 68; i++) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^
                ROTL(W[i - 13], 7) ^ W[i - 6];
        }

        // 使用局部变量存储状态
        uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
        uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

        // 压缩函数 - 4轮展开优化
        for (int j = 0; j < 64; j++) {
            // 计算SS1和SS2
            uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T(j), j)), 7);
            uint32_t SS2 = SS1 ^ ROTL(A, 12);

            // 根据轮次选择布尔函数
            uint32_t TT1, TT2;
            if (j < 16) {
                TT1 = FF0(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
                TT2 = GG0(E, F, G) + H + SS1 + W[j];
            }
            else {
                TT1 = FF1(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
                TT2 = GG1(E, F, G) + H + SS1 + W[j];
            }

            // 更新寄存器（保持标准顺序）
            D = C;
            C = ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 更新状态
        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
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
    std::cout << "测试空字符串:\n";
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

    // 比较结果
    if (base_digest == opt_digest) {
        std::cout << "结果匹配!\n";
    }
    else {
        std::cout << "结果不匹配!\n";
    }
    std::cout << std::endl;

    // 测试"abc"
    std::cout << "测试\"abc\":\n";
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

    // 比较结果
    if (base_digest == opt_digest) {
        std::cout << "结果匹配!\n";
    }
    else {
        std::cout << "结果不匹配!\n";
    }
    std::cout << std::endl;

    // 性能测试
    std::cout << "性能测试 (100KB数据, 1000次迭代):\n";
    test_performance("基础版", base, long_text);
    test_performance("优化版", opt, long_text);

    return 0;
}
