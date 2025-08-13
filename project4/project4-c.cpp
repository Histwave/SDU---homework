#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <cstdint>

// ============================== �԰����� SM3 ʵ�� ==============================
// ���� SM3 ��׼ʵ�֣��������ⲿ��

// ��ѭ����λ
inline uint32_t LEFT_ROTATE(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// SM3 ����
const uint32_t SM3_T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// SM3 ��ʼֵ
const uint32_t SM3_IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// ��������
uint32_t FF(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

uint32_t GG(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (~x & z));
}

// P0 �� P1 �û�����
uint32_t P0(uint32_t x) {
    return x ^ LEFT_ROTATE(x, 9) ^ LEFT_ROTATE(x, 17);
}

uint32_t P1(uint32_t x) {
    return x ^ LEFT_ROTATE(x, 15) ^ LEFT_ROTATE(x, 23);
}

// SM3 ��ϣ����
std::string sm3_hash(const std::string& data) {
    // ��ʼ��״̬
    uint32_t V[8];
    for (int i = 0; i < 8; i++) {
        V[i] = SM3_IV[i];
    }

    // �����Ϣ
    uint64_t len = data.size() * 8; // ԭʼ��Ϣ���� (bits)
    size_t blocks = ((len + 64 + 512 - 1) / 512); // ������� (ceil((len+64)/512))
    size_t total_len = blocks * 64; // ���ֽ��� (64 bytes per block)

    std::string padded(total_len, 0);
    std::copy(data.begin(), data.end(), padded.begin());
    padded[data.size()] = (char)0x80; // ���λ'1'

    // ��ӳ��� (�����)
    uint64_t bit_length = len;
    for (int i = 7; i >= 0; --i) {
        padded[total_len - 8 + i] = (bit_length >> (8 * (7 - i))) & 0xFF;
    }

    // ����ÿ��512λ��
    for (size_t i = 0; i < blocks; i++) {
        // ��Ϣ��չ
        uint32_t W[68] = { 0 };
        uint32_t W1[64] = { 0 };

        // ��512λ��ֳ�16��32λ��
        for (int j = 0; j < 16; j++) {
            size_t offset = i * 64 + j * 4;
            W[j] = ((uint8_t)padded[offset] << 24) |
                ((uint8_t)padded[offset + 1] << 16) |
                ((uint8_t)padded[offset + 2] << 8) |
                (uint8_t)padded[offset + 3];
        }

        // ��չ��Ϣ
        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ LEFT_ROTATE(W[j - 3], 15))
                ^ LEFT_ROTATE(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }

        // ѹ������
        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = LEFT_ROTATE((LEFT_ROTATE(A, 12) + E + LEFT_ROTATE(SM3_T[j], j)), 7);
            uint32_t SS2 = SS1 ^ LEFT_ROTATE(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = LEFT_ROTATE(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LEFT_ROTATE(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    // ת��Ϊ�ֽ�����
    std::string hash(32, 0);
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (V[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (V[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (V[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = V[i] & 0xFF;
    }

    return hash;
}

// ============================== Merkle ��ʵ�� ==============================
// ���� RFC6962 ��׼�� Merkle ��ʵ��

// ������ת��Ϊ8�ֽڴ���ַ���
std::string int_to_bytes(uint32_t n) {
    std::string bytes(8, 0);
    for (int i = 7; i >= 0; --i) {
        bytes[i] = static_cast<char>(n & 0xFF);
        n >>= 8;
    }
    return bytes;
}

// RFC6962 ��ϣ������װ
std::string rfc6962_hash_leaf(const std::string& data) {
    std::string prefix(1, 0x00); // Ҷ�ӽڵ�ǰ׺
    return sm3_hash(prefix + data);
}

std::string rfc6962_hash_node(const std::string& left, const std::string& right) {
    std::string prefix(1, 0x01); // �ڲ��ڵ�ǰ׺
    return sm3_hash(prefix + left + right);
}

// Merkle���ڵ�ṹ
struct MerkleNode {
    std::string hash;
    MerkleNode* left;
    MerkleNode* right;

    MerkleNode(const std::string& h) : hash(h), left(nullptr), right(nullptr) {}
    MerkleNode(const std::string& h, MerkleNode* l, MerkleNode* r) : hash(h), left(l), right(r) {}
};

// Merkle����
class MerkleTree {
private:
    MerkleNode* root;
    std::vector<MerkleNode*> leaves;
    std::vector<std::vector<MerkleNode*>> levels;

    // �ݹ�ɾ���ڵ�
    void deleteTree(MerkleNode* node) {
        if (!node) return;
        if (node->left) deleteTree(node->left);
        if (node->right) deleteTree(node->right);
        delete node;
    }

    // ������
    void buildTree() {
        if (leaves.empty()) {
            root = nullptr;
            return;
        }

        levels.clear();
        levels.push_back(leaves);

        std::vector<MerkleNode*> current = leaves;
        while (current.size() > 1) {
            std::vector<MerkleNode*> next_level;
            for (size_t i = 0; i < current.size(); i += 2) {
                MerkleNode* left = current[i];
                MerkleNode* right = (i + 1 < current.size()) ? current[i + 1] : nullptr;

                std::string combined_hash;
                if (right) {
                    combined_hash = rfc6962_hash_node(left->hash, right->hash);
                    next_level.push_back(new MerkleNode(combined_hash, left, right));
                }
                else {
                    // �����ڵ�������ڵ����Լ���ϣ
                    combined_hash = rfc6962_hash_node(left->hash, left->hash);
                    next_level.push_back(new MerkleNode(combined_hash, left, nullptr));
                }
            }
            levels.push_back(next_level);
            current = next_level;
        }
        root = current[0];
    }

public:
    MerkleTree(const std::vector<std::string>& leaf_data) {
        for (const auto& data : leaf_data) {
            leaves.push_back(new MerkleNode(rfc6962_hash_leaf(data)));
        }
        buildTree();
    }

    ~MerkleTree() {
        if (root) deleteTree(root);
    }

    // ��ȡ����ϣ
    std::string getRootHash() const {
        return root ? root->hash : "";
    }

    // ������֤��
    std::vector<std::pair<std::string, bool>> getExistenceProof(size_t leaf_index) {
        std::vector<std::pair<std::string, bool>> proof; // <hash, is_right>
        if (leaf_index >= leaves.size() || !root) return proof;

        size_t current_index = leaf_index;
        for (size_t level = 0; level < levels.size() - 1; ++level) {
            bool is_right = (current_index % 2 == 1);
            size_t sibling_index = is_right ? current_index - 1 : current_index + 1;

            // ����߽���������һ���ڵ㣩
            if (sibling_index >= levels[level].size()) {
                // ����㼶�ڵ����������ҵ�ǰ�����һ���ڵ�
                sibling_index = current_index; // ʹ��������Ϊ�ֵܽڵ�
            }

            proof.push_back(std::make_pair(levels[level][sibling_index]->hash, !is_right));
            current_index /= 2;
        }

        return proof;
    }

    // ��֤������֤��
    static bool verifyExistenceProof(
        const std::string& leaf_data,
        const std::vector<std::pair<std::string, bool>>& proof,
        const std::string& root_hash
    ) {
        std::string current_hash = rfc6962_hash_leaf(leaf_data);

        for (size_t i = 0; i < proof.size(); i++) {
            const std::string& sibling_hash = proof[i].first;
            bool is_right = proof[i].second;

            if (is_right) {
                // �ֵܽڵ����Ҳ�
                current_hash = rfc6962_hash_node(current_hash, sibling_hash);
            }
            else {
                // �ֵܽڵ������
                current_hash = rfc6962_hash_node(sibling_hash, current_hash);
            }
        }

        return current_hash == root_hash;
    }

    // ��������֤��
    std::pair<
        std::vector<std::pair<std::string, bool>>, // ǰ��֤��
        std::vector<std::pair<std::string, bool>>  // ���֤��
    > getNonExistenceProof(uint32_t target) {
        std::vector<std::pair<std::string, bool>> predecessor_proof;
        std::vector<std::pair<std::string, bool>> successor_proof;

        // ���������Ҷ������
        std::vector<uint32_t> sorted_indices;
        for (uint32_t i = 0; i < leaves.size(); i++) {
            sorted_indices.push_back(i);
        }

        // ����Ŀ��λ��
        auto it = std::lower_bound(sorted_indices.begin(), sorted_indices.end(), target);

        // ��ȡǰ���ͺ������
        size_t pred_index = leaves.size();
        size_t succ_index = leaves.size();

        if (it != sorted_indices.begin()) {
            pred_index = *(it - 1);
        }
        if (it != sorted_indices.end()) {
            succ_index = *it;
        }

        // ��ȡ֤��
        if (pred_index < leaves.size()) {
            predecessor_proof = getExistenceProof(pred_index);
        }
        if (succ_index < leaves.size()) {
            successor_proof = getExistenceProof(succ_index);
        }

        return std::make_pair(predecessor_proof, successor_proof);
    }
};

// ����ϣת��Ϊʮ�������ַ���
std::string hash_to_hex(const std::string& hash) {
    std::ostringstream ss;
    for (size_t i = 0; i < hash.size(); i++) {
        unsigned char c = static_cast<unsigned char>(hash[i]);
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

int main() {
    const size_t NUM_LEAVES = 100000; // 10��Ҷ�ӽڵ�

    // ����Ҷ�ӽڵ����ݣ�0��99999��������
    std::vector<std::string> leaf_data;
    leaf_data.reserve(NUM_LEAVES);
    for (uint32_t i = 0; i < NUM_LEAVES; ++i) {
        leaf_data.push_back(int_to_bytes(i));
    }

    std::cout << "�������� " << NUM_LEAVES << " ��Ҷ�ӵ� Merkle ��..." << std::endl;

    // ����Merkle��
    MerkleTree tree(leaf_data);
    std::string root_hash = tree.getRootHash();
    std::cout << "Merkle ����ϣ: " << hash_to_hex(root_hash) << "\n\n";

    // ������֤��ʾ��
    size_t test_index = 12345;
    auto existence_proof = tree.getExistenceProof(test_index);
    bool is_valid = MerkleTree::verifyExistenceProof(
        int_to_bytes(test_index), existence_proof, root_hash
    );
    std::cout << "Ҷ�� #" << test_index << " �Ĵ�����֤��: "
        << (is_valid ? "��Ч" : "��Ч") << "\n";
    std::cout << "֤��·������: " << existence_proof.size() << "\n\n";

    // ��������֤��ʾ��
    uint32_t non_existent = NUM_LEAVES; // ������Χ��Ҷ�ӽڵ�
    auto non_existence_proof = tree.getNonExistenceProof(non_existent);
    auto predecessor_proof = non_existence_proof.first;
    auto successor_proof = non_existence_proof.second;

    // ��֤ǰ��֤�������һ��Ҷ�ӣ�
    bool pred_valid = false;
    if (!predecessor_proof.empty()) {
        pred_valid = MerkleTree::verifyExistenceProof(
            int_to_bytes(NUM_LEAVES - 1), predecessor_proof, root_hash
        );
    }

    // ��֤���֤������ʵ�ʺ�̣�
    bool succ_valid = false;
    if (!successor_proof.empty()) {
        // �����ϣ����Ӧ���ǵ�һ������Ŀ��ֵ��Ҷ�ӣ���Ŀ��ֵ������Χ�������޺��
        succ_valid = false;
    }

    std::cout << "Ҷ�� #" << non_existent << " �Ĳ�������֤��:\n";
    std::cout << " - ǰ��֤��: " << (pred_valid ? "��Ч" : "��Ч")
        << " (·������: " << predecessor_proof.size() << ")\n";
    std::cout << " - ���֤��: " << (succ_valid ? "��Ч" : "��Ч")
        << " (·������: " << successor_proof.size() << ")\n";

    return 0;
}