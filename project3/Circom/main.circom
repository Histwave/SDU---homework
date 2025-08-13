include "poseidon2_permutation.circom";

template Poseidon2Hash() {
    // 隐私输入：哈希原像 (1个域元素)
    signal input preimage;
    
    // 公开输出：哈希值 (1个域元素)
    signal output hash;
    
    // Sponge 初始化 (速率 r=2, 容量 c=1)
    signal state[3];
    state[0] <== preimage;  // 吸收
    state[1] <== 0;         // 容量
    state[2] <== 0;         // 未使用
    
    // 应用 Poseidon2 排列
    component perm = poseidon2_permutation();
    perm.in[0] <== state[0];
    perm.in[1] <== state[1];
    perm.in[2] <== state[2];
    
    // 挤压 (取第一个元素作为输出)
    hash <== perm.out[0];
}

component main {public [hash]} = Poseidon2Hash();