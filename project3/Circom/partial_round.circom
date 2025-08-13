include "sbox.circom";
include "matmul_3x3.circom";

template partial_round() {
    signal input in[3];
    signal input constant;  // 轮常数 (仅第一个元素)
    signal output out[3];
    
    // 仅第一个元素加常数 + S-box
    component sbox0 = sbox();
    sbox0.in <== in[0] + constant;
    
    // 其他元素直通
    signal sbox_out[3];
    sbox_out[0] <== sbox0.out;
    sbox_out[1] <== in[1];
    sbox_out[2] <== in[2];
    
    // 线性层
    component matmul = matmul_3x3();
    matmul.in[0] <== sbox_out[0];
    matmul.in[1] <== sbox_out[1];
    matmul.in[2] <== sbox_out[2];
    
    out[0] <== matmul.out[0];
    out[1] <== matmul.out[1];
    out[2] <== matmul.out[2];
}

component main = partial_round();