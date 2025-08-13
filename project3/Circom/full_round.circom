include "sbox.circom";
include "matmul_3x3.circom";

template full_round() {
    signal input in[3];
    signal input constants[3];  // 轮常数
    signal output out[3];
    
    // 加轮常数 + S-box
    component sboxes[3];
    for (var i = 0; i < 3; i++) {
        sboxes[i] = sbox();
        sboxes[i].in <== in[i] + constants[i];
    }
    
    // 线性层
    component matmul = matmul_3x3();
    matmul.in[0] <== sboxes[0].out;
    matmul.in[1] <== sboxes[1].out;
    matmul.in[2] <== sboxes[2].out;
    
    out[0] <== matmul.out[0];
    out[1] <== matmul.out[1];
    out[2] <== matmul.out[2];
}

component main = full_round();