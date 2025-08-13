include "full_round.circom";
include "partial_round.circom";
include "matmul_3x3.circom";

template poseidon2_permutation() {
    signal input in[3];
    signal output out[3];
    
    // 初始线性层
    component init_matmul = matmul_3x3();
    init_matmul.in[0] <== in[0];
    init_matmul.in[1] <== in[1];
    init_matmul.in[2] <== in[2];
    
    // 轮常数 (示例值，实际需用论文中的值)
    var full_round_constants[8][3] = [
        [1, 2, 3], [4, 5, 6], [7, 8, 9], [10,11,12],
        [13,14,15], [16,17,18], [19,20,21], [22,23,24]
    ];
    
    var partial_round_constants[56] = [
        1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
        21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,
        39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56
    ];
    
    signal state[3];
    state[0] <== init_matmul.out[0];
    state[1] <== init_matmul.out[1];
    state[2] <== init_matmul.out[2];
    
    // 前4个完整轮
    component full_rounds1[4];
    for (var i = 0; i < 4; i++) {
        full_rounds1[i] = full_round();
        full_rounds1[i].constants[0] <== full_round_constants[i][0];
        full_rounds1[i].constants[1] <== full_round_constants[i][1];
        full_rounds1[i].constants[2] <== full_round_constants[i][2];
        
        if (i == 0) {
            full_rounds1[i].in[0] <== state[0];
            full_rounds1[i].in[1] <== state[1];
            full_rounds1[i].in[2] <== state[2];
        } else {
            full_rounds1[i].in[0] <== full_rounds1[i-1].out[0];
            full_rounds1[i].in[1] <== full_rounds1[i-1].out[1];
            full_rounds1[i].in[2] <== full_rounds1[i-1].out[2];
        }
    }
    
    // 56个部分轮
    component partial_rounds[56];
    for (var i = 0; i < 56; i++) {
        partial_rounds[i] = partial_round();
        partial_rounds[i].constant <== partial_round_constants[i];
        
        if (i == 0) {
            partial_rounds[i].in[0] <== full_rounds1[3].out[0];
            partial_rounds[i].in[1] <== full_rounds1[3].out[1];
            partial_rounds[i].in[2] <== full_rounds1[3].out[2];
        } else {
            partial_rounds[i].in[0] <== partial_rounds[i-1].out[0];
            partial_rounds[i].in[1] <== partial_rounds[i-1].out[1];
            partial_rounds[i].in[2] <== partial_rounds[i-1].out[2];
        }
    }
    
    // 后4个完整轮
    component full_rounds2[4];
    for (var i = 0; i < 4; i++) {
        full_rounds2[i] = full_round();
        full_rounds2[i].constants[0] <== full_round_constants[i+4][0];
        full_rounds2[i].constants[1] <== full_round_constants[i+4][1];
        full_rounds2[i].constants[2] <== full_round_constants[i+4][2];
        
        if (i == 0) {
            full_rounds2[i].in[0] <== partial_rounds[55].out[0];
            full_rounds2[i].in[1] <== partial_rounds[55].out[1];
            full_rounds2[i].in[2] <== partial_rounds[55].out[2];
        } else {
            full_rounds2[i].in[0] <== full_rounds2[i-1].out[0];
            full_rounds2[i].in[1] <== full_rounds2[i-1].out[1];
            full_rounds2[i].in[2] <== full_rounds2[i-1].out[2];
        }
    }
    
    out[0] <== full_rounds2[3].out[0];
    out[1] <== full_rounds2[3].out[1];
    out[2] <== full_rounds2[3].out[2];
}

component main = poseidon2_permutation();