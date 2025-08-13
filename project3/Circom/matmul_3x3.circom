template matmul_3x3() {
    signal input in[3];
    signal output out[3];
    
    // M = [[2,1,1], [1,2,1], [1,1,2]]
    out[0] <== 2*in[0] + in[1] + in[2];
    out[1] <== in[0] + 2*in[1] + in[2];
    out[2] <== in[0] + in[1] + 2*in[2];
}

component main = matmul_3x3();