template sbox() {
    signal input in;
    signal output out;
    
    signal s2 <== in * in;
    signal s4 <== s2 * s2;
    out <== s4 * in;  // x^5
}

component main = sbox();