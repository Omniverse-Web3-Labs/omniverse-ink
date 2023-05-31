pub fn compress_public_key(pk: [u8; 64]) -> [u8; 33] {
    let mut ret: [u8; 33] = [0; 33];
    ret[1..33].copy_from_slice(&pk[0..32]);
    if pk[63] % 2 == 0 {
        ret[0] = 2;
    }
    else {
        ret[0] = 3;
    }
    ret
}