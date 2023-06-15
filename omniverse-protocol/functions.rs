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

pub fn compressed_pubkey_to_account(compressed_pubkey: [u8; 33]) -> ink::primitives::AccountId {
    let mut addr_hash = <ink::env::hash::Keccak256 as ink::env::hash::HashOutput>::Type::default();
    ink::env::hash_encoded::<ink::env::hash::Keccak256, _>(&compressed_pubkey, &mut addr_hash);
    ink::primitives::AccountId::from(addr_hash)
}