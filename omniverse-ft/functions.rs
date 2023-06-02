pub fn compressed_pubkey_to_account(compressed_pubkey: [u8; 33]) -> ink::primitives::AccountId {
    let mut addr_hash = <ink::env::hash::Blake2x256 as ink::env::hash::HashOutput>::Type::default();
    ink::env::hash_encoded::<ink::env::hash::Blake2x256, _>(&compressed_pubkey, &mut addr_hash);
    ink::primitives::AccountId::from(addr_hash)
}