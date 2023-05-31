use scale::{
    Encode,
    Decode,
};

#[derive(Debug, Decode, Encode, Clone, scale_info::TypeInfo)]
pub struct OmniverseTransactionData {
    pub nonce: u128,
    pub chain_id: u32,
    pub initiate_sc: Vec<u8>,
    pub from: [u8; 64],
    pub payload: Vec<u8>,
    pub signature: [u8; 65],
}

impl OmniverseTransactionData {
    pub fn get_raw_data(&self) -> Vec<u8> {
        let mut raw_buffer = ink::prelude::vec![];
        raw_buffer.append(&mut ink::prelude::vec::Vec::from(self.nonce.to_be_bytes()));
        raw_buffer.append(&mut ink::prelude::vec::Vec::from(self.chain_id.to_be_bytes()));
        raw_buffer.append(&mut self.initiate_sc.clone());
        raw_buffer.append(&mut ink::prelude::vec::Vec::from(self.from.clone()));
        raw_buffer.append(&mut self.payload.clone());
        raw_buffer
    }

    pub fn get_hash(&self) -> <ink::env::hash::Sha2x256 as ink::env::hash::HashOutput>::Type {
        let raw_data = self.get_raw_data();
        let mut hash = <ink::env::hash::Sha2x256 as ink::env::hash::HashOutput>::Type::default();
        ink::env::hash_bytes::<ink::env::hash::Sha2x256>(&raw_data, &mut hash);
        hash
    }
}

#[derive(Debug, Decode, Encode, Clone, scale_info::TypeInfo)]
pub struct OmniverseTx {
    pub tx_data: OmniverseTransactionData,
    pub timestamp: u64,
}

impl OmniverseTx {
    pub fn new(tx_data: OmniverseTransactionData, timestamp: u64) -> Self {
        Self {
            tx_data,
            timestamp,
        }
    }
}

#[derive(Debug, Decode, Encode, Clone, scale_info::TypeInfo)]
pub struct EvilTxData {
    o_data: OmniverseTx,
    his_nonce: u128,
}

impl EvilTxData {
    pub fn new(o_data: OmniverseTx, his_nonce: u128) -> Self {
        Self {
            o_data,
            his_nonce
        }
    }
}

#[derive(Debug, Decode, Encode, Clone, scale_info::TypeInfo)]
pub struct RecordedCertificate {
    pub tx_list: Vec<OmniverseTx>,
    pub evil_tx_list: Vec<EvilTxData>,
}

impl RecordedCertificate {
    pub fn default() -> Self {
        Self {
            tx_list: Vec::<OmniverseTx>::new(),
            evil_tx_list: Vec::<EvilTxData>::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Encode, Decode, Clone, scale_info::TypeInfo)]
pub enum Error {
    Malicious,
    Duplicated,
    WrongSignature,
    NonceError,
    SerializePublicKeyFailed,
}