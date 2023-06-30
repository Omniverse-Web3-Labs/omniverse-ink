use scale::{
    Encode,
    Decode,
};
use ink::prelude::vec::Vec;

#[derive(Debug, Decode, Encode, Clone)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct OmniverseTransactionData {
    pub nonce: u128,
    pub chain_id: u32,
    pub initiate_sc: Vec<u8>,
    pub from: [u8; 64],
    pub payload: Vec<u8>,
    pub signature: [u8; 65],
}

impl OmniverseTransactionData {
    pub fn get_raw_data(&self) -> Result<Vec<u8>, Error> {
        let mut raw_buffer = ink::prelude::vec![];
        raw_buffer.append(&mut ink::prelude::vec::Vec::from(self.nonce.to_be_bytes()));
        raw_buffer.append(&mut ink::prelude::vec::Vec::from(self.chain_id.to_be_bytes()));
        raw_buffer.append(&mut self.initiate_sc.clone());
        raw_buffer.append(&mut ink::prelude::vec::Vec::from(self.from));
        let payload = OmniverseFungible::decode(&mut self.payload.as_slice()).map_err(|_| Error::PayloadError)?;
        let mut raw_payload: Vec<u8> = payload.get_raw_data();
        raw_buffer.append(&mut raw_payload);
        Ok(raw_buffer)
    }

    pub fn get_hash(&self) -> Result<<ink::env::hash::Keccak256 as ink::env::hash::HashOutput>::Type, Error> {
        let raw_data = self.get_raw_data()?;
        let mut hash = <ink::env::hash::Keccak256 as ink::env::hash::HashOutput>::Type::default();
        ink::env::hash_bytes::<ink::env::hash::Keccak256>(&raw_data, &mut hash);
        Ok(hash)
    }
}

#[derive(Debug, Decode, Encode, Clone)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
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

#[derive(Debug, Decode, Encode, Clone)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
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

#[derive(Default, Debug, Decode, Encode, Clone)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct RecordedCertificate {
    pub tx_list: Vec<OmniverseTx>,
    pub evil_tx_list: Vec<EvilTxData>,
}

#[derive(Debug, Decode, Encode, Clone)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct Member {
    pub chain_id: u32,
    pub contract_address: Vec<u8>,
}

#[derive(Debug, Encode, Decode)]
pub struct OmniverseFungible {
    pub op: u8,
    pub ex_data: Vec<u8>,
    pub amount: u128,
}

impl OmniverseFungible {
    pub fn new(op: u8, ex_data: Vec<u8>, amount: u128) -> Self {
        Self {
            op,
            ex_data,
            amount,
        }
    }

    pub fn get_raw_data(&self) -> Vec<u8> {
        let mut raw_buffer = ink::prelude::vec![];
        raw_buffer.append(&mut ink::prelude::vec::Vec::from(self.op.to_be_bytes()));
        raw_buffer.append(&mut self.ex_data.clone());
        raw_buffer.append(&mut ink::prelude::vec::Vec::from(self.amount.to_be_bytes()));
        raw_buffer
    }

    pub fn get_account(&self) -> [u8; 64] {
        let mut ret = [0_u8; 64];
        ret.copy_from_slice(self.ex_data.as_slice());
        ret
    }
}

#[derive(Debug, PartialEq, Eq, Encode, Decode, Clone)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum Error {
    Malicious,
    UserMalicious,
    Duplicated,
    WrongSignature,
    NonceError,
    SerializePublicKeyFailed,
    TransactionCached,
    TransactionNotCached,
    NonceNotMatch,
    CoolingDown,
    NotOwner,
    NoDelayedTx,
    NotCached,
    PayloadError,
    ExceedBalance,
    NotMember,
    WrongInitiator,
    WrongOpCode,
}