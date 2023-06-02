use omniverse_protocol::types::{
    OmniverseTransactionData,
    OmniverseTx
};
use scale::{
    Encode,
    Decode,
};

#[derive(Debug, PartialEq, Eq, Encode, Decode, Clone, scale_info::TypeInfo)]
pub enum Error {
    NoDelayedTx,
    NotCached,
    NonceError,
    PayloadError,
    ExceedBalance,
    NotMember,
    WrongInitiator,
    ProtocolContractNotSet,
    NotOwner,
}

#[derive(Debug, Decode, Encode, Clone, scale_info::TypeInfo)]
pub struct Member {
    pub chain_id: u32,
    pub contract_address: Vec<u8>,
}

#[derive(Encode, Decode)]
pub struct OmniverseFungible {
    pub op: u8,
    pub ex_data: [u8; 64],
    pub amount: u128,
}

impl OmniverseFungible {
    pub fn new(op: u8, ex_data: [u8; 64], amount: u128) -> Self {
        Self {
            op,
            ex_data,
            amount,
        }
    }
}

const GET_CACHED_DATA: [u8; 4] = [0_u8; 4];
const SEND_OMNIVERSE_TRANSACTION: [u8; 4] = [0_u8; 4];
const TRIGGER_EXECUTION: [u8; 4] = [0_u8; 4];

pub struct WrappedOmniverseProtocol {
    account: ink::primitives::AccountId,
}

impl WrappedOmniverseProtocol {
    pub fn new(account: ink::primitives::AccountId) -> Self {
        Self {
            account,
        }
    }

    pub fn get_cached_data(&self, pk: [u8; 64]) -> Option<OmniverseTx> {
        ink::env::call::build_call::<ink::env::DefaultEnvironment>()
            .call(self.account)
            .gas_limit(0)
            .transferred_value(0)
            .exec_input(
                ink::env::call::ExecutionInput::new(ink::env::call::Selector::new(GET_CACHED_DATA))
                .push_arg(pk)
            )
            .returns::<Option<OmniverseTx>>()
            .invoke()
    }

    pub fn send_omniverse_transaction(&self, data: OmniverseTransactionData) -> Result<(), Error> {
        ink::env::call::build_call::<ink::env::DefaultEnvironment>()
            .call(self.account)
            .gas_limit(0)
            .transferred_value(0)
            .exec_input(
                ink::env::call::ExecutionInput::new(ink::env::call::Selector::new(SEND_OMNIVERSE_TRANSACTION))
                .push_arg(data)
            )
            .returns::<Result<(), omniverse_protocol::types::Error>>()
            .invoke()
            .map_err(|_| Error::NoDelayedTx)
    }

    pub fn trigger_execution(&self, pk: [u8; 64], nonce: u128) -> Result<(), Error> {
        ink::env::call::build_call::<ink::env::DefaultEnvironment>()
            .call(self.account)
            .gas_limit(0)
            .transferred_value(0)
            .exec_input(
                ink::env::call::ExecutionInput::new(ink::env::call::Selector::new(TRIGGER_EXECUTION))
                .push_arg(pk)
                .push_arg(nonce)
            )
            .returns::<Result<(), omniverse_protocol::types::Error>>()
            .invoke()
            .map_err(|_| Error::NoDelayedTx)
    }
}