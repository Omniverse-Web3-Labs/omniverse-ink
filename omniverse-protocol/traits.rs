use crate::{
    types::{
        OmniverseTransactionData,
        OmniverseTx,
        Error,
    },
};

#[ink::trait_definition]
pub trait Omniverse {
    /// Sends an omniverse transaction
    #[ink(message)]
    fn send_omniverse_transaction(&mut self, data: OmniverseTransactionData) -> Result<(), Error>;
    /// Trigger execution
    #[ink(message)]
    fn trigger_execution(&mut self, pk: [u8; 64], nonce: u128) -> Result<(), Error>;
    /// Get the number of omniverse transactions sent by user `pk`
    #[ink(message)]
    fn get_transaction_count(&self, pk: [u8; 64]) -> u128;
    /// Get the transaction data and timestamp of a user at a nonce
    #[ink(message)]
    fn get_transaction_data(&self, pk: [u8; 64], nonce: u128) -> OmniverseTx;
    /// Get the chain id
    #[ink(message)]
    fn get_chain_id(&self) -> u32;
    /// Get cached transaction
    #[ink(message)]
    fn get_cached_transaction(&self, pk: [u8; 64]) -> Option<OmniverseTx>;
}