use crate::{
    OmniverseTransactionData,
    OmniverseTx,
    Error,
};

#[ink::trait_definition]
pub trait Omniverse {
    /// Sends an omniverse transaction
    #[ink(message)]
    fn send_omniverse_transaction(&mut self, data: OmniverseTransactionData) -> Result<(), Error>;
    /// Get the number of omniverse transactions sent by user `pk`
    #[ink(message)]
    fn get_transaction_count(&self, pk: [u8; 64]) -> u128;
    /// Get the transaction data and timestamp of a user at a nonce
    #[ink(message)]
    fn get_transaction_data(&self, pk: [u8; 64], nonce: u128) -> OmniverseTx;
    /// Get the chain id
    #[ink(message)]
    fn get_chain_id(&self) -> u32;
}