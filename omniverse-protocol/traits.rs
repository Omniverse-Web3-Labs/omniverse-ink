use crate::{
    types::{
        OmniverseTransactionData,
        OmniverseTx,
        Error,
        Member,
    },
};
use ink::prelude::vec::Vec;

#[ink::trait_definition]
pub trait Omniverse {
    /// Get the number of omniverse transactions sent by user `pk`
    #[ink(message)]
    fn get_transaction_count(&self, pk: [u8; 64]) -> u128;
    /// Get the transaction data and timestamp of a user at a nonce
    #[ink(message)]
    fn get_transaction_data(&self, pk: [u8; 64], nonce: u128) -> Option<OmniverseTx>;
    /// Get the chain id
    #[ink(message)]
    fn get_chain_id(&self) -> u32;
    /// Get cached transaction
    #[ink(message)]
    fn get_cached_transaction(&self, pk: [u8; 64]) -> Option<OmniverseTx>;
    /// Set cooling down time
    #[ink(message)]
    fn set_cooling_down(&mut self, cd_time: u64) -> Result<(), Error>;
}

#[ink::trait_definition]
pub trait FungibleToken {
    /// Sends an omniverse transaction
    #[ink(message)]
    fn send_omniverse_transaction(&mut self, data: OmniverseTransactionData) -> Result<(), Error>;
    /// Trigger execution
    #[ink(message)]
    fn trigger_execution(&mut self) -> Result<(), Error>;
    /// Set members
    #[ink(message)]
    fn set_members(&mut self, members: Vec<Member>) -> Result<(), Error>;
    /// Get members
    #[ink(message)]
    fn get_members(&self) -> Vec<Member>;
    /// Get executable transaction
    #[ink(message)]
    fn get_executable_delayed_transaction(&self) -> Option<([u8; 64], u128)>;
    /// Get omniverse balance
    #[ink(message)]
    fn balance_of(&self, pk: [u8; 64]) -> u128;
}