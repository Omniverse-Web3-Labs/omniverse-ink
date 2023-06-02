#![cfg_attr(not(feature = "std"), no_std, no_main)]

pub mod traits;
pub mod types;
pub mod functions;

#[ink::contract]
mod omniverse_ft {
    use super::traits::*;
    use super::types::*;
    use super::functions::*;
    use omniverse_protocol::types::{
        OmniverseTransactionData,
    };
    use ink::prelude::collections::BTreeMap;
    use ink::prelude::{
        string::String,
        vec::Vec,
    };
    use omniverse_protocol::{
        functions::compress_public_key,
    };

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct OmniverseFt {
        /// Account id of owner
        owner: Option<AccountId>,
        /// Token name
        name: String,
        /// Token symbol
        symbol: String,
        /// Balances of users
        omniverse_balances: BTreeMap<[u8; 64], u128>,
        /// Transactions to be executed later
        delayed_txs: Vec<([u8; 64], u128)>,
        /// Omniverse protocol account
        omniverse_protocol_account: Option<AccountId>,
        /// Token members
        members: BTreeMap<u32, Member>,
    }

    impl OmniverseFt {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(name: String, symbol: String) -> Self {
            let caller = Self::env().caller();
            Self {
                owner: Some(caller),
                name,
                symbol,
                omniverse_balances: BTreeMap::<[u8; 64], u128>::new(),
                delayed_txs: Vec::<([u8; 64], u128)>::new(),
                omniverse_protocol_account: None,
                members: BTreeMap::<u32, Member>::new(),
             }
        }

        #[ink(message)]
        pub fn send_omniverse_transaction(&mut self, data: OmniverseTransactionData) -> Result<(), Error> {
            if self.omniverse_protocol_account.is_none() {
                return Err(Error::ProtocolContractNotSet);
            }

            let member = self.members.get(&data.chain_id).ok_or(Error::NotMember)?;
            if member.contract_address != data.initiate_sc {
                return Err(Error::WrongInitiator);
            }

            let wrapped_op = WrappedOmniverseProtocol::new(self.omniverse_protocol_account.unwrap());
            wrapped_op.send_omniverse_transaction(data)
        }

        #[ink(message)]
        pub fn trigger_execution(&mut self) -> Result<(), Error> {
            if self.omniverse_protocol_account.is_none() {
                return Err(Error::ProtocolContractNotSet);
            }
            
            if self.delayed_txs.len() == 0 {
                return Err(Error::NoDelayedTx);
            }

            let wrapped_op = WrappedOmniverseProtocol::new(self.omniverse_protocol_account.unwrap());
            let cache_ret = wrapped_op.get_cached_data(self.delayed_txs[0].0);
            if let Some(cache) = cache_ret {
                if cache.tx_data.nonce != self.delayed_txs[0].1 {
                    return Err(Error::NonceError);
                }
                self.delayed_txs.remove(0);
                wrapped_op.trigger_execution(cache.tx_data.from, cache.tx_data.nonce)?;
                let payload: OmniverseFungible = scale::Decode::decode(&mut cache.tx_data.payload.as_slice()).map_err(|_| Error::PayloadError)?;
                match payload.op {
                    0 => self.omniverse_transfer(cache.tx_data.from, payload.ex_data, payload.amount)?,
                    1 => {
                        self.check_owner(cache.tx_data.from)?;
                        self.omniverse_mint(payload.ex_data, payload.amount)?;
                    },
                    2 => {
                        self.check_owner(cache.tx_data.from)?;
                        self.omniverse_burn(payload.ex_data, payload.amount)?;
                    },
                    _ => {},
                };
            }
            else {
                return Err(Error::NotCached);
            }

            Ok(())
        }

        #[ink(message)]
        pub fn set_members(&mut self, members: Vec<Member>) -> Result<(), Error> {
            self.only_owner()?;
            self.members.clear();
            for m in members.iter() {
                self.members.insert(m.chain_id, m.clone());
            }
            Ok(())
        }

        /// If the caller is the owner of the contract
        fn only_owner(&self) -> Result<(), Error> {
            let caller = self.env().caller();
            if self.owner.unwrap() != caller {
                return Err(Error::NotOwner);
            }

            Ok(())
        }

        fn check_owner(&self, pk: [u8; 64]) -> Result<(), Error> {
            let compressed_pubkey = compress_public_key(pk);
            let account_id = compressed_pubkey_to_account(compressed_pubkey);
            if account_id != self.owner.unwrap() {
                return Err(Error::NotOwner);
            }

            Ok(())
        }

        fn check_omniverse_transfer(&self, from: [u8; 64], amount: u128) -> Result<(), Error> {
            let balance = self.omniverse_balances.get(&from).unwrap_or(&0).clone();
            match balance > amount {
                true => Err(Error::ExceedBalance),
                false => Ok(()),
            }
        }

        fn omniverse_transfer(&mut self, from: [u8; 64], to: [u8; 64], amount: u128) -> Result<(), Error> {
            self.check_omniverse_transfer(from, amount)?;

            let from_balance = self.omniverse_balances.get(&from).unwrap().clone();
            let to_balance = self.omniverse_balances.get(&to).unwrap().clone();
            self.omniverse_balances.insert(from, from_balance - amount);
            self.omniverse_balances.insert(to, to_balance + amount);
            Ok(())
        }

        fn omniverse_mint(&mut self, to: [u8; 64], amount: u128) -> Result<(), Error> {
            let to_balance = self.omniverse_balances.get(&to).unwrap_or(&0);
            self.omniverse_balances.insert(to, to_balance + amount);
            Ok(())
        }

        fn check_omniverse_burn(&self, from: [u8; 64], amount: u128) -> Result<(), Error> {
            let balance = self.omniverse_balances.get(&from).unwrap_or(&0).clone();
            match balance > amount {
                true => Err(Error::ExceedBalance),
                false => Ok(()),
            }
        }

        fn omniverse_burn(&mut self, from: [u8; 64], amount: u128) -> Result<(), Error> {
            self.check_omniverse_burn(from, amount)?;

            let from_balance = self.omniverse_balances.get(&from).unwrap();
            self.omniverse_balances.insert(from, from_balance - amount);
            Ok(())
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// We test if the default constructor does its job.
        #[ink::test]
        fn default_works() {
            let omniverse_ft = OmniverseFt::default();
            assert_eq!(omniverse_ft.get(), false);
        }

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {
            let mut omniverse_ft = OmniverseFt::new(false);
            assert_eq!(omniverse_ft.get(), false);
            omniverse_ft.flip();
            assert_eq!(omniverse_ft.get(), true);
        }
    }


    /// This is how you'd write end-to-end (E2E) or integration tests for ink! contracts.
    ///
    /// When running these you need to make sure that you:
    /// - Compile the tests with the `e2e-tests` feature flag enabled (`--features e2e-tests`)
    /// - Are running a Substrate node which contains `pallet-contracts` in the background
    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// A helper function used for calling contract messages.
        use ink_e2e::build_message;

        /// The End-to-End test `Result` type.
        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        /// We test that we can upload and instantiate the contract using its default constructor.
        #[ink_e2e::test]
        async fn default_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // Given
            let constructor = OmniverseFtRef::default();

            // When
            let contract_account_id = client
                .instantiate("omniverse_ft", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // Then
            let get = build_message::<OmniverseFtRef>(contract_account_id.clone())
                .call(|omniverse_ft| omniverse_ft.get());
            let get_result = client.call_dry_run(&ink_e2e::alice(), &get, 0, None).await;
            assert!(matches!(get_result.return_value(), false));

            Ok(())
        }

        /// We test that we can read and write a value from the on-chain contract contract.
        #[ink_e2e::test]
        async fn it_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // Given
            let constructor = OmniverseFtRef::new(false);
            let contract_account_id = client
                .instantiate("omniverse_ft", &ink_e2e::bob(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            let get = build_message::<OmniverseFtRef>(contract_account_id.clone())
                .call(|omniverse_ft| omniverse_ft.get());
            let get_result = client.call_dry_run(&ink_e2e::bob(), &get, 0, None).await;
            assert!(matches!(get_result.return_value(), false));

            // When
            let flip = build_message::<OmniverseFtRef>(contract_account_id.clone())
                .call(|omniverse_ft| omniverse_ft.flip());
            let _flip_result = client
                .call(&ink_e2e::bob(), flip, 0, None)
                .await
                .expect("flip failed");

            // Then
            let get = build_message::<OmniverseFtRef>(contract_account_id.clone())
                .call(|omniverse_ft| omniverse_ft.get());
            let get_result = client.call_dry_run(&ink_e2e::bob(), &get, 0, None).await;
            assert!(matches!(get_result.return_value(), true));

            Ok(())
        }
    }
}
