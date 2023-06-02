#![cfg_attr(not(feature = "std"), no_std, no_main)]

pub mod traits;
pub mod types;
pub mod functions;

#[ink::contract]
mod omniverse_protocol {
    pub use super::traits::*;
    pub use super::types::*;
    pub use super::functions::*;
    use ink::prelude::collections::BTreeMap;
    pub const DEFAULT_CD: u64 = 10;

    #[ink(event)]
    pub struct TransactionSent {
        pk: [u8; 64],
        nonce: u128,
    }

    #[ink(event)]
    pub struct TransactionDuplicated {
        pk: [u8; 64],
        nonce: u128,
    }

    #[ink(event)]
    pub struct TransactionExecuted {
        pk: [u8; 64],
        nonce: u128,
    }

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct OmniverseProtocol {
        // Data for Ownable
        /// Account id of owner
        owner: Option<AccountId>,

        /// Account id of app contract
        app_contract: Option<AccountId>,

        /// Chain id
        chain_id: u32,
        /// Cooling down time
        cd_time: u64,
        /// Omniverse account records
        transaction_recorder: BTreeMap<[u8; 64], RecordedCertificate>,
        /// Transactions to be executed
        transaction_cache: BTreeMap<[u8; 64], OmniverseTx>,
    }

    impl Omniverse for OmniverseProtocol {
        /// Sends an omniverse transaction
        #[ink(message)]
        fn send_omniverse_transaction(&mut self, data: OmniverseTransactionData) -> Result<(), Error> {
            self.only_app_contract()?;
            // Check if the sender is malicious
            let rc_ret = self.transaction_recorder.get(&data.from);
            if let Some(rc) = rc_ret {
                if rc.evil_tx_list.len() > 0 {
                    return Err(Error::UserMalicious);
                }
            }

            // Verify the signature
            let ret = self.verify_transaction(&data);

            match ret {
                Ok(()) => {
                    // Check cache
                    let cache_ret = self.transaction_cache.get(&data.from);
                    if cache_ret.is_some() {
                        return Err(Error::TransactionCached);
                    }

                    let cache = OmniverseTx::new(data.clone(), self.env().block_timestamp());
                    // Logic verification
                    self.check_execution(&data);
                    self.transaction_cache.insert(data.from.clone(), cache);
                    Self::env().emit_event(TransactionSent {
                        pk: data.from,
                        nonce: data.nonce,
                    });
                }
                Err(Error::Duplicated) => {
                    Self::env().emit_event(TransactionDuplicated {
                        pk: data.from,
                        nonce: data.nonce,
                    });
                }
                Err(Error::Malicious) => {
                    // Slash
                }
                _ => {

                }
            }

            ret
        }

        /// Get the number of omniverse transactions sent by user `pk`
        #[ink(message)]
        fn get_transaction_count(&self, pk: [u8; 64]) -> u128 {
            let ret = self.transaction_recorder.get(&pk);
            match ret {
                None => 0,
                Some(rc) => rc.tx_list.len() as u128,
            }
        }

        /// Get the transaction data and timestamp of a user at a nonce
        #[ink(message)]
        fn get_transaction_data(&self, pk: [u8; 64], nonce: u128) -> OmniverseTx {
            let ret = self.transaction_recorder.get(&pk).expect("Record not found");
            ret.tx_list.get(nonce as usize).expect("Transaction data not found").clone()
        }

        /// Get the chain id
        #[ink(message)]
        fn get_chain_id(&self) -> u32 {
            self.chain_id
        }

        /// Get cached transaction
        #[ink(message)]
        fn get_cached_transaction(&self, pk: [u8; 64]) -> Option<OmniverseTx> {
            let cache = self.transaction_cache.get(&pk);
            match cache {
                Some(c) => Some(c.clone()),
                None => None
            }
        }

        /// Trigger execution
        #[ink(message)]
        fn trigger_execution(&mut self, pk: [u8; 64], nonce: u128) -> Result<(), Error> {
            self.only_app_contract()?;
            let cache = self.transaction_cache.get(&pk).ok_or(Error::TransactionNotCached)?;
            if cache.tx_data.nonce != nonce {
                return Err(Error::NonceNotMatch);
            }

            if cache.timestamp + self.cd_time < self.env().block_timestamp() {
                return Err(Error::CoolingDown);
            }
            let mut rc = self.transaction_recorder.get(&pk).unwrap_or(&RecordedCertificate::default()).clone();
            rc.tx_list.push(cache.clone());
            self.transaction_cache.remove(&pk);
            self.transaction_recorder.insert(pk.clone(), rc);                
            Self::env().emit_event(TransactionExecuted {
                pk,
                nonce,
            });
            Ok(())
        }
    }

    impl OmniverseProtocol {
        /// Constructor
        #[ink(constructor)]
        pub fn new(chain_id: u32) -> Self {
            let caller = Self::env().caller();
            Self {
                owner: Some(caller),
                app_contract: None,
                chain_id,
                cd_time: DEFAULT_CD,
                transaction_recorder: BTreeMap::new(),
                transaction_cache: BTreeMap::new(),
            }
        }

        #[ink(message)]
        pub fn set_app_contract(&mut self, account: AccountId) -> Result<(), Error> {
            self.only_owner()?;

            self.app_contract = Some(account);

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

        /// If the caller is the app contract
        fn only_app_contract(&self) -> Result<(), Error> {
            let caller = self.env().caller();
            if let Some(account) = self.app_contract {
                if account != caller {
                    return Err(Error::NotAppContract);
                }
            }
            else {
                return Err(Error::AppContractNotSet);                
            }

            Ok(())
        }

        fn check_execution(&self, data: &OmniverseTransactionData) -> Result<(), Error> {
            Ok(())
        }

        /// Verify an omniverse transaction
        fn verify_transaction(&mut self, data: &OmniverseTransactionData) -> Result<(), Error> {
            let raw_data = data.get_raw_data();
            let c_pk = compress_public_key(data.from);
            // Verify signature
            let sig = data
            .signature
            .clone()
            .try_into()
            .map_err(|_| Error::SerializePublicKeyFailed)?;
            if !self.verify_signature(&raw_data, sig, c_pk) {
                return Err(Error::WrongSignature);
            }

            // Check nonce
            let mut rc = self.transaction_recorder.get(&data.from).unwrap_or(& RecordedCertificate::default()).clone();
            let nonce = rc.tx_list.len() as u128;
            if nonce == data.nonce {
                return Ok(());
            }
            else if nonce > data.nonce {
                // The message has been received, check conflicts
                let his_tx: &OmniverseTx = rc.tx_list.get(data.nonce as usize).expect("Transaction not found");
                let his_hash = his_tx.tx_data.get_hash();
                let hash = data.get_hash();
                if his_hash != hash {
                    rc.evil_tx_list.push(EvilTxData::new(OmniverseTx::new(data.clone(), self.env().block_timestamp()), nonce));
                    self.transaction_recorder.insert(data.from, rc.clone());
                    return Err(Error::Malicious);
                }
                else {
                    return Err(Error::Duplicated);
                }
            }
            else {
                return Err(Error::NonceError);
            }
        }

        /// Verify signature
        fn verify_signature(&self, raw_data: &Vec<u8>, signature: [u8; 65], c_pk: [u8; 33]) -> bool {
            let mut hash = <ink::env::hash::Sha2x256 as ink::env::hash::HashOutput>::Type::default();
            ink::env::hash_bytes::<ink::env::hash::Sha2x256>(&raw_data, &mut hash);

            let mut compressed_pubkey = [0; 33];
            let ret = ink::env::ecdsa_recover(&signature, &hash, &mut compressed_pubkey);
            if ret.is_err() {
                return false;
            }

            c_pk == compressed_pubkey
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;
        use ink::env::{
            test::{self, default_accounts},
            DefaultEnvironment,
        };
        use secp256k1::rand::rngs::OsRng;
        use secp256k1::{ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};

        const signature: [u8; 65] = [
            119, 239,  67, 254,  77,  20, 200, 139, 106,  52, 180,
            113,   5,  87,  53, 109, 195, 208,  44, 145,  57, 206,
            32,  49, 154,  97, 194,  75, 128, 180, 187,  77, 103,
            117, 252, 208,  68, 198, 154,  45, 159, 113,   5,  83,
            206,  99,  41, 210, 144, 235,  48, 199,  57, 192,  38,
            105, 190,  24, 173, 145, 200, 110, 136,  86,  27
        ];

        const message_hash: [u8; 32] = [
            238, 229, 119, 112, 248,  69, 107, 141,
            74,  45, 169, 173,   2, 132,  54, 236,
            106,  98,  71, 118,  53, 193,  37, 113,
            246,  83, 204,  25,  86,  45,  95, 211
        ];

        const EXPECTED_COMPRESSED_PUBLIC_KEY: [u8; 33] = [
            2,144,101,32,18,128,96,228,162,202,76,18,107,219,5,157,35,133,125,153,254,81,97,69,51,241,57,23,173,207,216,227,161
        ];

        fn get_sig_slice(sig: &RecoverableSignature) -> [u8; 65] {
            let (recovery_id, sig_slice) = sig.serialize_compact();
            let mut sig_recovery: [u8; 65] = [0; 65];
            sig_recovery[0..64].copy_from_slice(&sig_slice);
            sig_recovery[64] = recovery_id.to_i32() as u8;
            sig_recovery
        }

        /// We test if the constructor does its job.
        #[ink::test]
        fn new_works() {
            let omniverse_protocol = OmniverseProtocol::new(0);
            assert_eq!(omniverse_protocol.get_chain_id(), 0);
        }

        /// We test a simple use case of our contract.
        #[ink::test]
        fn verify_signature_works() {
            let msg = "hello nika";
            let mut msg_hash = <ink::env::hash::Sha2x256 as ink::env::hash::HashOutput>::Type::default();
            ink::env::hash_bytes::<ink::env::hash::Sha2x256>(&msg.as_bytes(), &mut msg_hash);
            assert_eq!(msg_hash, message_hash);
            
            let mut omniverse_protocol = OmniverseProtocol::new(0);
            assert_eq!(omniverse_protocol.verify_signature(&ink::prelude::vec::Vec::from("error message".as_bytes()), signature, EXPECTED_COMPRESSED_PUBLIC_KEY), false);
            assert_eq!(omniverse_protocol.verify_signature(&ink::prelude::vec::Vec::from(msg.as_bytes()), signature, [0; 33]), false);
            assert_eq!(omniverse_protocol.verify_signature(&ink::prelude::vec::Vec::from(msg.as_bytes()), signature, EXPECTED_COMPRESSED_PUBLIC_KEY), true);
        }

        #[ink::test]
        fn set_app_contract_works() {
            let accounts = default_accounts::<DefaultEnvironment>();
            let mut omniverse_protocol = OmniverseProtocol::new(0);
            
            // Succeed
            assert_eq!(omniverse_protocol.set_app_contract(accounts.alice), Ok(()));

            // Caller not owner
            test::set_caller::<DefaultEnvironment>(accounts.bob);
            assert_eq!(omniverse_protocol.set_app_contract(accounts.alice), Err(Error::NotOwner));
        }

        #[ink::test]
        fn trigger_execution_works() {
            let accounts = default_accounts::<DefaultEnvironment>();
            let mut omniverse_protocol = OmniverseProtocol::new(0);
            // App contract not set
            assert_eq!(omniverse_protocol.trigger_execution([0_u8; 64], 0), Err(Error::AppContractNotSet));
            // Transaction not cached
            omniverse_protocol.set_app_contract(accounts.alice);
            assert_eq!(omniverse_protocol.trigger_execution([0_u8; 64], 0), Err(Error::TransactionNotCached));
            // Nonce not match
            let mut transaction_data = OmniverseTransactionData {
                nonce: 0,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: [0; 64],
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };
            omniverse_protocol.transaction_cache.insert(transaction_data.from, OmniverseTx::new(transaction_data.clone(), 0));
            assert_eq!(omniverse_protocol.trigger_execution(transaction_data.from, 1), Err(Error::NonceNotMatch));
            // Succeed
            assert_eq!(omniverse_protocol.trigger_execution(transaction_data.from, 0), Ok(()));
            assert_eq!(omniverse_protocol.get_transaction_count(transaction_data.from), 1);
            assert_eq!(omniverse_protocol.transaction_cache.get(&transaction_data.from).is_none(), true);
        }

        #[ink::test]
        fn send_omniverse_transaction_works() {
            let accounts = default_accounts::<DefaultEnvironment>();
            let mut transaction_data = OmniverseTransactionData {
                nonce: 0,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: [0; 64],
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };

            let mut omniverse_protocol = OmniverseProtocol::new(0);
            assert_eq!(omniverse_protocol.send_omniverse_transaction(transaction_data.clone()), Err(Error::AppContractNotSet));
            omniverse_protocol.set_app_contract(accounts.alice);
            assert_eq!(omniverse_protocol.send_omniverse_transaction(transaction_data.clone()), Err(Error::WrongSignature));

            let secp = Secp256k1::new();
            let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
		    let pk: [u8; 64] = public_key.serialize_uncompressed()[1..].try_into().expect("");
            transaction_data.from = pk;
            let message = Message::from_slice(transaction_data.get_hash().as_slice())
		    .expect("messages must be 32 bytes and are expected to be hashes");
            let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret_key);
	        let sig_recovery = get_sig_slice(&sig);
            transaction_data.signature = sig_recovery;
            assert_eq!(omniverse_protocol.send_omniverse_transaction(transaction_data.clone()), Ok(()));
            let trigger_ret = omniverse_protocol.trigger_execution(transaction_data.from, transaction_data.nonce);
            assert_eq!(trigger_ret, Ok(()));
            let count = omniverse_protocol.get_transaction_count(transaction_data.from);
            assert_eq!(count, 1);
            assert_eq!(omniverse_protocol.send_omniverse_transaction(transaction_data.clone()), Err(Error::Duplicated));

            transaction_data.nonce = 10;
            let message = Message::from_slice(transaction_data.get_hash().as_slice())
		    .expect("messages must be 32 bytes and are expected to be hashes");
            let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret_key);
	        let sig_recovery = get_sig_slice(&sig);
            transaction_data.signature = sig_recovery;
            assert_eq!(omniverse_protocol.send_omniverse_transaction(transaction_data.clone()), Err(Error::NonceError));
            
            transaction_data.chain_id = 10;
            transaction_data.nonce = 0;
            let message = Message::from_slice(transaction_data.get_hash().as_slice())
		    .expect("messages must be 32 bytes and are expected to be hashes");
            let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret_key);
	        let sig_recovery = get_sig_slice(&sig);
            transaction_data.signature = sig_recovery;
            assert_eq!(omniverse_protocol.send_omniverse_transaction(transaction_data.clone()), Err(Error::Malicious));

            assert_eq!(omniverse_protocol.send_omniverse_transaction(transaction_data.clone()), Err(Error::UserMalicious));
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
            let constructor = OmniverseProtocolRef::default();

            // When
            let contract_account_id = client
                .instantiate("omniverse_protocol", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // Then
            let get = build_message::<OmniverseProtocolRef>(contract_account_id.clone())
                .call(|omniverse_protocol| omniverse_protocol.get());
            let get_result = client.call_dry_run(&ink_e2e::alice(), &get, 0, None).await;
            assert!(matches!(get_result.return_value(), false));

            Ok(())
        }

        /// We test that we can read and write a value from the on-chain contract contract.
        #[ink_e2e::test]
        async fn it_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // Given
            let constructor = OmniverseProtocolRef::new(false);
            let contract_account_id = client
                .instantiate("omniverse_protocol", &ink_e2e::bob(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            let get = build_message::<OmniverseProtocolRef>(contract_account_id.clone())
                .call(|omniverse_protocol| omniverse_protocol.get());
            let get_result = client.call_dry_run(&ink_e2e::bob(), &get, 0, None).await;
            assert!(matches!(get_result.return_value(), false));

            // When
            let flip = build_message::<OmniverseProtocolRef>(contract_account_id.clone())
                .call(|omniverse_protocol| omniverse_protocol.flip());
            let _flip_result = client
                .call(&ink_e2e::bob(), flip, 0, None)
                .await
                .expect("flip failed");

            // Then
            let get = build_message::<OmniverseProtocolRef>(contract_account_id.clone())
                .call(|omniverse_protocol| omniverse_protocol.get());
            let get_result = client.call_dry_run(&ink_e2e::bob(), &get, 0, None).await;
            assert!(matches!(get_result.return_value(), true));

            Ok(())
        }
    }
}
