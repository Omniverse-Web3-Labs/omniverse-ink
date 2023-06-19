#![cfg_attr(not(feature = "std"), no_std, no_main)]

pub mod traits;
pub mod types;
pub mod functions;

#[ink::contract]
mod omniverse_protocol {
    pub use super::traits::*;
    pub use super::types::*;
    pub use super::functions::*;
    use ink::prelude::{
        vec::Vec,
        collections::BTreeMap,
        string::String,
    };
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
        owner: AccountId,

        // Properties for omniverse protocol
        /// Chain id
        chain_id: u32,
        /// Cooling down time
        cd_time: u64,
        /// Omniverse account records
        transaction_recorder: BTreeMap<[u8; 64], RecordedCertificate>,
        /// Transactions to be executed
        transaction_cache: BTreeMap<[u8; 64], OmniverseTx>,

        // Properties for fungible token
        /// Token name
        name: String,
        /// Token symbol
        symbol: String,
        /// Balances of users
        omniverse_balances: BTreeMap<[u8; 64], u128>,
        /// Transactions to be executed later
        delayed_txs: Vec<([u8; 64], u128)>,
        /// Token members
        members: BTreeMap<u32, Member>,
    }

    impl Omniverse for OmniverseProtocol {
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
        fn get_transaction_data(&self, pk: [u8; 64], nonce: u128) -> Option<OmniverseTx> {
            let ret = self.transaction_recorder.get(&pk);
            match ret {
                None => None,
                Some(&ref record) => {
                    match record.tx_list.get(nonce as usize) {
                        None => None,
                        Some(&ref data) => Some(data.clone()),
                    }
                },
            }
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

        /// Set cooling down time
        #[ink(message)]
        fn set_cooling_down(&mut self, cd_time: u64) -> Result<(), Error> {
            self.only_owner()?;
            self.cd_time = cd_time;
            Ok(())
        }
    }

    impl FungibleToken for OmniverseProtocol {
        /// Sends an omniverse transaction
        #[ink(message)]
        fn send_omniverse_transaction(&mut self, data: OmniverseTransactionData) -> Result<(), Error> {
            let member = self.members.get(&data.chain_id).ok_or(Error::NotMember)?;
            if member.contract_address != data.initiate_sc {
                return Err(Error::WrongInitiator);
            }

            let ret = self.send_omniverse_transaction_internal(data.clone());
            if ret == Ok(()) {
                self.delayed_txs.push((data.from, data.nonce));
            }
            ret
        }
        
        /// Trigger execution
        #[ink(message)]
        fn trigger_execution(&mut self) -> Result<(), Error> {            
            if self.delayed_txs.len() == 0 {
                return Err(Error::NoDelayedTx);
            }

            let cache_ret = self.get_cached_transaction(self.delayed_txs[0].0);
            if let Some(cache) = cache_ret {
                if cache.tx_data.nonce != self.delayed_txs[0].1 {
                    return Err(Error::NonceError);
                }
                self.delayed_txs.remove(0);
                self.trigger_execution_internal(cache.tx_data.from, cache.tx_data.nonce)?;
                let payload: OmniverseFungible = scale::Decode::decode(&mut cache.tx_data.payload.as_slice()).map_err(|_| Error::PayloadError)?;
                match payload.op {
                    0 => self.omniverse_transfer(cache.tx_data.from, payload.get_account(), payload.amount)?,
                    1 => {
                        self.check_owner(cache.tx_data.from)?;
                        self.omniverse_mint(payload.get_account(), payload.amount)?;
                    },
                    2 => {
                        self.check_owner(cache.tx_data.from)?;
                        self.omniverse_burn(payload.get_account(), payload.amount)?;
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
        fn set_members(&mut self, members: Vec<Member>) -> Result<(), Error> {
            self.only_owner()?;
            self.members.clear();
            for m in members.iter() {
                self.members.insert(m.chain_id, m.clone());
            }
            Ok(())
        }

        #[ink(message)]
        fn get_members(&self) -> Vec<Member> {
            let mut ret = Vec::<Member>::new();
            for (_, value) in self.members.iter() {
                ret.push(value.clone());
            }
            ret
        }

        /// Get executable transaction
        #[ink(message)]
        fn get_executable_delayed_transaction(&self) -> Option<([u8; 64], u128)> {
            if self.delayed_txs.len() > 0 {
                let cache = self.get_cached_transaction(self.delayed_txs[0].0).unwrap();
                if self.env().block_timestamp() >= cache.timestamp + self.cd_time {
                    return Some(self.delayed_txs[0].clone());
                }
            }
            None
        }

        /// Get omniverse balance
        #[ink(message)]
        fn balance_of(&self, pk: [u8; 64]) -> u128 {
            self.omniverse_balances.get(&pk).unwrap_or(&0).clone()
        }
    }

    impl OmniverseProtocol {
        /// Constructor
        #[ink(constructor)]
        pub fn new(chain_id: u32, owner: [u8; 64], name: String, symbol: String) -> Self {
            let compressed_pubkey = compress_public_key(owner);
            let account_id = compressed_pubkey_to_account(compressed_pubkey);
            Self {
                owner: account_id,
                chain_id,
                cd_time: DEFAULT_CD,
                transaction_recorder: BTreeMap::new(),
                transaction_cache: BTreeMap::new(),
                name,
                symbol,
                omniverse_balances: BTreeMap::new(),
                delayed_txs: Vec::<([u8; 64], u128)>::new(),
                members: BTreeMap::new(),
            }
        }

        //======================functions for omniverse protocol========================
        /// Verify an omniverse transaction
        fn send_omniverse_transaction_internal(&mut self, data: OmniverseTransactionData) -> Result<(), Error> {
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
                    self.check_execution(&data)?;
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

        fn trigger_execution_internal(&mut self, pk: [u8; 64], nonce: u128) -> Result<(), Error> {
            let cache = self.transaction_cache.get(&pk).ok_or(Error::TransactionNotCached)?;
            if cache.tx_data.nonce != nonce {
                return Err(Error::NonceNotMatch);
            }

            if cache.timestamp + self.cd_time > self.env().block_timestamp() {
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

        fn verify_transaction(&mut self, data: &OmniverseTransactionData) -> Result<(), Error> {
            let raw_data = data.get_raw_data()?;
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
                let his_hash = his_tx.tx_data.get_hash()?;
                let hash = data.get_hash()?;
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
            let mut hash = <ink::env::hash::Keccak256 as ink::env::hash::HashOutput>::Type::default();
            ink::env::hash_bytes::<ink::env::hash::Keccak256>(&raw_data, &mut hash);

            let mut compressed_pubkey = [0; 33];
            let ret = ink::env::ecdsa_recover(&signature, &hash, &mut compressed_pubkey);
            if ret.is_err() {
                return false;
            }

            c_pk == compressed_pubkey
        }

        /// If the caller is the owner of the contract
        fn only_owner(&self) -> Result<(), Error> {
            let caller = self.env().caller();
            if self.owner != caller {
                return Err(Error::NotOwner);
            }

            Ok(())
        }

        //======================functions for fungible token========================
        fn check_owner(&self, pk: [u8; 64]) -> Result<(), Error> {
            let compressed_pubkey = compress_public_key(pk);
            let account_id = compressed_pubkey_to_account(compressed_pubkey);
            if account_id != self.owner {
                return Err(Error::NotOwner);
            }

            Ok(())
        }

        fn check_omniverse_transfer(&self, from: [u8; 64], amount: u128) -> Result<(), Error> {
            let balance = self.omniverse_balances.get(&from).unwrap_or(&0).clone();
            match balance < amount {
                true => Err(Error::ExceedBalance),
                false => Ok(()),
            }
        }

        fn omniverse_transfer(&mut self, from: [u8; 64], to: [u8; 64], amount: u128) -> Result<(), Error> {
            self.check_omniverse_transfer(from, amount)?;

            let from_balance = self.omniverse_balances.get(&from).unwrap().clone();
            let to_balance = self.omniverse_balances.get(&to).unwrap_or(&0).clone();
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
            match balance < amount {
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

        fn check_execution(&self, data: &OmniverseTransactionData) -> Result<(), Error> {
            let payload: OmniverseFungible = scale::Decode::decode(&mut data.payload.as_slice()).map_err(|_| Error::PayloadError)?;
            match payload.op {
                0 => self.check_omniverse_transfer(data.from, payload.amount)?,
                1 => {
                    self.check_owner(data.from)?;
                },
                2 => {
                    self.check_owner(data.from)?;
                    self.check_omniverse_burn(payload.get_account(), payload.amount)?;
                },
                _ => return Err(Error::WrongOpCode),
            };
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
        use scale::{
            Encode,
        };
        use ink::env::{
            test::{self},
            DefaultEnvironment,
        };
        use secp256k1::rand::rngs::OsRng;
        use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1};

        const OWNER_PK: [u8; 64] = [0; 64];
        const USER_PK: [u8; 64] = [1; 64];

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
            let omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            assert_eq!(omniverse_protocol.get_chain_id(), 0);
        }

        //=================== Check non-message functions ======================
        // For fungible tokens
        #[ink::test]
        fn check_owner_works() {
            let omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            
            assert_eq!(omniverse_protocol.check_owner(USER_PK), Err(Error::NotOwner));
            test::set_caller::<DefaultEnvironment>(compressed_pubkey_to_account(compress_public_key(OWNER_PK)));
            assert_eq!(omniverse_protocol.check_owner(OWNER_PK), Ok(()));
        }

        #[ink::test]
        fn check_omniverse_burn_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            // Exceed balance
            assert_eq!(omniverse_protocol.check_omniverse_burn(USER_PK, 1000), Err(Error::ExceedBalance));
            // Enough balance
            omniverse_protocol.omniverse_balances.insert(USER_PK, 1000);
            assert_eq!(omniverse_protocol.check_omniverse_burn(USER_PK, 1000), Ok(()));
        }

        #[ink::test]
        fn check_omniverse_transfer_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            // Exceed balance
            assert_eq!(omniverse_protocol.check_omniverse_transfer(USER_PK, 1000), Err(Error::ExceedBalance));
            // Enough balance
            omniverse_protocol.omniverse_balances.insert(USER_PK, 1000);
            assert_eq!(omniverse_protocol.check_omniverse_transfer(USER_PK, 1000), Ok(()));
        }

        #[ink::test]
        fn omniverse_transfer_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());

            omniverse_protocol.omniverse_balances.insert(USER_PK, 1000);
            assert_eq!(omniverse_protocol.omniverse_transfer(USER_PK, OWNER_PK, 1000), Ok(()));
            let balance = omniverse_protocol.omniverse_balances.get(&USER_PK).unwrap().clone();
            assert_eq!(balance, 0);
            let balance = omniverse_protocol.omniverse_balances.get(&OWNER_PK).unwrap().clone();
            assert_eq!(balance, 1000);
        }

        #[ink::test]
        fn omniverse_mint_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());

            assert_eq!(omniverse_protocol.omniverse_mint(USER_PK, 1000), Ok(()));
            let balance = omniverse_protocol.omniverse_balances.get(&USER_PK).unwrap().clone();
            assert_eq!(balance, 1000);
        }

        #[ink::test]
        fn omniverse_burn_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());

            omniverse_protocol.omniverse_balances.insert(USER_PK, 1000);
            assert_eq!(omniverse_protocol.omniverse_burn(USER_PK, 1000), Ok(()));
            let balance = omniverse_protocol.omniverse_balances.get(&USER_PK).unwrap().clone();
            assert_eq!(balance, 0);
        }

        #[ink::test]
        fn check_execution_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            let mut transaction_data = OmniverseTransactionData {
                nonce: 0,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: OWNER_PK,
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };

            // Payload error
            assert_eq!(omniverse_protocol.check_execution(&transaction_data), Err(Error::PayloadError));

            // Op code error
            let mut payload_item = OmniverseFungible::new(10, USER_PK.to_vec(), 100);
            transaction_data.payload = payload_item.encode();
            assert_eq!(omniverse_protocol.check_execution(&transaction_data), Err(Error::WrongOpCode));
            
            // Transfer
            payload_item.op = 0;
            omniverse_protocol.omniverse_balances.insert(OWNER_PK, 100);
            transaction_data.payload = payload_item.encode();
            assert_eq!(omniverse_protocol.check_execution(&transaction_data), Ok(()));

            // Mint
            payload_item.op = 1;
            transaction_data.payload = payload_item.encode();
            test::set_caller::<DefaultEnvironment>(compressed_pubkey_to_account(compress_public_key(OWNER_PK)));
            assert_eq!(omniverse_protocol.check_execution(&transaction_data), Ok(()));

            // Burn
            payload_item.op = 0;
            transaction_data.from = OWNER_PK;
            omniverse_protocol.omniverse_balances.insert(OWNER_PK, 100);
            transaction_data.payload = payload_item.encode();
            assert_eq!(omniverse_protocol.check_execution(&transaction_data), Ok(()));
        }

        // For omniverse protocol
        #[ink::test]
        fn verify_signature_works() {
            let msg = "hello nika";
            let mut msg_hash = <ink::env::hash::Keccak256 as ink::env::hash::HashOutput>::Type::default();
            ink::env::hash_bytes::<ink::env::hash::Keccak256>(&msg.as_bytes(), &mut msg_hash);
            
            let secp = Secp256k1::new();
            let omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
            let pk: [u8; 64] = public_key.serialize_uncompressed()[1..].try_into().expect("");
            let message = Message::from_slice(&msg_hash[..])
		    .expect("messages must be 32 bytes and are expected to be hashes");
            let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret_key);
	        let sig_recovery = get_sig_slice(&sig);
            assert_eq!(omniverse_protocol.verify_signature(&ink::prelude::vec::Vec::from("error message".as_bytes()), sig_recovery, compress_public_key(pk)), false);
            assert_eq!(omniverse_protocol.verify_signature(&ink::prelude::vec::Vec::from(msg.as_bytes()), sig_recovery, [0; 33]), false);
            assert_eq!(omniverse_protocol.verify_signature(&ink::prelude::vec::Vec::from(msg.as_bytes()), sig_recovery, compress_public_key(pk)), true);
        }

        #[ink::test]
        fn verify_transaction_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            let mut transaction_data = OmniverseTransactionData {
                nonce: 0,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: USER_PK,
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };
            let payload_item = OmniverseFungible::new(1, USER_PK.to_vec(), 100);
            transaction_data.payload = payload_item.encode();

            // Succeed
            let secp = Secp256k1::new();
            let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
		    let pk: [u8; 64] = public_key.serialize_uncompressed()[1..].try_into().expect("");
            transaction_data.from = pk;
            let hash = transaction_data.get_hash();
            assert_eq!(hash.is_ok(), true);
            let message = Message::from_slice(hash.unwrap().as_slice())
		    .expect("messages must be 32 bytes and are expected to be hashes");
            let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret_key);
	        let sig_recovery = get_sig_slice(&sig);
            transaction_data.signature = sig_recovery;
            assert_eq!(omniverse_protocol.verify_transaction(&transaction_data.clone()), Ok(()));
            let mut rc = RecordedCertificate::default();
            rc.tx_list.push(OmniverseTx::new(transaction_data.clone(), 0));
            omniverse_protocol.transaction_recorder.insert(transaction_data.from, rc);
            let count = omniverse_protocol.get_transaction_count(transaction_data.from);
            assert_eq!(count, 1);

            // Duplicate
            assert_eq!(omniverse_protocol.verify_transaction(&transaction_data.clone()), Err(Error::Duplicated));

            // Nonce error
            transaction_data.nonce = 10;
            let hash = transaction_data.get_hash();
            assert_eq!(hash.is_ok(), true);
            let message = Message::from_slice(hash.unwrap().as_slice())
		    .expect("messages must be 32 bytes and are expected to be hashes");
            let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret_key);
	        let sig_recovery = get_sig_slice(&sig);
            transaction_data.signature = sig_recovery;
            assert_eq!(omniverse_protocol.verify_transaction(&transaction_data.clone()), Err(Error::NonceError));
            
            // Malicious
            transaction_data.chain_id = 10;
            transaction_data.nonce = 0;
            let hash = transaction_data.get_hash();
            assert_eq!(hash.is_ok(), true);
            let message = Message::from_slice(hash.unwrap().as_slice())
		    .expect("messages must be 32 bytes and are expected to be hashes");
            let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret_key);
	        let sig_recovery = get_sig_slice(&sig);
            transaction_data.signature = sig_recovery;
            assert_eq!(omniverse_protocol.verify_transaction(&transaction_data.clone()), Err(Error::Malicious));
        }

        #[ink::test]
        fn send_omniverse_transaction_internal_works() {
            let secp = Secp256k1::new();
            let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
		    let pk: [u8; 64] = public_key.serialize_uncompressed()[1..].try_into().expect("");
            let mut omniverse_protocol = OmniverseProtocol::new(0, pk, "FT".to_string(), "FT".to_string());
            let mut transaction_data = OmniverseTransactionData {
                nonce: 0,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: pk,
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };

            // Succeed
            let payload_item = OmniverseFungible::new(1, USER_PK.to_vec(), 100);
            transaction_data.payload = payload_item.encode();
            let hash = transaction_data.get_hash();
            assert_eq!(hash.is_ok(), true);
            let message = Message::from_slice(hash.unwrap().as_slice())
		    .expect("messages must be 32 bytes and are expected to be hashes");
            let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret_key);
	        let sig_recovery = get_sig_slice(&sig);
            transaction_data.signature = sig_recovery;
            assert_eq!(omniverse_protocol.send_omniverse_transaction_internal(transaction_data.clone()), Ok(()));

            // Transaction cached
            assert_eq!(omniverse_protocol.send_omniverse_transaction_internal(transaction_data.clone()), Err(Error::TransactionCached));

            // User malicious
            let mut rc = omniverse_protocol.transaction_recorder.get(&pk).unwrap_or(&RecordedCertificate::default()).clone();
            rc.evil_tx_list.push(EvilTxData::new(OmniverseTx::new(transaction_data.clone(), 0), 0));
            omniverse_protocol.transaction_recorder.insert(transaction_data.from, rc);
            assert_eq!(omniverse_protocol.send_omniverse_transaction_internal(transaction_data.clone()), Err(Error::UserMalicious));
        }

        #[ink::test]
        fn trigger_execution_internal_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            // Transaction not cached
            assert_eq!(omniverse_protocol.trigger_execution_internal(USER_PK, 0), Err(Error::TransactionNotCached));
            
            // Nonce not match
            let transaction_data = OmniverseTransactionData {
                nonce: 0,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: USER_PK,
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };
            omniverse_protocol.transaction_cache.insert(transaction_data.from, OmniverseTx::new(transaction_data.clone(), 0));
            assert_eq!(omniverse_protocol.trigger_execution_internal(transaction_data.from, 1), Err(Error::NonceNotMatch));

            // Succeed
            ink::env::test::set_block_timestamp::<DefaultEnvironment>(100);
            assert_eq!(omniverse_protocol.trigger_execution_internal(transaction_data.from, 0), Ok(()));
            assert_eq!(omniverse_protocol.get_transaction_count(transaction_data.from), 1);
            assert_eq!(omniverse_protocol.transaction_cache.get(&transaction_data.from).is_none(), true);

            // Cooling down
            ink::env::test::set_block_timestamp::<DefaultEnvironment>(0);
            omniverse_protocol.transaction_cache.insert(transaction_data.from, OmniverseTx::new(transaction_data.clone(), 0));
            assert_eq!(omniverse_protocol.trigger_execution_internal(transaction_data.from, 0), Err(Error::CoolingDown));
        }

        #[ink::test]
        fn only_owner_works() {
            let omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            // Caller not owner
            assert_eq!(omniverse_protocol.only_owner(), Err(Error::NotOwner));
            // Caller is owner
            test::set_caller::<DefaultEnvironment>(compressed_pubkey_to_account(compress_public_key(OWNER_PK)));
            assert_eq!(omniverse_protocol.only_owner(), Ok(()));
        }

        //====================== Check message functions ========================
        // For fungible token
        #[ink::test]
        fn trigger_execution_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            // No delayed tx
            assert_eq!(omniverse_protocol.trigger_execution(), Err(Error::NoDelayedTx));

            // Not cached
            omniverse_protocol.delayed_txs.push((OWNER_PK, 0));
            assert_eq!(omniverse_protocol.trigger_execution(), Err(Error::NotCached));

            // Nonce error
            let mut transaction_data = OmniverseTransactionData {
                nonce: 1,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: OWNER_PK,
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };
            omniverse_protocol.transaction_cache.insert(transaction_data.from, OmniverseTx::new(transaction_data.clone(), 0));
            assert_eq!(omniverse_protocol.trigger_execution(), Err(Error::NonceError));

            // Payload error
            transaction_data.nonce = 0;
            omniverse_protocol.transaction_cache.insert(transaction_data.from, OmniverseTx::new(transaction_data.clone(), 0));
            ink::env::test::set_block_timestamp::<DefaultEnvironment>(100);
            assert_eq!(omniverse_protocol.trigger_execution(), Err(Error::PayloadError));

            // Mint
            let mut tx_count: u128 = 2;
            let payload_item = OmniverseFungible::new(1, OWNER_PK.to_vec(), 100);
            transaction_data.payload = payload_item.encode();
            omniverse_protocol.transaction_cache.insert(transaction_data.from, OmniverseTx::new(transaction_data.clone(), 0));
            test::set_caller::<DefaultEnvironment>(compressed_pubkey_to_account(compress_public_key(OWNER_PK)));
            ink::env::test::set_block_timestamp::<DefaultEnvironment>(100);
            omniverse_protocol.delayed_txs.push((OWNER_PK, 0));
            assert_eq!(omniverse_protocol.trigger_execution(), Ok(()));
            assert_eq!(omniverse_protocol.get_transaction_count(transaction_data.from), tx_count);
            assert_eq!(omniverse_protocol.transaction_cache.get(&transaction_data.from).is_none(), true);
            assert_eq!(omniverse_protocol.omniverse_balances.get(&OWNER_PK).unwrap(), &100);

            // Transfer
            tx_count += 1;
            let payload_item = OmniverseFungible::new(0, USER_PK.to_vec(), 100);
            transaction_data.payload = payload_item.encode();
            transaction_data.nonce = 0;
            omniverse_protocol.transaction_cache.insert(transaction_data.from, OmniverseTx::new(transaction_data.clone(), 0));
            omniverse_protocol.delayed_txs.push((OWNER_PK, 0));
            assert_eq!(omniverse_protocol.trigger_execution(), Ok(()));
            assert_eq!(omniverse_protocol.get_transaction_count(transaction_data.from), tx_count);
            assert_eq!(omniverse_protocol.transaction_cache.get(&transaction_data.from).is_none(), true);
            assert_eq!(omniverse_protocol.omniverse_balances.get(&USER_PK).unwrap(), &100);

            // Burn
            tx_count += 1;
            let payload_item = OmniverseFungible::new(2, USER_PK.to_vec(), 100);
            transaction_data.payload = payload_item.encode();
            transaction_data.nonce = 0;
            omniverse_protocol.transaction_cache.insert(transaction_data.from, OmniverseTx::new(transaction_data.clone(), 0));
            omniverse_protocol.delayed_txs.push((OWNER_PK, 0));
            assert_eq!(omniverse_protocol.trigger_execution(), Ok(()));
            assert_eq!(omniverse_protocol.get_transaction_count(transaction_data.from), tx_count);
            assert_eq!(omniverse_protocol.transaction_cache.get(&transaction_data.from).is_none(), true);
            assert_eq!(omniverse_protocol.omniverse_balances.get(&USER_PK).unwrap(), &0);
        }

        #[ink::test]
        fn send_omniverse_transaction_works() {
            let secp = Secp256k1::new();
            let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
		    let pk: [u8; 64] = public_key.serialize_uncompressed()[1..].try_into().expect("");
            let mut omniverse_protocol = OmniverseProtocol::new(0, pk, "FT".to_string(), "FT".to_string());
            let mut transaction_data = OmniverseTransactionData {
                nonce: 0,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: pk,
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };

            // Not member
            assert_eq!(omniverse_protocol.send_omniverse_transaction(transaction_data.clone()), Err(Error::NotMember));

            // Wrong initiator
            omniverse_protocol.members.insert(1_u32, Member {chain_id: 1, contract_address: vec![1]});
            assert_eq!(omniverse_protocol.send_omniverse_transaction(transaction_data.clone()), Err(Error::WrongInitiator));

            // Succeed
            let mut members = Vec::<Member>::new();
            members.push(Member {chain_id: 1, contract_address: Vec::<u8>::new()});
            test::set_caller::<DefaultEnvironment>(compressed_pubkey_to_account(compress_public_key(pk)));
            assert_eq!(omniverse_protocol.set_members(members), Ok(()));
            let payload_item = OmniverseFungible::new(1, USER_PK.to_vec(), 100);
            transaction_data.payload = payload_item.encode();
            let hash = transaction_data.get_hash();
            assert_eq!(hash.is_ok(), true);
            let message = Message::from_slice(hash.unwrap().as_slice())
		    .expect("messages must be 32 bytes and are expected to be hashes");
            let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret_key);
	        let sig_recovery = get_sig_slice(&sig);
            transaction_data.signature = sig_recovery;
            assert_eq!(omniverse_protocol.send_omniverse_transaction(transaction_data.clone()), Ok(()));
        }

        #[ink::test]
        fn set_members_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            
            let mut members = Vec::<Member>::new();
            members.push(Member {chain_id: 0, contract_address: Vec::<u8>::new()});
            members.push(Member {chain_id: 1, contract_address: Vec::<u8>::new()});
            test::set_caller::<DefaultEnvironment>(compressed_pubkey_to_account(compress_public_key(OWNER_PK)));
            assert_eq!(omniverse_protocol.set_members(members), Ok(()));
        }

        // For fungible token
        #[ink::test]
        fn get_transaction_count_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            // No transaction
            assert_eq!(omniverse_protocol.get_transaction_count(USER_PK), 0);

            // Transactions exist
            let transaction_data = OmniverseTransactionData {
                nonce: 0,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: USER_PK,
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };
            let mut rc = omniverse_protocol.transaction_recorder.get(&transaction_data.from).unwrap_or(&RecordedCertificate::default()).clone();
            rc.tx_list.push(OmniverseTx::new(transaction_data.clone(), 0));
            omniverse_protocol.transaction_recorder.insert(USER_PK, rc.clone());
            assert_eq!(omniverse_protocol.get_transaction_count(USER_PK), 1);
        }

        #[ink::test]
        fn get_transaction_data_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            // No record
            assert_eq!(omniverse_protocol.get_transaction_data(USER_PK, 0).is_none(), true);

            // Data not found
            let mut rc = omniverse_protocol.transaction_recorder.get(&USER_PK).unwrap_or(&RecordedCertificate::default()).clone();
            omniverse_protocol.transaction_recorder.insert(USER_PK, rc.clone());
            assert_eq!(omniverse_protocol.get_transaction_data(USER_PK, 0).is_none(), true);

            // Data found
            let transaction_data = OmniverseTransactionData {
                nonce: 0,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: USER_PK,
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };
            rc.tx_list.push(OmniverseTx::new(transaction_data.clone(), 0));
            omniverse_protocol.transaction_recorder.insert(USER_PK, rc.clone());
            assert_eq!(omniverse_protocol.get_transaction_data(USER_PK, 0).is_some(), true);
        }

        #[ink::test]
        fn get_chain_id_works() {
            let omniverse_protocol = OmniverseProtocol::new(10, OWNER_PK, "FT".to_string(), "FT".to_string());
            assert_eq!(omniverse_protocol.get_chain_id(), 10);
        }

        #[ink::test]
        fn get_cached_transaction_works() {
            let mut omniverse_protocol = OmniverseProtocol::new(0, OWNER_PK, "FT".to_string(), "FT".to_string());
            // No cached data
            assert_eq!(omniverse_protocol.get_cached_transaction(USER_PK).is_none(), true);

            // Cached data exist
            let transaction_data = OmniverseTransactionData {
                nonce: 0,
                chain_id: 1,
                initiate_sc: ink::prelude::vec::Vec::new(),
                from: USER_PK,
                payload: ink::prelude::vec::Vec::new(),
                signature: [0; 65],
            };
            omniverse_protocol.transaction_cache.insert(transaction_data.from, OmniverseTx::new(transaction_data.clone(), 0));
            assert_eq!(omniverse_protocol.get_cached_transaction(USER_PK).is_some(), true);
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
