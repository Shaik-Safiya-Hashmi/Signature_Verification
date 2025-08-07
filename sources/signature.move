module MyModule::SignatureVerification {
    use aptos_framework::signer;
    use std::vector;
    use aptos_std::ed25519;
    use std::string::{Self, String};

    /// Error codes
    const E_INVALID_SIGNATURE: u64 = 1;
    const E_MESSAGE_NOT_FOUND: u64 = 2;

    /// Struct to store verified messages with their signatures
    struct VerifiedMessage has store, key {
        message: String,
        public_key: vector<u8>,
        signature: vector<u8>,
        timestamp: u64,
    }

    /// Function to verify and store a message signature
    public fun verify_and_store_message(
        account: &signer,
        message: String,
        public_key: vector<u8>,
        signature: vector<u8>
    ) {
        // Convert message to bytes for verification
        let message_bytes = *string::bytes(&message);
        
        // Create public key struct for verification
        let pk = ed25519::new_unvalidated_public_key_from_bytes(public_key);
        let sig = ed25519::new_signature_from_bytes(signature);
        
        // Verify the signature
        assert!(
            ed25519::signature_verify_strict(&sig, &pk, message_bytes),
            E_INVALID_SIGNATURE
        );

        // Store the verified message
        let verified_msg = VerifiedMessage {
            message,
            public_key,
            signature,
            timestamp: aptos_framework::timestamp::now_seconds(),
        };
        
        move_to(account, verified_msg);
    }

    /// Function to retrieve and validate a stored verified message
    public fun get_verified_message(account_addr: address): (String, vector<u8>, bool) acquires VerifiedMessage {
        // Check if the account has a verified message
        assert!(exists<VerifiedMessage>(account_addr), E_MESSAGE_NOT_FOUND);
        
        let verified_msg = borrow_global<VerifiedMessage>(account_addr);
        
        // Re-verify the signature to ensure integrity
        let message_bytes = *string::bytes(&verified_msg.message);
        let pk = ed25519::new_unvalidated_public_key_from_bytes(verified_msg.public_key);
        let sig = ed25519::new_signature_from_bytes(verified_msg.signature);
        
        let is_valid = ed25519::signature_verify_strict(&sig, &pk, message_bytes);
        
        (verified_msg.message, verified_msg.public_key, is_valid)
    }
}