#![forbid(unsafe_code)]

//! Non-authorizing dependency-closure and strict-policy probe.
//!
//! This crate is not a Keep workspace member, is excluded from the npm package, and cannot mint
//! authority. Its verification wrapper exists solely to make the proposed RFC-8032 policy and
//! hostile corpus executable before dependency admission.

use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictVerifyError {
    InvalidPublicKey,
    NonCanonicalPublicKey,
    WeakPublicKey,
    InvalidSignature,
}

/// Verify pure Ed25519 under Keep's frozen public-key policy.
///
/// The wrapper deliberately exposes neither permissive verification, prehash/context variants,
/// batching, signing, nor key generation. Public keys must decode, recompress to the exact input
/// bytes, and be non-weak before `verify_strict` is invoked.
pub fn verify_rfc8032_strict(
    public_key_bytes: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), StrictVerifyError> {
    let key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| StrictVerifyError::InvalidPublicKey)?;
    if key.to_edwards().compress().to_bytes() != *public_key_bytes {
        return Err(StrictVerifyError::NonCanonicalPublicKey);
    }
    if key.is_weak() {
        return Err(StrictVerifyError::WeakPublicKey);
    }
    let signature = Signature::from_bytes(signature_bytes);
    key.verify_strict(message, &signature)
        .map_err(|_| StrictVerifyError::InvalidSignature)
}

pub fn verifier_type_size() -> usize {
    core::mem::size_of::<ed25519_dalek::VerifyingKey>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        let mut out = [0u8; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        out
    }

    const PUBLIC_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIGNATURE: &str = concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );

    fn decode_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len() / 2)
            .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
            .collect()
    }

    fn assert_vector(public_key: &str, message: &str, signature: &str) {
        assert_eq!(
            verify_rfc8032_strict(
                &decode::<32>(public_key),
                &decode_bytes(message),
                &decode::<64>(signature),
            ),
            Ok(())
        );
    }

    #[test]
    fn rfc8032_vector_one_and_exact_mutants() {
        let key = decode::<32>(PUBLIC_KEY);
        let signature = decode::<64>(SIGNATURE);
        assert_eq!(verify_rfc8032_strict(&key, b"", &signature), Ok(()));
        assert_eq!(
            verify_rfc8032_strict(&key, b"altered", &signature),
            Err(StrictVerifyError::InvalidSignature)
        );
        let mut altered_key = key;
        altered_key[0] ^= 1;
        assert!(verify_rfc8032_strict(&altered_key, b"", &signature).is_err());
        let mut altered_signature = signature;
        altered_signature[0] ^= 1;
        assert_eq!(
            verify_rfc8032_strict(&key, b"", &altered_signature),
            Err(StrictVerifyError::InvalidSignature)
        );
    }

    #[test]
    fn rfc8032_vectors_two_and_three() {
        assert_vector(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
        );
        assert_vector(
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            concat!(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            ),
        );
    }

    #[test]
    fn noncanonical_and_weak_public_keys_refuse_before_verification() {
        let signature = decode::<64>(SIGNATURE);
        let mut noncanonical_identity = [0xff; 32];
        noncanonical_identity[0] = 0xee;
        noncanonical_identity[31] = 0x7f;
        assert_eq!(
            verify_rfc8032_strict(&noncanonical_identity, b"", &signature),
            Err(StrictVerifyError::NonCanonicalPublicKey)
        );
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            verify_rfc8032_strict(&identity, b"", &signature),
            Err(StrictVerifyError::WeakPublicKey)
        );
    }

    #[test]
    fn every_small_order_public_key_refuses_before_verification() {
        let signature = decode::<64>(SIGNATURE);
        for point in curve25519_dalek::constants::EIGHT_TORSION {
            let encoded = point.compress().to_bytes();
            assert_eq!(
                verify_rfc8032_strict(&encoded, b"", &signature),
                Err(StrictVerifyError::WeakPublicKey),
                "small-order public key {encoded:02x?} was accepted"
            );
        }
    }

    #[test]
    fn noncanonical_r_and_scalar_at_group_order_refuse() {
        let key = decode::<32>(PUBLIC_KEY);
        let mut signature = decode::<64>(SIGNATURE);
        signature[..32].fill(0xff);
        signature[0] = 0xee;
        signature[31] = 0x7f;
        assert_eq!(
            verify_rfc8032_strict(&key, b"", &signature),
            Err(StrictVerifyError::InvalidSignature)
        );

        let mut signature = decode::<64>(SIGNATURE);
        signature[32..].copy_from_slice(&decode::<32>(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ));
        assert_eq!(
            verify_rfc8032_strict(&key, b"", &signature),
            Err(StrictVerifyError::InvalidSignature)
        );

        signature[32..].copy_from_slice(&decode::<32>(
            "eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ));
        assert_eq!(
            verify_rfc8032_strict(&key, b"", &signature),
            Err(StrictVerifyError::InvalidSignature)
        );

        for point in curve25519_dalek::constants::EIGHT_TORSION {
            let mut signature = decode::<64>(SIGNATURE);
            signature[..32].copy_from_slice(&point.compress().to_bytes());
            assert_eq!(
                verify_rfc8032_strict(&key, b"", &signature),
                Err(StrictVerifyError::InvalidSignature)
            );
        }
    }

    #[test]
    fn scalar_canonicality_boundaries_are_exact() {
        use curve25519_dalek::scalar::Scalar;

        let order_minus_one =
            decode::<32>("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        let order =
            decode::<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        let order_plus_one =
            decode::<32>("eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        assert!(bool::from(
            Scalar::from_canonical_bytes(order_minus_one).is_some()
        ));
        assert!(bool::from(Scalar::from_canonical_bytes(order).is_none()));
        assert!(bool::from(
            Scalar::from_canonical_bytes(order_plus_one).is_none()
        ));
    }
}
