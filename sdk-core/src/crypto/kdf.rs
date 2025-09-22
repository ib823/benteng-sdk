//! Key Derivation Functions

use crate::error::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain separation constants
pub const BENTENG_HYBRID_V1: &[u8] = b"benteng/hybrid/v1";
pub const BENTENG_AEAD_V1: &[u8] = b"benteng/aead/v1";

/// HKDF-SHA256 Extract and Expand
pub fn hkdf_sha256_derive(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let hk = if let Some(salt) = salt {
        Hkdf::<Sha256>::new(Some(salt), ikm)
    } else {
        Hkdf::<Sha256>::new(None, ikm)
    };

    let mut output = Zeroizing::new(vec![0u8; output_len]);
    hk.expand(info, output.as_mut_slice())
        .map_err(|_| crate::error::BentengError::InternalError)?;

    Ok(output)
}

/// Derive DEK for hybrid mode (X25519 + ML-KEM)
pub fn derive_hybrid_dek(
    ss_ecc: &[u8],
    ss_pqc: &[u8],
    tenant_id: &[u8],
    policy_id: &[u8],
    path: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    // Combine both shared secrets
    let mut ikm = Vec::with_capacity(BENTENG_HYBRID_V1.len() + ss_ecc.len() + ss_pqc.len());
    ikm.extend_from_slice(BENTENG_HYBRID_V1);
    ikm.extend_from_slice(ss_ecc);
    ikm.extend_from_slice(ss_pqc);

    // Create salt from identifiers
    let mut salt = Vec::new();
    salt.extend_from_slice(tenant_id);
    salt.extend_from_slice(policy_id);

    // Create info with domain separation
    let mut info = Vec::new();
    info.extend_from_slice(BENTENG_AEAD_V1);
    info.extend_from_slice(tenant_id);
    info.extend_from_slice(policy_id);
    info.extend_from_slice(path.as_bytes());

    let derived = hkdf_sha256_derive(&ikm, Some(&salt), &info, 32)?;

    let mut dek = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(&derived);
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let output = hkdf_sha256_derive(ikm, Some(salt), info, 32).unwrap();
        assert_eq!(output.len(), 32);
    }
}
