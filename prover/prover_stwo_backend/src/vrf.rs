/// Length in bytes of the VRF pre-output embedded in identity proofs.
pub const VRF_PREOUTPUT_LENGTH: usize = 32;
/// Length in bytes of Schnorrkel VRF proofs used by the STWO identity circuit.
pub const VRF_PROOF_LENGTH: usize = schnorrkel::vrf::VRF_PROOF_LENGTH;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_length_matches_schnorrkel() {
        assert_eq!(VRF_PROOF_LENGTH, schnorrkel::vrf::VRF_PROOF_LENGTH);
    }
}
