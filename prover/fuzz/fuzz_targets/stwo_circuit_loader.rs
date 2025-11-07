#![no_main]

use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use libfuzzer_sys::fuzz_target;
use plonky3_backend::{
    ChallengeValue, HashFormat, Proof, ProofMetadata, ProofParts, TranscriptCheckpoint,
    TranscriptSnapshot, TranscriptStage,
};
use prover_stwo_backend::official::proof::StarkProof;

const MAX_BLOB: usize = 2048;
const MAX_VEC: usize = 8;

#[derive(Debug)]
struct ProverSeed {
    stwo_payload: Vec<u8>,
    parts: ProofPartsSeed,
}

impl<'a> Arbitrary<'a> for ProverSeed {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self {
            stwo_payload: arbitrary_bytes(u, MAX_BLOB)?,
            parts: ProofPartsSeed::arbitrary(u)?,
        })
    }
}

#[derive(Debug)]
struct ProofPartsSeed {
    proof: Vec<u8>,
    metadata: MetadataSeed,
    auxiliary: Vec<Vec<u8>>,
}

impl ProofPartsSeed {
    fn into_parts(self) -> ProofParts {
        ProofParts::new(self.proof, self.metadata.into_metadata(), self.auxiliary)
    }
}

impl<'a> Arbitrary<'a> for ProofPartsSeed {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let proof = arbitrary_bytes(u, MAX_BLOB)?;
        let metadata = MetadataSeed::arbitrary(u)?;
        let aux_len = u.int_in_range(0..=MAX_VEC)?;
        let mut auxiliary = Vec::with_capacity(aux_len);
        for _ in 0..aux_len {
            auxiliary.push(arbitrary_bytes(u, MAX_BLOB)?);
        }
        Ok(Self {
            proof,
            metadata,
            auxiliary,
        })
    }
}

#[derive(Debug)]
struct MetadataSeed {
    trace_commitment: [u8; 32],
    quotient_commitment: [u8; 32],
    random_commitment: Option<[u8; 32]>,
    fri_commitments: Vec<[u8; 32]>,
    canonical_inputs: Vec<u8>,
    transcript: TranscriptSeed,
    security_bits: u32,
    derived_security_bits: u32,
    use_gpu: bool,
}

impl MetadataSeed {
    fn into_metadata(self) -> ProofMetadata {
        ProofMetadata::assemble(
            self.trace_commitment,
            self.quotient_commitment,
            self.random_commitment,
            self.fri_commitments,
            self.canonical_inputs,
            self.transcript.into_snapshot(),
            HashFormat::PoseidonMerkleCap,
            self.security_bits,
            self.derived_security_bits,
            self.use_gpu,
        )
    }
}

impl<'a> Arbitrary<'a> for MetadataSeed {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let random_commitment = if u.arbitrary::<bool>()? {
            Some(<[u8; 32]>::arbitrary(u)?)
        } else {
            None
        };
        Ok(Self {
            trace_commitment: <[u8; 32]>::arbitrary(u)?,
            quotient_commitment: <[u8; 32]>::arbitrary(u)?,
            random_commitment,
            fri_commitments: arbitrary_array_vec::<32>(u, MAX_VEC)?,
            canonical_inputs: arbitrary_bytes(u, MAX_BLOB)?,
            transcript: TranscriptSeed::arbitrary(u)?,
            security_bits: u.arbitrary::<u32>()?,
            derived_security_bits: u.arbitrary::<u32>()?,
            use_gpu: u.arbitrary::<bool>()?,
        })
    }
}

#[derive(Debug)]
struct TranscriptSeed {
    degree_bits: u32,
    trace_length_bits: u32,
    alpha: [u32; 4],
    zeta: [u32; 4],
    pcs_alpha: [u32; 4],
    fri_challenges: Vec<[u32; 4]>,
    query_indices: Vec<u32>,
    checkpoints: Vec<CheckpointSeed>,
}

impl TranscriptSeed {
    fn into_snapshot(self) -> TranscriptSnapshot {
        let fri_challenges = self
            .fri_challenges
            .into_iter()
            .map(ChallengeValue::from_limbs)
            .collect();
        let checkpoints = self
            .checkpoints
            .into_iter()
            .map(CheckpointSeed::into_checkpoint)
            .collect();
        TranscriptSnapshot::new(
            self.degree_bits,
            self.trace_length_bits,
            ChallengeValue::from_limbs(self.alpha),
            ChallengeValue::from_limbs(self.zeta),
            ChallengeValue::from_limbs(self.pcs_alpha),
            fri_challenges,
            self.query_indices,
            checkpoints,
        )
    }
}

impl<'a> Arbitrary<'a> for TranscriptSeed {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self {
            degree_bits: u.arbitrary::<u32>()?,
            trace_length_bits: u.arbitrary::<u32>()?,
            alpha: arbitrary_limbs(u)?,
            zeta: arbitrary_limbs(u)?,
            pcs_alpha: arbitrary_limbs(u)?,
            fri_challenges: arbitrary_vec(u, MAX_VEC, arbitrary_limbs)?,
            query_indices: arbitrary_vec(u, MAX_VEC, |u| u.arbitrary::<u32>()?),
            checkpoints: arbitrary_vec(u, MAX_VEC, CheckpointSeed::arbitrary)?,
        })
    }
}

#[derive(Debug)]
struct CheckpointSeed {
    stage: u8,
    state: Vec<u8>,
}

impl CheckpointSeed {
    fn into_checkpoint(self) -> TranscriptCheckpoint {
        TranscriptCheckpoint::new(stage_from_byte(self.stage), self.state)
    }
}

impl<'a> Arbitrary<'a> for CheckpointSeed {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self {
            stage: u.arbitrary::<u8>()?,
            state: arbitrary_bytes(u, MAX_BLOB)?,
        })
    }
}

fn arbitrary_bytes(u: &mut Unstructured<'_>, max_len: usize) -> ArbitraryResult<Vec<u8>> {
    let len = u.int_in_range(0..=max_len)?;
    let mut bytes = vec![0u8; len];
    u.fill_buffer(&mut bytes)?;
    Ok(bytes)
}

fn arbitrary_limbs(u: &mut Unstructured<'_>) -> ArbitraryResult<[u32; 4]> {
    let mut limbs = [0u32; 4];
    for limb in &mut limbs {
        *limb = u.arbitrary::<u32>()?;
    }
    Ok(limbs)
}

fn arbitrary_array_vec<const N: usize>(
    u: &mut Unstructured<'_>,
    max_len: usize,
) -> ArbitraryResult<Vec<[u8; N]>> {
    let len = u.int_in_range(0..=max_len)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(<[u8; N]>::arbitrary(u)?);
    }
    Ok(values)
}

fn arbitrary_vec<T, F>(
    u: &mut Unstructured<'_>,
    max_len: usize,
    mut generator: F,
) -> ArbitraryResult<Vec<T>>
where
    F: FnMut(&mut Unstructured<'_>) -> ArbitraryResult<T>,
{
    let len = u.int_in_range(0..=max_len)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(generator(u)?);
    }
    Ok(values)
}

fn stage_from_byte(byte: u8) -> TranscriptStage {
    match byte % 4 {
        0 => TranscriptStage::AfterPublicValues,
        1 => TranscriptStage::AfterCommitments,
        2 => TranscriptStage::AfterZetaSampling,
        _ => TranscriptStage::AfterQuerySampling,
    }
}

fuzz_target!(|seed: ProverSeed| {
    if let Ok(parsed) = serde_json::from_slice::<StarkProof>(&seed.stwo_payload) {
        let _ = serde_json::to_vec(&parsed);
    }

    let _ = Proof::from_parts("consensus", seed.parts.into_parts());
});
