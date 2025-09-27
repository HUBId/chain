//! Consensus node logic responsible for VRF leader election and BFT voting.
//!
//! This module encapsulates proposer selection, vote validation, and
//! misbehavior evidence tracking. Core invariants:
//!
//! * [`EvidencePool`] de-duplicates votes by `(height, round, kind, voter)` to
//!   detect equivocation.
//! * All [`BftVote`] values must carry signatures that validate against the
//!   submitter's public key prior to acceptance.
//! * VRF submissions are filtered through [`VrfSubmissionPool`] so that
//!   proposer randomness is both unbiased and replay-safe across epochs.
use std::collections::{HashMap, HashSet};

use malachite::Natural;
use malachite::base::num::arithmetic::traits::DivRem;
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::crypto::{
    VrfPublicKey, VrfSecretKey, address_from_public_key, public_key_from_hex, signature_from_hex,
    verify_signature, vrf_public_key_to_hex,
};
use crate::errors::{ChainError, ChainResult};
use crate::reputation::Tier;
use crate::types::{Account, Address, Stake};
#[cfg(test)]
use crate::vrf::VrfSubmission;
use crate::vrf::{self, PoseidonVrfInput, VerifiedSubmission, VrfProof, VrfSubmissionPool};
use tracing::warn;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposerSelection {
    pub proposer: Address,
    pub randomness: Natural,
    pub proof: VrfProof,
    pub total_voting_power: Natural,
    pub quorum_threshold: Natural,
    pub timetoke_hours: u64,
    pub tier: Tier,
    pub vrf_public_key: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BftVoteKind {
    PreVote,
    PreCommit,
}

impl BftVoteKind {
    fn as_byte(self) -> u8 {
        match self {
            BftVoteKind::PreVote => 0,
            BftVoteKind::PreCommit => 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceKind {
    DoubleSignPrevote,
    DoubleSignPrecommit,
    InvalidProof,
    InvalidProposal,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub address: Address,
    pub height: u64,
    pub round: u64,
    pub kind: EvidenceKind,
    pub vote_kind: Option<BftVoteKind>,
    pub block_hashes: Vec<String>,
}

impl EvidenceRecord {
    fn double_sign(vote: &SignedBftVote, previous: &str) -> Self {
        let kind = match vote.vote.kind {
            BftVoteKind::PreVote => EvidenceKind::DoubleSignPrevote,
            BftVoteKind::PreCommit => EvidenceKind::DoubleSignPrecommit,
        };
        Self {
            address: vote.vote.voter.clone(),
            height: vote.vote.height,
            round: vote.vote.round,
            kind,
            vote_kind: Some(vote.vote.kind),
            block_hashes: vec![previous.to_string(), vote.vote.block_hash.clone()],
        }
    }

    fn invalid_proof(address: &Address, height: u64, round: u64) -> Self {
        Self {
            address: address.clone(),
            height,
            round,
            kind: EvidenceKind::InvalidProof,
            vote_kind: None,
            block_hashes: Vec::new(),
        }
    }

    fn invalid_proposal(
        address: &Address,
        height: u64,
        round: u64,
        block_hash: Option<String>,
    ) -> Self {
        Self {
            address: address.clone(),
            height,
            round,
            kind: EvidenceKind::InvalidProposal,
            vote_kind: None,
            block_hashes: block_hash.into_iter().collect(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvidencePool {
    votes: HashMap<(u64, u64, BftVoteKind, Address), String>,
}

impl EvidencePool {
    pub fn record_vote(&mut self, vote: &SignedBftVote) -> Option<EvidenceRecord> {
        let key = (
            vote.vote.height,
            vote.vote.round,
            vote.vote.kind,
            vote.vote.voter.clone(),
        );
        if let Some(existing) = self.votes.get(&key) {
            if existing != &vote.vote.block_hash {
                return Some(EvidenceRecord::double_sign(vote, existing));
            }
            return None;
        }
        self.votes.insert(key, vote.vote.block_hash.clone());
        None
    }

    pub fn record_invalid_proof(
        &mut self,
        address: &Address,
        height: u64,
        round: u64,
    ) -> EvidenceRecord {
        EvidenceRecord::invalid_proof(address, height, round)
    }

    pub fn record_invalid_proposal(
        &mut self,
        address: &Address,
        height: u64,
        round: u64,
        block_hash: Option<String>,
    ) -> EvidenceRecord {
        EvidenceRecord::invalid_proposal(address, height, round, block_hash)
    }

    pub fn prune_below(&mut self, threshold_height: u64) {
        self.votes
            .retain(|(height, _, _, _), _| *height >= threshold_height);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BftVote {
    pub round: u64,
    pub height: u64,
    pub block_hash: String,
    pub voter: Address,
    pub kind: BftVoteKind,
}

impl BftVote {
    pub fn message_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"rpp-bft-vote");
        data.extend_from_slice(&self.round.to_le_bytes());
        data.extend_from_slice(&self.height.to_le_bytes());
        data.extend_from_slice(self.block_hash.as_bytes());
        data.extend_from_slice(self.voter.as_bytes());
        data.push(self.kind.as_byte());
        data
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedBftVote {
    pub vote: BftVote,
    pub public_key: String,
    pub signature: String,
}

impl SignedBftVote {
    pub fn verify(&self) -> ChainResult<()> {
        let public_key = public_key_from_hex(&self.public_key)?;
        let derived = address_from_public_key(&public_key);
        if derived != self.vote.voter {
            return Err(ChainError::Crypto(
                "vote public key does not match voter address".into(),
            ));
        }
        let signature = signature_from_hex(&self.signature)?;
        verify_signature(&public_key, &self.vote.message_bytes(), &signature)?;
        Ok(())
    }

    pub fn hash(&self) -> String {
        hex::encode::<[u8; 32]>(Blake2sHasher::hash(&self.vote.message_bytes()).into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteRecord {
    pub vote: SignedBftVote,
    pub weight: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusCertificate {
    pub round: u64,
    pub total_power: String,
    pub quorum_threshold: String,
    pub pre_vote_power: String,
    pub pre_commit_power: String,
    pub commit_power: String,
    pub observers: u64,
    pub pre_votes: Vec<VoteRecord>,
    pub pre_commits: Vec<VoteRecord>,
}

impl ConsensusCertificate {
    pub fn genesis() -> Self {
        Self {
            round: 0,
            total_power: "0".to_string(),
            quorum_threshold: "0".to_string(),
            pre_vote_power: "0".to_string(),
            pre_commit_power: "0".to_string(),
            commit_power: "0".to_string(),
            observers: 0,
            pre_votes: Vec::new(),
            pre_commits: Vec::new(),
        }
    }
}

const MAX_TIMETOKE_HOURS: u64 = 24 * 30;

#[derive(Clone, Debug)]
pub struct ValidatorCandidate {
    pub address: Address,
    pub stake: Stake,
    pub reputation_score: f64,
    pub tier: Tier,
    pub timetoke_hours: u64,
}

#[derive(Clone, Debug)]
pub struct ValidatorProfile {
    pub address: Address,
    pub stake: Stake,
    pub reputation_score: f64,
    pub tier: Tier,
    pub timetoke_hours: u64,
    pub vrf: VrfProof,
    pub randomness: Natural,
}

impl ValidatorProfile {
    pub fn voting_power(&self) -> Natural {
        let base_multiplier = (self.reputation_score * 1000.0).round() as i64 + 1000;
        let base_multiplier = base_multiplier.max(1) as u128;
        let timetoke_bonus = (self.timetoke_hours.min(MAX_TIMETOKE_HOURS) + 1) as u128;
        let multiplier = Natural::from(base_multiplier) * Natural::from(timetoke_bonus);
        self.stake.as_natural().clone() * multiplier
    }
}

#[derive(Clone, Debug)]
pub struct ObserverProfile {
    pub address: Address,
    pub tier: Tier,
}

pub fn classify_participants(
    accounts: &[Account],
) -> (Vec<ValidatorCandidate>, Vec<ObserverProfile>) {
    let mut validators = Vec::new();
    let mut observers = Vec::new();
    for account in accounts {
        let candidate = ValidatorCandidate {
            address: account.address.clone(),
            stake: account.stake.clone(),
            reputation_score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            timetoke_hours: account.reputation.timetokes.hours_online,
        };
        match account.reputation.tier {
            Tier::Tl3 | Tier::Tl4 | Tier::Tl5 => validators.push(candidate),
            Tier::Tl1 | Tier::Tl2 => observers.push(ObserverProfile {
                address: account.address.clone(),
                tier: account.reputation.tier.clone(),
            }),
            Tier::Tl0 => {
                // TL0 identities have not validated their ZSI and remain outside of consensus.
            }
        }
    }
    (validators, observers)
}

fn quorum_threshold(total: &Natural) -> Natural {
    if *total == Natural::from(0u32) {
        return Natural::from(0u32);
    }
    let numerator = total.clone() * Natural::from(2u32);
    let denominator = Natural::from(3u32);
    let (mut threshold, remainder) = numerator.div_rem(&denominator);
    if remainder > Natural::from(0u32) {
        threshold += Natural::from(1u32);
    }
    threshold += Natural::from(1u32);
    threshold
}

pub fn evaluate_vrf(
    seed: &[u8; 32],
    round: u64,
    address: &Address,
    timetoke_hours: u64,
    secret: Option<&VrfSecretKey>,
) -> ChainResult<VrfProof> {
    let tier_seed = vrf::derive_tier_seed(address, timetoke_hours);
    let input = PoseidonVrfInput::new(*seed, round, tier_seed);
    let secret_key = secret
        .ok_or_else(|| ChainError::Crypto("missing VRF secret key for evaluation".to_string()))?;
    let output = vrf::generate_vrf(&input, secret_key)?;
    Ok(VrfProof::from_output(&output))
}

pub fn verify_vrf(
    seed: &[u8; 32],
    round: u64,
    address: &Address,
    timetoke_hours: u64,
    proof: &VrfProof,
    public: Option<&VrfPublicKey>,
) -> bool {
    let Some(public_key) = public else {
        warn!(%address, "missing VRF public key for verification");
        return false;
    };
    let Ok(output) = proof.to_vrf_output() else {
        return false;
    };
    let tier_seed = vrf::derive_tier_seed(address, timetoke_hours);
    let input = PoseidonVrfInput::new(*seed, round, tier_seed);
    vrf::verify_vrf(&input, public_key, &output).is_ok()
}

#[derive(Clone, Debug)]
pub struct ConsensusRound {
    height: u64,
    round: u64,
    seed: [u8; 32],
    validators: Vec<ValidatorProfile>,
    observers: Vec<ObserverProfile>,
    voting_power: HashMap<Address, Natural>,
    total_power: Natural,
    quorum: Natural,
    validator_submissions: HashMap<Address, VerifiedSubmission>,
    vrf_audit: Vec<vrf::VrfSelectionRecord>,
    vrf_metrics: vrf::VrfSelectionMetrics,
    proposal: Option<ProposerSelection>,
    pre_votes: Vec<VoteRecord>,
    pre_commits: Vec<VoteRecord>,
    pre_vote_weight: Natural,
    pre_commit_weight: Natural,
    commit_weight: Natural,
    prevote_voters: HashSet<Address>,
    precommit_voters: HashSet<Address>,
    block_hash: Option<String>,
}

impl ConsensusRound {
    pub fn new(
        height: u64,
        round: u64,
        seed: [u8; 32],
        target_validator_count: usize,
        candidates: Vec<ValidatorCandidate>,
        observers: Vec<ObserverProfile>,
        submissions: &VrfSubmissionPool,
    ) -> Self {
        let mut voting_power = HashMap::new();
        let mut total_power = Natural::from(0u32);
        let mut validators = Vec::new();
        let mut validator_submissions = HashMap::new();
        let mut candidate_map = HashMap::new();

        for candidate in candidates.into_iter() {
            candidate_map.insert(candidate.address.clone(), candidate);
        }

        let selection = vrf::select_validators(submissions, target_validator_count);
        let mut vrf_metrics = selection.metrics.clone();
        vrf_metrics.set_round(round);
        for submission in &selection.validators {
            if !submission.verified {
                warn!(address = %submission.address, "ignoring unverified VRF submission");
                continue;
            }
            if let Some(candidate) = candidate_map.get(&submission.address) {
                let profile = ValidatorProfile {
                    address: candidate.address.clone(),
                    stake: candidate.stake.clone(),
                    reputation_score: candidate.reputation_score,
                    tier: candidate.tier.clone(),
                    timetoke_hours: candidate.timetoke_hours,
                    vrf: submission.proof.clone(),
                    randomness: submission.randomness.clone(),
                };
                let power = profile.voting_power();
                total_power += power.clone();
                voting_power.insert(profile.address.clone(), power);
                validator_submissions.insert(submission.address.clone(), submission.clone());
                validators.push(profile);
            }
        }

        if validators.is_empty() {
            if let Some(fallback) = selection.fallback.clone() {
                if !fallback.submission.verified {
                    warn!(address = %fallback.submission.address, "ignoring unverified fallback submission");
                } else if let Some(candidate) = candidate_map.get(&fallback.submission.address) {
                    let profile = ValidatorProfile {
                        address: candidate.address.clone(),
                        stake: candidate.stake.clone(),
                        reputation_score: candidate.reputation_score,
                        tier: candidate.tier.clone(),
                        timetoke_hours: candidate.timetoke_hours,
                        vrf: fallback.submission.proof.clone(),
                        randomness: fallback.submission.randomness.clone(),
                    };
                    let power = profile.voting_power();
                    total_power += power.clone();
                    voting_power.insert(profile.address.clone(), power);
                    validator_submissions
                        .insert(fallback.submission.address.clone(), fallback.submission);
                    validators.push(profile);
                }
            }
        }
        validators.sort_by(|a, b| a.address.cmp(&b.address));
        let quorum = quorum_threshold(&total_power);
        Self {
            height,
            round,
            seed,
            validators,
            observers,
            voting_power,
            total_power,
            quorum,
            validator_submissions,
            vrf_audit: selection.audit.clone(),
            vrf_metrics,
            proposal: None,
            pre_votes: Vec::new(),
            pre_commits: Vec::new(),
            pre_vote_weight: Natural::from(0u32),
            pre_commit_weight: Natural::from(0u32),
            commit_weight: Natural::from(0u32),
            prevote_voters: HashSet::new(),
            precommit_voters: HashSet::new(),
            block_hash: None,
        }
    }

    pub fn round(&self) -> u64 {
        self.round
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn observers(&self) -> &[ObserverProfile] {
        &self.observers
    }

    pub fn validators(&self) -> &[ValidatorProfile] {
        &self.validators
    }

    pub fn vrf_audit(&self) -> &[vrf::VrfSelectionRecord] {
        &self.vrf_audit
    }

    pub fn vrf_metrics(&self) -> &vrf::VrfSelectionMetrics {
        &self.vrf_metrics
    }

    pub fn commit_participants(&self) -> Vec<Address> {
        let mut participants: Vec<Address> = self.precommit_voters.iter().cloned().collect();
        participants.sort();
        participants
    }

    pub fn total_power(&self) -> &Natural {
        &self.total_power
    }

    pub fn quorum_threshold(&self) -> &Natural {
        &self.quorum
    }

    pub fn set_block_hash(&mut self, block_hash: String) {
        self.block_hash = Some(block_hash);
    }

    pub fn select_proposer(&mut self) -> Option<ProposerSelection> {
        let submissions: Vec<VerifiedSubmission> = self
            .validators
            .iter()
            .filter_map(|profile| self.validator_submissions.get(&profile.address).cloned())
            .collect();
        let leader_submission = vrf::select_leader(&submissions)?;
        let public_key = match leader_submission.public_key.as_ref() {
            Some(key) => key,
            None => {
                warn!(
                    address = %leader_submission.address,
                    "selected leader is missing VRF public key"
                );
                return None;
            }
        };
        let public_key_hex = vrf_public_key_to_hex(public_key);
        let leader = self
            .validators
            .iter()
            .find(|profile| profile.address == leader_submission.address)?;
        let selection = ProposerSelection {
            proposer: leader.address.clone(),
            randomness: leader_submission.proof.randomness.clone(),
            proof: leader_submission.proof.clone(),
            total_voting_power: self.total_power.clone(),
            quorum_threshold: self.quorum.clone(),
            timetoke_hours: leader.timetoke_hours,
            tier: leader.tier.clone(),
            vrf_public_key: public_key_hex,
        };
        self.proposal = Some(selection.clone());
        Some(selection)
    }

    fn expected_block_hash(&self) -> ChainResult<&String> {
        self.block_hash
            .as_ref()
            .ok_or_else(|| ChainError::Crypto("consensus round missing block hash context".into()))
    }

    fn voting_power_for(&self, address: &Address) -> ChainResult<Natural> {
        self.voting_power
            .get(address)
            .cloned()
            .ok_or_else(|| ChainError::Crypto("vote submitted by non-validator".into()))
    }

    fn ensure_vote_context(&self, vote: &SignedBftVote) -> ChainResult<()> {
        if vote.vote.round != self.round {
            return Err(ChainError::Crypto(
                "vote references incorrect consensus round".into(),
            ));
        }
        if vote.vote.height != self.height {
            return Err(ChainError::Crypto(
                "vote references incorrect block height".into(),
            ));
        }
        let expected = self.expected_block_hash()?;
        if &vote.vote.block_hash != expected {
            return Err(ChainError::Crypto(
                "vote references unexpected block hash".into(),
            ));
        }
        Ok(())
    }

    pub fn register_prevote(&mut self, vote: &SignedBftVote) -> ChainResult<()> {
        vote.verify()?;
        self.ensure_vote_context(vote)?;
        if vote.vote.kind != BftVoteKind::PreVote {
            return Err(ChainError::Crypto(
                "attempted to register non-prevote in prevote stage".into(),
            ));
        }
        if self.prevote_voters.contains(&vote.vote.voter) {
            return Ok(());
        }
        let weight = self.voting_power_for(&vote.vote.voter)?;
        self.prevote_voters.insert(vote.vote.voter.clone());
        self.pre_vote_weight += weight.clone();
        self.pre_votes.push(VoteRecord {
            vote: vote.clone(),
            weight: weight.to_string(),
        });
        Ok(())
    }

    pub fn register_precommit(&mut self, vote: &SignedBftVote) -> ChainResult<()> {
        vote.verify()?;
        self.ensure_vote_context(vote)?;
        if vote.vote.kind != BftVoteKind::PreCommit {
            return Err(ChainError::Crypto(
                "attempted to register non-precommit in precommit stage".into(),
            ));
        }
        if self.precommit_voters.contains(&vote.vote.voter) {
            return Ok(());
        }
        if !self.prevote_voters.contains(&vote.vote.voter) {
            return Err(ChainError::Crypto(
                "validator submitted precommit without prevote".into(),
            ));
        }
        let weight = self.voting_power_for(&vote.vote.voter)?;
        self.precommit_voters.insert(vote.vote.voter.clone());
        self.pre_commit_weight += weight.clone();
        self.pre_commits.push(VoteRecord {
            vote: vote.clone(),
            weight: weight.to_string(),
        });
        if self.pre_commit_weight >= self.quorum {
            self.commit_weight = self.pre_commit_weight.clone();
        }
        Ok(())
    }

    pub fn commit_reached(&self) -> bool {
        self.commit_weight >= self.quorum
    }

    pub fn certificate(&self) -> ConsensusCertificate {
        ConsensusCertificate {
            round: self.round,
            total_power: self.total_power.to_string(),
            quorum_threshold: self.quorum.to_string(),
            pre_vote_power: self.pre_vote_weight.to_string(),
            pre_commit_power: self.pre_commit_weight.to_string(),
            commit_power: self.commit_weight.to_string(),
            observers: self.observers.len() as u64,
            pre_votes: self.pre_votes.clone(),
            pre_commits: self.pre_commits.clone(),
        }
    }
}

pub fn aggregate_total_stake(entries: &[(Address, Stake)]) -> Natural {
    entries.iter().fold(Natural::from(0u32), |acc, (_, stake)| {
        acc + stake.as_natural().clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{address_from_public_key, generate_vrf_keypair};
    use crate::reputation::Tier;
    use crate::types::{Account, Stake};
    use ed25519_dalek::{Keypair, Signer};
    use rand::rngs::OsRng;

    fn validator_round_with_params(
        target_validator_count: usize,
        height: u64,
        round_number: u64,
    ) -> (ConsensusRound, Keypair, Address, String) {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let address = address_from_public_key(&keypair.public);
        let mut account = Account::new(address.clone(), 0, Stake::from_u128(1_000));
        account.reputation.tier = Tier::Tl3;
        account.reputation.score = 1.0;
        account.reputation.timetokes.hours_online = super::MAX_TIMETOKE_HOURS;
        let (validators, observers) = classify_participants(&[account.clone()]);
        let mut pool = VrfSubmissionPool::new();
        let tier_seed = vrf::derive_tier_seed(&address, account.reputation.timetokes.hours_online);
        let input = PoseidonVrfInput::new([0u8; 32], 1, tier_seed);
        let vrf_keypair = generate_vrf_keypair().expect("vrf keypair");
        let output = vrf::generate_vrf(&input, &vrf_keypair.secret).expect("generate vrf");
        let submission = VrfSubmission {
            address: address.clone(),
            public_key: Some(vrf_keypair.public.clone()),
            input,
            proof: VrfProof::from_output(&output),
            tier: account.reputation.tier.clone(),
            timetoke_hours: account.reputation.timetokes.hours_online,
        };
        vrf::submit_vrf(&mut pool, submission);
        let mut round = ConsensusRound::new(
            height,
            round_number,
            [0u8; 32],
            target_validator_count,
            validators,
            observers,
            &pool,
        );
        let block_hash = hex::encode([5u8; 32]);
        round.set_block_hash(block_hash.clone());
        (round, keypair, address, block_hash)
    }

    fn validator_round_with_target(
        target_validator_count: usize,
    ) -> (ConsensusRound, Keypair, Address, String) {
        validator_round_with_params(target_validator_count, 1, 0)
    }

    fn validator_round() -> (ConsensusRound, Keypair, Address, String) {
        validator_round_with_target(100)
    }

    #[test]
    fn consensus_round_accepts_signed_votes() {
        let (mut round, keypair, address, block_hash) = validator_round();
        let prevote = BftVote {
            round: round.round(),
            height: round.height(),
            block_hash: block_hash.clone(),
            voter: address.clone(),
            kind: BftVoteKind::PreVote,
        };
        let prevote_sig = keypair.sign(&prevote.message_bytes());
        let signed_prevote = SignedBftVote {
            vote: prevote.clone(),
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(prevote_sig.to_bytes()),
        };
        round.register_prevote(&signed_prevote).unwrap();

        let precommit_vote = BftVote {
            kind: BftVoteKind::PreCommit,
            ..prevote
        };
        let precommit_sig = keypair.sign(&precommit_vote.message_bytes());
        let signed_precommit = SignedBftVote {
            vote: precommit_vote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(precommit_sig.to_bytes()),
        };
        round.register_precommit(&signed_precommit).unwrap();
        assert!(round.commit_reached());
        assert_eq!(round.commit_participants(), vec![address.clone()]);
        let certificate = round.certificate();
        assert_eq!(certificate.pre_votes.len(), 1);
        assert_eq!(certificate.pre_commits.len(), 1);
    }

    #[test]
    fn consensus_round_accepts_higher_round_votes() {
        let height = 5;
        let round_number = 3;
        let (mut round, keypair, address, block_hash) =
            validator_round_with_params(100, height, round_number);
        assert_eq!(round.round(), round_number);
        assert_eq!(round.height(), height);

        let vote = BftVote {
            round: round_number,
            height,
            block_hash: block_hash.clone(),
            voter: address.clone(),
            kind: BftVoteKind::PreVote,
        };
        let signature = keypair.sign(&vote.message_bytes());
        let signed_vote = SignedBftVote {
            vote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(signature.to_bytes()),
        };

        round.register_prevote(&signed_vote).unwrap();
    }

    #[test]
    fn consensus_round_rejects_mismatched_vote() {
        let (mut round, keypair, address, block_hash) = validator_round();
        let mismatched_vote = BftVote {
            round: round.round(),
            height: round.height(),
            block_hash: block_hash,
            voter: address.clone(),
            kind: BftVoteKind::PreVote,
        };
        let mut tampered = mismatched_vote.clone();
        tampered.block_hash = hex::encode([9u8; 32]);
        let signature = keypair.sign(&tampered.message_bytes());
        let signed = SignedBftVote {
            vote: tampered,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(signature.to_bytes()),
        };
        let err = round.register_prevote(&signed).unwrap_err();
        assert!(matches!(err, ChainError::Crypto(_)));
    }

    #[test]
    fn consensus_round_reports_vrf_metrics() {
        let (round, _, _, _) = validator_round();
        let metrics = round.vrf_metrics().clone();
        assert_eq!(metrics.pool_entries, 1);
        assert_eq!(metrics.verified_submissions, 1);
        assert_eq!(metrics.accepted_validators, 1);
        assert_eq!(metrics.rejected_candidates, 0);
        assert!(!metrics.fallback_selected);
        assert_eq!(metrics.target_validator_count, 100);
    }

    #[test]
    fn consensus_round_metrics_flag_fallback_usage() {
        let (round, _, _, _) = validator_round_with_target(0);
        let metrics = round.vrf_metrics().clone();
        assert_eq!(metrics.pool_entries, 1);
        assert_eq!(metrics.verified_submissions, 1);
        assert_eq!(metrics.accepted_validators, 0);
        assert!(metrics.rejected_candidates >= 1);
        assert!(metrics.fallback_selected);
        assert_eq!(metrics.target_validator_count, 0);
    }

    #[test]
    fn evidence_pool_flags_double_sign() {
        let (_, keypair, address, block_hash) = validator_round();
        let vote = BftVote {
            round: 1,
            height: 1,
            block_hash: block_hash.clone(),
            voter: address.clone(),
            kind: BftVoteKind::PreVote,
        };
        let signature = keypair.sign(&vote.message_bytes());
        let mut signed = SignedBftVote {
            vote: vote.clone(),
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(signature.to_bytes()),
        };
        let mut pool = EvidencePool::default();
        assert!(pool.record_vote(&signed).is_none());
        signed.vote.block_hash = hex::encode([7u8; 32]);
        let double_sign = pool.record_vote(&signed).expect("double sign detected");
        assert_eq!(double_sign.address, address);
        assert_eq!(double_sign.vote_kind, Some(BftVoteKind::PreVote));
        assert_eq!(double_sign.block_hashes.len(), 2);
    }

    #[test]
    fn evidence_pool_prunes_entries() {
        let (_, keypair, address, block_hash) = validator_round();
        let vote = BftVote {
            round: 1,
            height: 5,
            block_hash: block_hash.clone(),
            voter: address.clone(),
            kind: BftVoteKind::PreCommit,
        };
        let signature = keypair.sign(&vote.message_bytes());
        let signed = SignedBftVote {
            vote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(signature.to_bytes()),
        };
        let mut pool = EvidencePool::default();
        assert!(pool.record_vote(&signed).is_none());
        pool.prune_below(6);
        assert!(pool.record_vote(&signed).is_none());
    }
}
