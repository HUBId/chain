use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use malachite::Natural;
use malachite::base::num::arithmetic::traits::DivRem;
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::crypto::{
    address_from_public_key, public_key_from_hex, signature_from_hex, verify_signature,
};
use crate::errors::{ChainError, ChainResult};
use crate::reputation::Tier;
use crate::types::{Account, Address, Stake};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VrfProof {
    pub randomness: Natural,
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposerSelection {
    pub proposer: Address,
    pub randomness: Natural,
    pub proof: VrfProof,
    pub total_voting_power: Natural,
    pub quorum_threshold: Natural,
    pub timetoke_hours: u64,
    pub tier: Tier,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

const VRF_SELECTION_WINDOW: u64 = 1_000_000;
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
    pub selection_slot: u64,
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

struct EvaluatedCandidate {
    profile: ValidatorCandidate,
    vrf: VrfProof,
    slot: u64,
    threshold: u64,
}

impl EvaluatedCandidate {
    fn into_validator_profile(self) -> ValidatorProfile {
        ValidatorProfile {
            address: self.profile.address,
            stake: self.profile.stake,
            reputation_score: self.profile.reputation_score,
            tier: self.profile.tier,
            timetoke_hours: self.profile.timetoke_hours,
            vrf: self.vrf,
            selection_slot: self.slot,
        }
    }
}

fn timetoke_threshold(hours: u64) -> u64 {
    let base = VRF_SELECTION_WINDOW / 10;
    let capped = hours.min(MAX_TIMETOKE_HOURS);
    if MAX_TIMETOKE_HOURS == 0 {
        return base;
    }
    let bonus_range = VRF_SELECTION_WINDOW.saturating_sub(base);
    base + (bonus_range * capped) / MAX_TIMETOKE_HOURS
}

fn vrf_selection_slot(proof: &VrfProof) -> u64 {
    match hex::decode(&proof.proof) {
        Ok(bytes) if bytes.len() >= 8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            u64::from_be_bytes(buf) % VRF_SELECTION_WINDOW
        }
        Ok(bytes) => {
            let mut buf = [0u8; 8];
            let start = 8 - bytes.len();
            buf[start..].copy_from_slice(&bytes);
            u64::from_be_bytes(buf) % VRF_SELECTION_WINDOW
        }
        Err(_) => VRF_SELECTION_WINDOW.saturating_sub(1),
    }
}

fn candidate_cmp(a: &EvaluatedCandidate, b: &EvaluatedCandidate) -> Ordering {
    let tier_cmp = a.profile.tier.cmp(&b.profile.tier);
    if tier_cmp != Ordering::Equal {
        return tier_cmp;
    }
    let timetoke_cmp = a.profile.timetoke_hours.cmp(&b.profile.timetoke_hours);
    if timetoke_cmp != Ordering::Equal {
        return timetoke_cmp;
    }
    let slot_cmp = b.slot.cmp(&a.slot);
    if slot_cmp != Ordering::Equal {
        return slot_cmp;
    }
    b.profile.address.cmp(&a.profile.address)
}

fn leader_cmp(a: &ValidatorProfile, b: &ValidatorProfile) -> Ordering {
    let tier_cmp = a.tier.cmp(&b.tier);
    if tier_cmp != Ordering::Equal {
        return tier_cmp;
    }
    let timetoke_cmp = a.timetoke_hours.cmp(&b.timetoke_hours);
    if timetoke_cmp != Ordering::Equal {
        return timetoke_cmp;
    }
    let slot_cmp = b.selection_slot.cmp(&a.selection_slot);
    if slot_cmp != Ordering::Equal {
        return slot_cmp;
    }
    b.address.cmp(&a.address)
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

fn natural_from_bytes(bytes: &[u8]) -> Natural {
    let mut value = Natural::from(0u32);
    for byte in bytes {
        value *= Natural::from(256u32);
        value += Natural::from(*byte);
    }
    value
}

fn vrf_domain(seed: &[u8; 32], round: u64, address: &Address, timetoke_hours: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + 8 + 8 + address.len());
    data.extend_from_slice(seed);
    data.extend_from_slice(&round.to_le_bytes());
    data.extend_from_slice(address.as_bytes());
    data.extend_from_slice(&timetoke_hours.to_le_bytes());
    data
}

pub fn evaluate_vrf(
    seed: &[u8; 32],
    round: u64,
    address: &Address,
    timetoke_hours: u64,
) -> VrfProof {
    let data = vrf_domain(seed, round, address, timetoke_hours);
    let hash = Blake2sHasher::hash(&data);
    let hash_bytes: [u8; 32] = hash.into();
    VrfProof {
        randomness: natural_from_bytes(&hash_bytes),
        proof: hex::encode(hash_bytes),
    }
}

pub fn verify_vrf(
    seed: &[u8; 32],
    round: u64,
    address: &Address,
    timetoke_hours: u64,
    proof: &VrfProof,
) -> bool {
    let expected = evaluate_vrf(seed, round, address, timetoke_hours);
    expected.proof == proof.proof && expected.randomness == proof.randomness
}

#[derive(Clone, Debug)]
pub struct ConsensusRound {
    round: u64,
    seed: [u8; 32],
    validators: Vec<ValidatorProfile>,
    observers: Vec<ObserverProfile>,
    voting_power: HashMap<Address, Natural>,
    total_power: Natural,
    quorum: Natural,
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
        round: u64,
        seed: [u8; 32],
        candidates: Vec<ValidatorCandidate>,
        observers: Vec<ObserverProfile>,
    ) -> Self {
        let mut voting_power = HashMap::new();
        let mut total_power = Natural::from(0u32);
        let mut validators = Vec::new();
        let mut fallback: Option<EvaluatedCandidate> = None;
        for candidate in candidates.into_iter() {
            let vrf = evaluate_vrf(&seed, round, &candidate.address, candidate.timetoke_hours);
            let slot = vrf_selection_slot(&vrf);
            let threshold = timetoke_threshold(candidate.timetoke_hours);
            let evaluated = EvaluatedCandidate {
                profile: candidate,
                vrf,
                slot,
                threshold,
            };
            if evaluated.slot <= evaluated.threshold {
                let profile = evaluated.into_validator_profile();
                let power = profile.voting_power();
                total_power += power.clone();
                voting_power.insert(profile.address.clone(), power);
                validators.push(profile);
            } else {
                match &mut fallback {
                    Some(current) => {
                        if candidate_cmp(&evaluated, current) == Ordering::Greater {
                            *current = evaluated;
                        }
                    }
                    None => {
                        fallback = Some(evaluated);
                    }
                }
            }
        }
        if validators.is_empty() {
            if let Some(evaluated) = fallback {
                let profile = evaluated.into_validator_profile();
                let power = profile.voting_power();
                total_power += power.clone();
                voting_power.insert(profile.address.clone(), power);
                validators.push(profile);
            }
        }
        validators.sort_by(|a, b| a.address.cmp(&b.address));
        let quorum = quorum_threshold(&total_power);
        Self {
            round,
            seed,
            validators,
            observers,
            voting_power,
            total_power,
            quorum,
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

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn observers(&self) -> &[ObserverProfile] {
        &self.observers
    }

    pub fn validators(&self) -> &[ValidatorProfile] {
        &self.validators
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
        let leader = self.validators.iter().max_by(|a, b| leader_cmp(a, b))?;
        let selection = ProposerSelection {
            proposer: leader.address.clone(),
            randomness: leader.vrf.randomness.clone(),
            proof: leader.vrf.clone(),
            total_voting_power: self.total_power.clone(),
            quorum_threshold: self.quorum.clone(),
            timetoke_hours: leader.timetoke_hours,
            tier: leader.tier.clone(),
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
        if vote.vote.height != self.round {
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
    use crate::crypto::address_from_public_key;
    use crate::reputation::Tier;
    use crate::types::{Account, Stake};
    use ed25519_dalek::{Keypair, Signer};
    use rand::rngs::OsRng;

    fn validator_round() -> (ConsensusRound, Keypair, Address, String) {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let address = address_from_public_key(&keypair.public);
        let mut account = Account::new(address.clone(), 0, Stake::from_u128(1_000));
        account.reputation.tier = Tier::Tl3;
        account.reputation.score = 1.0;
        account.reputation.timetokes.hours_online = super::MAX_TIMETOKE_HOURS;
        let (validators, observers) = classify_participants(&[account]);
        let mut round = ConsensusRound::new(1, [0u8; 32], validators, observers);
        let block_hash = hex::encode([5u8; 32]);
        round.set_block_hash(block_hash.clone());
        (round, keypair, address, block_hash)
    }

    #[test]
    fn consensus_round_accepts_signed_votes() {
        let (mut round, keypair, address, block_hash) = validator_round();
        let prevote = BftVote {
            round: round.round(),
            height: round.round(),
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
    fn consensus_round_rejects_mismatched_vote() {
        let (mut round, keypair, address, block_hash) = validator_round();
        let mismatched_vote = BftVote {
            round: round.round(),
            height: round.round(),
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
}
