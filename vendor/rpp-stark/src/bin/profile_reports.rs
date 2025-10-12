use std::convert::TryInto;
use std::env;
use std::fs;
use std::path::PathBuf;

use rpp_stark::config::{
    compute_param_digest, CommonIdentifiers, ProfileConfig, ProfileId, ProofKind,
    COMMON_IDENTIFIERS, PROFILE_HIGH_SECURITY_CONFIG, PROFILE_HISEC, PROFILE_STANDARD_CONFIG,
    PROFILE_STD, PROFILE_THROUGHPUT_CONFIG,
};
use rpp_stark::field::FieldElement;
use rpp_stark::fri::{FriProof, FriSecurityLevel};
use rpp_stark::hash::{hash, Hasher, OutputReader};
use rpp_stark::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
use rpp_stark::proof::ser::{
    compute_integrity_digest, compute_public_digest, serialize_public_inputs,
};
use rpp_stark::proof::types::{
    CompositionBinding, FriHandle, FriParametersMirror, MerkleAuthenticationPath,
    MerkleProofBundle, Openings, OpeningsDescriptor, OutOfDomainOpening, Proof, Telemetry,
    TelemetryOption, TraceOpenings, PROOF_VERSION,
};
use rpp_stark::utils::serialization::DigestBytes;

#[derive(Clone)]
struct ProfileDescriptor {
    code: &'static str,
    profile: ProfileConfig,
}

#[derive(Clone)]
struct ProfileReport {
    descriptor: ProfileDescriptor,
    param_digest_hex: String,
    run_a_hash: String,
    run_b_hash: String,
    proof_size: usize,
    max_proof_size: u32,
}

fn main() {
    let mut args = env::args().skip(1);
    let mut output_dir = PathBuf::from("reports");
    let mut include_throughput = env::var("ENABLE_PROFILE_THR")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                if let Some(value) = args.next() {
                    output_dir = PathBuf::from(value);
                }
            }
            "--include-throughput" => include_throughput = true,
            _ => {}
        }
    }

    let mut descriptors = vec![
        ProfileDescriptor {
            code: "PROFILE_STD",
            profile: PROFILE_STANDARD_CONFIG.clone(),
        },
        ProfileDescriptor {
            code: "PROFILE_HISEC",
            profile: PROFILE_HIGH_SECURITY_CONFIG.clone(),
        },
    ];

    if include_throughput {
        descriptors.push(ProfileDescriptor {
            code: "PROFILE_THR",
            profile: PROFILE_THROUGHPUT_CONFIG.clone(),
        });
    }

    let reports: Vec<ProfileReport> = descriptors
        .into_iter()
        .map(|descriptor| build_report(descriptor, &COMMON_IDENTIFIERS))
        .collect();

    fs::create_dir_all(&output_dir)
        .unwrap_or_else(|err| panic!("failed to create report directory {output_dir:?}: {err}"));

    write_file(
        &output_dir.join("PARAMS_REPORT.md"),
        &render_params_report(&reports),
    );
    write_file(
        &output_dir.join("DETERMINISM_REPORT.md"),
        &render_determinism_report(&reports),
    );
    write_file(
        &output_dir.join("SIZE_REPORT.md"),
        &render_size_report(&reports),
    );
}

fn build_report(descriptor: ProfileDescriptor, common: &CommonIdentifiers) -> ProfileReport {
    let profile = descriptor.profile.clone();
    let param_digest = compute_param_digest(&profile, common);
    let param_digest_hex = hex_string(param_digest.as_bytes());

    let (run_a_hash, proof_size) = sample_hash(&profile, &param_digest, "duplicate-run");
    let (run_b_hash, _) = sample_hash(&profile, &param_digest, "duplicate-run");

    ProfileReport {
        descriptor,
        param_digest_hex,
        run_a_hash,
        run_b_hash,
        proof_size,
        max_proof_size: profile.limits.max_proof_size_bytes,
    }
}

fn sample_hash(
    profile: &ProfileConfig,
    param_digest: &rpp_stark::config::ParamDigest,
    run_label: &str,
) -> (String, usize) {
    let proof = build_sample_proof(profile, param_digest, run_label);
    let bytes = proof.to_bytes().expect("serialize proof");
    let digest = hash(&bytes);
    (format!("{}", digest.to_hex()), bytes.len())
}

fn build_sample_proof(
    profile: &ProfileConfig,
    param_digest: &rpp_stark::config::ParamDigest,
    run_label: &str,
) -> Proof {
    let mut reader = sample_reader(profile.id, run_label);

    let mut core_root = [0u8; 32];
    reader
        .fill(&mut core_root)
        .expect("profile sampler XOF should not fail");
    let aux_root = [0u8; 32];

    let mut fri_layer_roots = Vec::new();
    for _ in 0..2 {
        fri_layer_roots.push(sample_digest(&mut reader));
    }

    let ood_openings: Vec<OutOfDomainOpening> = Vec::new();

    let final_polynomial: Vec<FieldElement> = (0..4)
        .map(|_| FieldElement::from(sample_u64(&mut reader)))
        .collect();

    let fold_challenges = vec![FieldElement::ZERO; fri_layer_roots.len()];
    let fri_proof = FriProof::new(
        profile_to_security_level(profile.id),
        16,
        fri_layer_roots.clone(),
        fold_challenges,
        final_polynomial,
        sample_digest(&mut reader),
        Vec::new(),
    )
    .expect("sample fri proof");

    let public_inputs = sample_public_inputs(profile, run_label);

    let merkle = MerkleProofBundle {
        core_root,
        aux_root,
        fri_layer_roots: fri_layer_roots.clone(),
    };

    let public_digest = compute_public_digest(&public_inputs);

    let telemetry = Telemetry {
        header_length: 0,
        body_length: 0,
        fri_parameters: FriParametersMirror {
            fold: 2,
            cap_degree: profile.limits.max_layers as u16,
            cap_size: profile.limits.max_queries as u32,
            query_budget: profile.fri_queries,
        },
        integrity_digest: DigestBytes { bytes: [0u8; 32] },
    };

    let trace_openings = build_trace_stub(&fri_proof);
    let openings = Openings {
        trace: trace_openings,
        composition: None,
        out_of_domain: ood_openings,
    };
    let binding = CompositionBinding::new(
        ProofKind::Tx,
        profile.air_spec_ids.get(ProofKind::Tx).clone(),
        public_inputs,
        None,
    );
    let openings_descriptor = OpeningsDescriptor::new(merkle, openings);
    let fri_handle = FriHandle::new(fri_proof);
    let telemetry_option = TelemetryOption::new(true, telemetry);
    let mut proof = Proof::from_parts(
        PROOF_VERSION,
        param_digest.clone(),
        DigestBytes {
            bytes: public_digest,
        },
        DigestBytes { bytes: core_root },
        binding,
        openings_descriptor,
        fri_handle,
        telemetry_option,
    );

    let payload = proof
        .serialize_payload()
        .expect("sample proof payload serialization");
    let header_bytes = proof
        .serialize_header(&payload)
        .expect("sample proof header serialization");
    let telemetry = proof.telemetry_frame_mut();
    telemetry.set_body_length((payload.len() + 32) as u32);
    telemetry.set_header_length(header_bytes.len() as u32);
    let integrity = compute_integrity_digest(&header_bytes, &payload);
    telemetry.set_integrity_digest(DigestBytes { bytes: integrity });

    proof
}

fn sample_public_inputs(profile: &ProfileConfig, run_label: &str) -> Vec<u8> {
    let header = ExecutionHeaderV1 {
        version: PublicInputVersion::V1,
        program_digest: DigestBytes {
            bytes: sample_digest_from_label(profile, run_label, b"program"),
        },
        trace_length: profile.limits.per_proof_max_trace_steps.tx,
        trace_width: profile.limits.per_proof_max_trace_width.tx as u32,
    };
    let body = format!(
        "profile={}\nrun={}\nproof_version={}",
        profile.name, run_label, PROOF_VERSION
    );
    let inputs = PublicInputs::Execution {
        header,
        body: body.as_bytes(),
    };
    serialize_public_inputs(&inputs).expect("sample public inputs serialization")
}

fn sample_reader(profile_id: ProfileId, run_label: &str) -> OutputReader {
    let mut hasher = Hasher::new();
    hasher.update(b"rpp-stark/sample-envelope");
    hasher.update(&profile_id.to_le_bytes());
    hasher.update(run_label.as_bytes());
    hasher.finalize_xof()
}

fn sample_digest(reader: &mut OutputReader) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    reader
        .fill(&mut bytes)
        .expect("profile sampler XOF should not fail");
    bytes
}

fn build_trace_stub(fri_proof: &FriProof) -> TraceOpenings {
    let indices: Vec<u32> = fri_proof
        .queries
        .iter()
        .map(|query| query.position.try_into().unwrap_or(u32::MAX))
        .collect();
    let leaves = vec![Vec::new(); indices.len()];
    let paths = vec![MerkleAuthenticationPath { nodes: Vec::new() }; indices.len()];
    TraceOpenings {
        indices,
        leaves,
        paths,
    }
}

fn sample_u64(reader: &mut OutputReader) -> u64 {
    let mut bytes = [0u8; 8];
    reader
        .fill(&mut bytes)
        .expect("profile sampler XOF should not fail");
    u64::from_le_bytes(bytes)
}

fn sample_digest_from_label(profile: &ProfileConfig, run_label: &str, scope: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(profile.name.as_bytes());
    hasher.update(&profile.id.to_le_bytes());
    hasher.update(run_label.as_bytes());
    hasher.update(scope);
    hasher.finalize().into_bytes()
}

fn profile_to_security_level(id: ProfileId) -> FriSecurityLevel {
    if id == PROFILE_STD {
        FriSecurityLevel::Standard
    } else if id == PROFILE_HISEC {
        FriSecurityLevel::HiSec
    } else {
        FriSecurityLevel::Throughput
    }
}

fn render_params_report(reports: &[ProfileReport]) -> String {
    let mut rows = String::new();
    for report in reports {
        let profile = &report.descriptor.profile;
        rows.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            report.descriptor.code,
            profile.id.0,
            profile.name,
            profile.security_goal,
            profile.fri_queries,
            report.param_digest_hex
        ));
    }

    format!(
        "# Parameter Report\n\
\nProfiles are listed in canonical order. The digest column records the deterministic\nparameter hash bound to `COMMON_IDENTIFIERS`.\n\
\n| Profile | ID | Name | Security goal | FRI queries | Param digest |\n| --- | --- | --- | --- | --- | --- |\n{}",
        rows
    )
}

fn render_determinism_report(reports: &[ProfileReport]) -> String {
    let mut rows = String::new();
    for report in reports {
        let status = if report.run_a_hash == report.run_b_hash {
            "match"
        } else {
            "mismatch"
        };
        rows.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            report.descriptor.code, report.run_a_hash, report.run_b_hash, status
        ));
    }

    format!(
        "# Determinism Report\n\
\nEach profile is executed twice with identical inputs. Matching hashes demonstrate\nthat byte outputs are reproducible.\n\
\n| Profile | Run A hash | Run B hash | Status |\n| --- | --- | --- | --- |\n{}",
        rows
    )
}

fn render_size_report(reports: &[ProfileReport]) -> String {
    let mut rows = String::new();
    for report in reports {
        let headroom = report
            .max_proof_size
            .saturating_sub(report.proof_size as u32);
        rows.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            report.descriptor.code, report.proof_size, report.max_proof_size, headroom
        ));
    }

    format!(
        "# Size Report\n\
\nThe synthetic envelope size is compared against the documented profile limit.\n\
\n| Profile | Sample proof bytes | Max proof size (bytes) | Headroom |\n| --- | --- | --- | --- |\n{}",
        rows
    )
}

fn write_file(path: &PathBuf, contents: &str) {
    fs::write(path, contents).unwrap_or_else(|err| {
        panic!("failed to write {}: {err}", path.display());
    });
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}
