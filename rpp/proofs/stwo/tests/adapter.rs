use crate::stwo::air::{AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain};
use crate::stwo::circuit::{ExecutionTrace, TraceSegment};
use crate::stwo::conversions::{field_to_base, field_to_secure};
use crate::stwo::official_adapter::{BlueprintComponent, ColumnVec, TreeVec};
#[cfg(feature = "backend-stwo")]
use crate::stwo::official_adapter::{Component, ComponentProver};
use crate::stwo::params::{FieldElement, StarkParameters};

#[cfg(feature = "backend-stwo")]
use num_traits::{One, Zero};
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::core::air::accumulation::PointEvaluationAccumulator;
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::core::circle::CirclePoint;
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::core::constraints::point_vanishing;
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::core::fields::m31::BaseField;
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::core::fields::qm31::SecureField;
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::core::fields::FieldExpOps;
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::core::poly::circle::CanonicCoset;
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::prover::DomainEvaluationAccumulator;
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::prover::Trace;
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::prover::poly::circle::PolyOps;
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::prover::backend::cpu::{CpuBackend, CpuCircleEvaluation, CpuCirclePoly};
#[cfg(feature = "backend-stwo")]
use stwo::stwo_official::prover::poly::{BitReversedOrder, NaturalOrder};

fn constant_segment(
    parameters: &StarkParameters,
    name: &str,
    column_names: &[&str],
    row_values: &[[u64; 2]],
) -> TraceSegment {
    let columns = column_names
        .iter()
        .map(|column| column.to_string())
        .collect();
    let rows = row_values
        .iter()
        .map(|values| {
            values
                .iter()
                .map(|value| parameters.element_from_u64(*value))
                .collect::<Vec<FieldElement>>()
        })
        .collect();
    TraceSegment::new(name, columns, rows).expect("valid segment")
}

#[cfg(feature = "backend-stwo")]
fn build_mask_values(
    trace: &ExecutionTrace,
    component: &BlueprintComponent,
    mask_points: &TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
) -> TreeVec<ColumnVec<Vec<SecureField>>> {
    let mut trees = Vec::with_capacity(mask_points.len());
    for (tree_index, columns) in mask_points.iter().enumerate() {
        if tree_index == 0 {
            trees.push(Vec::new());
            continue;
        }
        let segment = &trace.segments[tree_index - 1];
        let column_values = columns
            .iter()
            .enumerate()
            .map(|(column_index, offsets)| {
                let value = &segment.rows[0][column_index];
                let secure_value = field_to_secure(value);
                vec![secure_value; offsets.len()]
            })
            .collect();
        trees.push(column_values);
    }
    TreeVec(trees)
}

#[cfg(feature = "backend-stwo")]
#[test]
fn point_quotients_match_blueprint_evaluations() {
    let parameters = StarkParameters::blueprint_default();

    // Blueprint trace with a deliberate mismatch on the first row so that the
    // numerator remains constant across all extension points.
    let segment = constant_segment(
        &parameters,
        "adapter_minimal",
        &["a", "b"],
        &[[3, 5], [7, 9]],
    );
    let trace = ExecutionTrace::single(segment.clone()).expect("execution trace");

    let column_a = AirColumn::new(segment.name.clone(), segment.columns[0].clone());
    let column_b = AirColumn::new(segment.name.clone(), segment.columns[1].clone());
    let constraint = AirConstraint::new(
        "b_minus_a",
        segment.name.clone(),
        ConstraintDomain::FirstRow,
        AirExpression::difference(column_b.expr(), column_a.expr()),
    );
    let air = AirDefinition::new(vec![constraint]);

    let component = BlueprintComponent::new(&air, &trace, &parameters).expect("component");
    let descriptor = &component.segments[0];
    let coset = CanonicCoset::new(descriptor.log_size.max(1));

    let evaluations = air.evaluate(&trace, &parameters).expect("air evaluation");
    let numerator_field = &evaluations[0].rows[0].1;
    let numerator_secure = field_to_secure(numerator_field);

    let sample_points = [3u128, 11, 27].map(CirclePoint::get_point);
    for point in sample_points {
        let mask_points = component.mask_points(point);
        let mask = build_mask_values(&trace, &component, &mask_points);

        let mut accumulator = PointEvaluationAccumulator::new(SecureField::one());
        component.evaluate_constraint_quotients_at_point(point, &mask, &mut accumulator);
        let combined = accumulator.finalize();

        let denominator = point_vanishing(coset.at(0), point);
        assert!(!denominator.is_zero(), "unexpected vanishing denominator");

        let expected = numerator_secure * denominator.inverse();
        assert_eq!(combined, expected);
    }
}

#[cfg(feature = "backend-stwo")]
#[test]
fn domain_quotients_align_with_blueprint_trace() {
    let parameters = StarkParameters::blueprint_default();
    // Scenario mirrors a minimal range-check where b = a + 1 on every row.
    let segment = constant_segment(
        &parameters,
        "adapter_domain",
        &["a", "b"],
        &[[0, 1], [1, 2], [2, 3], [3, 4]],
    );
    let trace = ExecutionTrace::single(segment.clone()).expect("execution trace");

    let column_a = AirColumn::new(segment.name.clone(), segment.columns[0].clone());
    let column_b = AirColumn::new(segment.name.clone(), segment.columns[1].clone());
    let one = FieldElement::one(parameters.modulus());
    let constraint = AirConstraint::new(
        "b_matches_a_plus_one",
        segment.name.clone(),
        ConstraintDomain::AllRows,
        AirExpression::difference(
            column_b.expr(),
            AirExpression::sum(vec![column_a.expr(), AirExpression::constant(one)]),
        ),
    );
    let air = AirDefinition::new(vec![constraint]);
    let component = BlueprintComponent::new(&air, &trace, &parameters).expect("component");

    // Build the prover trace via the same conversion pipeline the adapter uses.
    let descriptor = &component.segments[0];
    let log_size = descriptor.log_size.max(1);
    let domain_size = 1 << log_size;

    let mut circle_evals = Vec::with_capacity(descriptor.column_count);
    for column_index in 0..descriptor.column_count {
        let mut base_values: Vec<BaseField> = segment
            .rows
            .iter()
            .map(|row| field_to_base(&row[column_index]))
            .collect();
        base_values.resize(domain_size, BaseField::zero());
        let domain = CanonicCoset::new(log_size).circle_domain();
        let evaluation =
            CpuCircleEvaluation::<BaseField, NaturalOrder>::new(domain, base_values).bit_reverse();
        circle_evals.push(evaluation);
    }
    let circle_polys: Vec<CpuCirclePoly> = circle_evals
        .iter()
        .cloned()
        .map(|evaluation| evaluation.interpolate())
        .collect();
    let eval_refs: Vec<&CpuCircleEvaluation<BaseField, BitReversedOrder>> =
        circle_evals.iter().collect();
    let poly_refs: Vec<&CpuCirclePoly> = circle_polys.iter().collect();
    let trace_for_prover = Trace {
        polys: TreeVec(vec![Vec::new(), poly_refs]),
        evals: TreeVec(vec![Vec::new(), eval_refs]),
    };

    let randomizer = field_to_secure(&parameters.element_from_u64(7));
    let mut accumulator = DomainEvaluationAccumulator::new(
        randomizer,
        component.max_constraint_log_degree_bound(),
        component.n_constraints(),
    );
    component.evaluate_constraint_quotients_on_domain(&trace_for_prover, &mut accumulator);

    let composition = accumulator.finalize();
    let secure_zero = field_to_secure(&parameters.element_from_u64(0));
    let eval_domain = CanonicCoset::new(composition.log_size()).circle_domain();
    let twiddles = CpuBackend::precompute_twiddles(eval_domain.half_coset);
    let aggregated = composition.evaluate_with_twiddles(eval_domain, &twiddles);
    for value in aggregated.values.to_cpu().to_vec() {
        assert_eq!(value, secure_zero);
    }

    let evaluations = air.evaluate(&trace, &parameters).expect("air evaluation");
    assert!(
        evaluations
            .iter()
            .all(|evaluation| evaluation.is_satisfied())
    );
}
