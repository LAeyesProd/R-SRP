use chrono::Utc;
use crue_engine::{
    context::EvaluationContext,
    engine::CrueEngine,
    rules::{Rule, RuleAction, RuleCondition, RuleRegistry},
    vm::BytecodeVm,
    EvaluationRequest,
};
use immutable_logging::{
    chain::verify_chain_proof,
    log_entry::{Decision as LogDecision, EventType, LogEntry},
    ImmutableLog,
};
use pqcrypto::{hybrid::HybridSigner, Dilithium, DilithiumLevel};

fn map_decision(d: crue_engine::decision::Decision) -> LogDecision {
    match d {
        crue_engine::decision::Decision::Allow => LogDecision::Allow,
        crue_engine::decision::Decision::Block => LogDecision::Block,
        crue_engine::decision::Decision::Warn => LogDecision::Warn,
        crue_engine::decision::Decision::ApprovalRequired => LogDecision::ApprovalRequired,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let src = r#"RULE CRUE_900 VERSION 1.0 WHEN agent.requests_last_hour >= 50 THEN BLOCK WITH CODE "VOLUME_EXCEEDED""#;
    let ast = crue_dsl::parser::parse(src)?;
    let bytecode = crue_dsl::compiler::Compiler::compile(&ast)?;

    let mut registry = RuleRegistry::empty();
    registry.add_rule(Rule {
        id: "CRUE_900".into(),
        version: "1.0.0".into(),
        name: "DEMO_VOLUME".into(),
        description: "Block at 50 req/h".into(),
        severity: "HIGH".into(),
        condition: RuleCondition {
            field: "agent.requests_last_hour".into(),
            operator: ">=".into(),
            value: 50,
        },
        action: RuleAction {
            action_type: "BLOCK".into(),
            error_code: Some("VOLUME_EXCEEDED".into()),
            message: Some("Demo policy matched".into()),
            timeout_minutes: None,
            alert_soc: true,
        },
        valid_from: Utc::now(),
        valid_until: None,
        enabled: true,
    });
    let mut engine = CrueEngine::new();
    engine.load_rules(registry);
    engine.register_compiled_rule_ast(&ast)?;
    let req = EvaluationRequest {
        request_id: "demo-req-001".into(),
        agent_id: "agent-007".into(),
        agent_org: "ACME".into(),
        agent_level: "standard".into(),
        mission_id: None,
        mission_type: None,
        query_type: None,
        justification: Some("monthly audit".into()),
        export_format: None,
        result_limit: Some(10),
        requests_last_hour: 55,
        requests_last_24h: 120,
        results_last_query: 3,
        account_department: None,
        allowed_departments: vec![],
        request_hour: 10,
        is_within_mission_hours: true,
    };
    let engine_hybrid_signer = HybridSigner::new(DilithiumLevel::Dilithium2);
    let engine_hybrid_kp = engine_hybrid_signer.generate_keypair()?;
    let engine_hybrid_pk = engine_hybrid_kp.public_key();
    let (eval, engine_envelope_v1) = engine.evaluate_with_signed_proof_v1_hybrid(
        &req,
        "demo-pq-proof-key-1",
        &engine_hybrid_signer,
        &engine_hybrid_kp,
    );
    let (_eval2, engine_binding) =
        engine.evaluate_with_proof(&req, engine_hybrid_signer.backend_id());
    let ctx = EvaluationContext::from_request(&req);
    let vm_eval = BytecodeVm::eval(&bytecode, &ctx)?;

    let dilithium = Dilithium::new(DilithiumLevel::Dilithium2);
    let (pk, sk) = dilithium.generate_keypair()?;
    let pq_sig = dilithium.sign(&sk, &bytecode.instructions)?;
    let pq_ok = dilithium.verify(&pk, &bytecode.instructions, &pq_sig)?;
    let binding_ok = if let Some(binding) = &engine_binding {
        binding.verify_recompute(
            &bytecode,
            &req,
            &ctx,
            eval.decision,
            engine_hybrid_signer.backend_id(),
        )?
    } else {
        false
    };
    let engine_sig_ok = if let Some(envelope) = &engine_envelope_v1 {
        envelope.verify_hybrid(&engine_hybrid_pk)?
    } else {
        false
    };
    let engine_proof_v1_bytes = if let Some(envelope) = &engine_envelope_v1 {
        Some(envelope.canonical_bytes()?)
    } else {
        None
    };
    let engine_proof_v1 = engine_proof_v1_bytes.is_some();
    let (engine_proof_v1_size, engine_proof_v1_hash) = if let Some(bytes) = &engine_proof_v1_bytes {
        let digest = crypto_core::hash::sha256(&bytes);
        (bytes.len(), crypto_core::hash::hex_encode(&digest))
    } else {
        (0usize, String::from("-"))
    };

    let log = ImmutableLog::new();
    let mut builder = LogEntry::builder(
        EventType::RuleViolation,
        req.agent_id.clone(),
        req.agent_org.clone(),
    )
    .decision(map_decision(eval.decision));
    if let Some(rule_id) = &eval.rule_id {
        builder = builder.rule_id(rule_id.clone());
    }
    if let Some(bytes) = &engine_proof_v1_bytes {
        builder = builder.proof_envelope_v1_bytes(bytes);
    }
    let entry = builder.build()?;
    let appended = log.append(entry).await?;
    let ledger_proof_attached = appended.proof_envelope_v1_b64().is_some();
    let proof = log
        .get_chain_proof(appended.entry_id())
        .await
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "proof missing"))?;
    let proof_ok = verify_chain_proof(&proof);
    let chain_ok = log.verify().await?;

    println!("policy={} vm_eval={} bytecode={} decision={} pq_backend={} pq_sig={} pq_verify={} engine_proof_backend={} engine_binding={} binding_ok={} engine_proof_v1={} engine_v1_size={} engine_v1_sha256={} engine_sig_ok={} ledger_proof_attached={} ledger_entry={} chain_verify={} proof_verify={}",
        ast.id, vm_eval, bytecode.instructions.len(), eval.decision, dilithium.backend_id(), pq_sig.signature.len(), pq_ok, engine_hybrid_signer.backend_id(), engine_binding.is_some(), binding_ok, engine_proof_v1, engine_proof_v1_size, engine_proof_v1_hash, engine_sig_ok, ledger_proof_attached, appended.entry_id(), chain_ok, proof_ok);
    Ok(())
}
