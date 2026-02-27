//! CRUE Engine Core

use crate::context::EvaluationContext;
use crate::decision::{ActionResult, Decision};
use crate::error::EngineError;
use crate::ir::{ActionInstruction, RuleEffect};
#[cfg(feature = "pq-proof")]
use crate::proof::PqProofEnvelope;
use crate::proof::{ProofBinding, ProofEnvelope, ProofEnvelopeV1};
use crate::rules::RuleRegistry;
use crate::vm::{ActionVm, BytecodeVm, Instruction};
use crate::{EvaluationRequest, EvaluationResult};
use crue_dsl::ast::RuleAst;
use crue_dsl::compiler::{Bytecode, Compiler};
use std::time::Instant;
use tracing::{error, info, warn};

/// Compiled policy rule evaluated through the bytecode VM.
#[derive(Debug, Clone)]
pub struct CompiledPolicyRule {
    pub id: String,
    pub version: String,
    pub policy_hash: String,
    pub bytecode: Bytecode,
    pub effects: Vec<RuleEffect>,
    pub match_program: Vec<Instruction>,
    pub action_program: Vec<ActionInstruction>,
}

impl CompiledPolicyRule {
    pub fn from_ast(ast: &RuleAst) -> Result<Self, EngineError> {
        let policy_hash = hash_policy_ast(ast)?;
        let bytecode =
            Compiler::compile(ast).map_err(|e| EngineError::CompilationError(e.to_string()))?;
        let effects = ast
            .then_clause
            .clone()
            .into_iter()
            .map(RuleEffect::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let action_program = if bytecode.action_instructions.is_empty() {
            // Backward-compatible fallback for bytecode produced before THEN-action compilation existed.
            compile_action_program(&effects)
        } else {
            bytecode
                .action_instructions
                .iter()
                .cloned()
                .map(ActionInstruction::try_from)
                .collect::<Result<Vec<_>, _>>()?
        };
        let primary_decision = ActionVm::execute(&action_program)?.decision;
        let match_program = BytecodeVm::build_match_program(&bytecode, primary_decision)?;
        Ok(Self {
            id: ast.id.clone(),
            version: ast.version.clone(),
            policy_hash,
            bytecode,
            effects,
            match_program,
            action_program,
        })
    }

    pub fn from_source(source: &str) -> Result<Self, EngineError> {
        let ast = crue_dsl::parser::parse(source)
            .map_err(|e| EngineError::CompilationError(e.to_string()))?;
        Self::from_ast(&ast)
    }

    pub fn evaluate(&self, ctx: &EvaluationContext) -> Result<bool, EngineError> {
        BytecodeVm::eval(&self.bytecode, ctx)
    }

    /// Preferred compiled-path evaluation: returns `Some(decision)` on match, `None` otherwise.
    pub fn evaluate_match_decision(
        &self,
        ctx: &EvaluationContext,
    ) -> Result<Option<Decision>, EngineError> {
        BytecodeVm::eval_match_program(&self.match_program, &self.bytecode, ctx)
    }

    pub fn apply_action(&self) -> ActionResult {
        ActionVm::execute(&self.action_program)
            .unwrap_or_else(|_| compiled_actions_to_result(&self.effects))
    }
}

/// CRUE Engine - main rule evaluation engine
pub struct CrueEngine {
    rule_registry: RuleRegistry,
    compiled_rules: Vec<CompiledPolicyRule>,
    strict_mode: bool,
}

impl CrueEngine {
    /// Create new CRUE engine
    pub fn new() -> Self {
        CrueEngine {
            rule_registry: RuleRegistry::new(),
            compiled_rules: Vec::new(),
            strict_mode: true,
        }
    }

    /// Load rules from legacy runtime registry.
    pub fn load_rules(&mut self, registry: RuleRegistry) {
        self.rule_registry = registry;
    }

    /// Replace compiled rules (preferred execution path when non-empty).
    pub fn load_compiled_rules(&mut self, rules: Vec<CompiledPolicyRule>) {
        self.compiled_rules = rules;
    }

    /// Register a compiled rule from AST.
    pub fn register_compiled_rule_ast(&mut self, ast: &RuleAst) -> Result<(), EngineError> {
        self.compiled_rules.push(CompiledPolicyRule::from_ast(ast)?);
        Ok(())
    }

    /// Register a compiled rule from DSL source.
    pub fn register_compiled_rule_source(&mut self, source: &str) -> Result<(), EngineError> {
        self.compiled_rules
            .push(CompiledPolicyRule::from_source(source)?);
        Ok(())
    }

    /// Clear compiled rules and fall back to legacy runtime rules.
    pub fn clear_compiled_rules(&mut self) {
        self.compiled_rules.clear();
    }

    /// Evaluate request against compiled rules first, then legacy runtime rules.
    pub fn evaluate(&self, request: &EvaluationRequest) -> EvaluationResult {
        self.evaluate_internal(request, None).0
    }

    /// Evaluate request and produce a strict `ProofBinding` when the compiled-bytecode path is used.
    ///
    /// Returns `(result, binding)` where `binding` is:
    /// - `Some(..)` when a compiled rule matched and binding generation succeeded
    /// - `None` when evaluation used legacy runtime rules or no compiled rule matched
    pub fn evaluate_with_proof(
        &self,
        request: &EvaluationRequest,
        crypto_backend_id: &str,
    ) -> (EvaluationResult, Option<ProofBinding>) {
        self.evaluate_internal(request, Some(crypto_backend_id))
    }

    /// Evaluate request and return a signed proof envelope (Ed25519 bootstrap signing).
    ///
    /// The envelope is only produced when the compiled-bytecode path is used and a rule matches.
    pub fn evaluate_with_signed_proof_ed25519(
        &self,
        request: &EvaluationRequest,
        crypto_backend_id: &str,
        signer_key_id: &str,
        key_pair: &crypto_core::signature::Ed25519KeyPair,
    ) -> (EvaluationResult, Option<ProofEnvelope>) {
        let (result, binding) = self.evaluate_with_proof(request, crypto_backend_id);
        let Some(binding) = binding else {
            return (result, None);
        };

        match ProofEnvelope::sign_ed25519(binding, signer_key_id.to_string(), key_pair) {
            Ok(envelope) => (result, Some(envelope)),
            Err(e) => {
                error!("Failed to sign proof envelope: {}", e);
                if self.strict_mode {
                    (
                        engine_error_result(
                            request,
                            result.rule_id.clone(),
                            result.rule_version.clone(),
                            &format!("Proof envelope signing error: {}", e),
                            result.evaluation_time_ms,
                        ),
                        None,
                    )
                } else {
                    (result, None)
                }
            }
        }
    }

    /// Evaluate request and return a canonical `ProofEnvelopeV1` signed with Ed25519.
    pub fn evaluate_with_signed_proof_v1_ed25519(
        &self,
        request: &EvaluationRequest,
        crypto_backend_id: &str,
        signer_key_id: &str,
        key_pair: &crypto_core::signature::Ed25519KeyPair,
    ) -> (EvaluationResult, Option<ProofEnvelopeV1>) {
        let (result, binding) = self.evaluate_with_proof(request, crypto_backend_id);
        let Some(binding) = binding else {
            return (result, None);
        };
        match ProofEnvelopeV1::sign_ed25519(&binding, signer_key_id, key_pair) {
            Ok(envelope) => (result, Some(envelope)),
            Err(e) => {
                error!("Failed to sign proof envelope v1: {}", e);
                if self.strict_mode {
                    (
                        engine_error_result(
                            request,
                            result.rule_id.clone(),
                            result.rule_version.clone(),
                            &format!("ProofEnvelopeV1 signing error: {}", e),
                            result.evaluation_time_ms,
                        ),
                        None,
                    )
                } else {
                    (result, None)
                }
            }
        }
    }

    /// Evaluate request and return a signed PQ/hybrid proof envelope.
    ///
    /// Requires the `pq-proof` feature. The envelope is only produced when the
    /// compiled-bytecode path matches a rule.
    #[cfg(feature = "pq-proof")]
    pub fn evaluate_with_signed_proof_hybrid(
        &self,
        request: &EvaluationRequest,
        signer_key_id: &str,
        signer: &pqcrypto::hybrid::HybridSigner,
        keypair: &pqcrypto::hybrid::HybridKeyPair,
    ) -> (EvaluationResult, Option<PqProofEnvelope>) {
        let (result, binding) = self.evaluate_with_proof(request, signer.backend_id());
        let Some(binding) = binding else {
            return (result, None);
        };

        match PqProofEnvelope::sign_hybrid(binding, signer_key_id.to_string(), signer, keypair) {
            Ok(envelope) => (result, Some(envelope)),
            Err(e) => {
                error!("Failed to sign PQ proof envelope: {}", e);
                if self.strict_mode {
                    (
                        engine_error_result(
                            request,
                            result.rule_id.clone(),
                            result.rule_version.clone(),
                            &format!("PQ proof envelope signing error: {}", e),
                            result.evaluation_time_ms,
                        ),
                        None,
                    )
                } else {
                    (result, None)
                }
            }
        }
    }

    /// Evaluate request and return a canonical `ProofEnvelopeV1` signed with the hybrid signer.
    #[cfg(feature = "pq-proof")]
    pub fn evaluate_with_signed_proof_v1_hybrid(
        &self,
        request: &EvaluationRequest,
        signer_key_id: &str,
        signer: &pqcrypto::hybrid::HybridSigner,
        keypair: &pqcrypto::hybrid::HybridKeyPair,
    ) -> (EvaluationResult, Option<ProofEnvelopeV1>) {
        let (result, binding) = self.evaluate_with_proof(request, signer.backend_id());
        let Some(binding) = binding else {
            return (result, None);
        };
        match ProofEnvelopeV1::sign_hybrid(&binding, signer_key_id, signer, keypair) {
            Ok(envelope) => (result, Some(envelope)),
            Err(e) => {
                error!("Failed to sign proof envelope v1 hybrid: {}", e);
                if self.strict_mode {
                    (
                        engine_error_result(
                            request,
                            result.rule_id.clone(),
                            result.rule_version.clone(),
                            &format!("ProofEnvelopeV1 hybrid signing error: {}", e),
                            result.evaluation_time_ms,
                        ),
                        None,
                    )
                } else {
                    (result, None)
                }
            }
        }
    }

    fn evaluate_internal(
        &self,
        request: &EvaluationRequest,
        proof_backend: Option<&str>,
    ) -> (EvaluationResult, Option<ProofBinding>) {
        let start = Instant::now();
        info!("Evaluating request: {}", request.request_id);
        let ctx = EvaluationContext::from_request(request);

        if let Some(result) = self.evaluate_compiled(request, &ctx, start, proof_backend) {
            return result;
        }

        (self.evaluate_legacy_rules(request, &ctx, start), None)
    }

    fn evaluate_compiled(
        &self,
        request: &EvaluationRequest,
        ctx: &EvaluationContext,
        start: Instant,
        proof_backend: Option<&str>,
    ) -> Option<(EvaluationResult, Option<ProofBinding>)> {
        for rule in &self.compiled_rules {
            match rule.evaluate_match_decision(ctx) {
                Ok(Some(vm_decision)) => {
                    let mut result = rule.apply_action();
                    if result.decision != vm_decision {
                        let msg = format!(
                            "Compiled VM decision mismatch for rule {}: vm={:?} action={:?}",
                            rule.id, vm_decision, result.decision
                        );
                        error!("{}", msg);
                        if self.strict_mode {
                            return Some((
                                engine_error_result(
                                    request,
                                    Some(rule.id.clone()),
                                    Some(rule.version.clone()),
                                    &msg,
                                    start.elapsed().as_millis() as u64,
                                ),
                                None,
                            ));
                        }
                    } else {
                        result.decision = vm_decision;
                    }
                    let evaluation_time = start.elapsed().as_millis() as u64;
                    info!(
                        "Request {}: {} by compiled rule {} ({}ms)",
                        request.request_id,
                        format!("{:?}", result.decision),
                        rule.id,
                        evaluation_time
                    );
                    let eval_result = build_eval_result(
                        request,
                        result.clone(),
                        Some(rule.id.clone()),
                        Some(rule.version.clone()),
                        evaluation_time,
                    );

                    let binding = if let Some(crypto_backend_id) = proof_backend {
                        match ProofBinding::create_with_policy_hash(
                            &rule.bytecode,
                            request,
                            ctx,
                            result.decision,
                            crypto_backend_id,
                            Some(&rule.policy_hash),
                        ) {
                            Ok(binding) => Some(binding),
                            Err(e) => {
                                error!(
                                    "Failed to build proof binding for compiled rule {}: {}",
                                    rule.id, e
                                );
                                if self.strict_mode {
                                    return Some((
                                        engine_error_result(
                                            request,
                                            Some(rule.id.clone()),
                                            Some(rule.version.clone()),
                                            &format!("Proof binding error: {}", e),
                                            evaluation_time,
                                        ),
                                        None,
                                    ));
                                }
                                None
                            }
                        }
                    } else {
                        None
                    };
                    return Some((eval_result, binding));
                }
                Ok(None) => {}
                Err(e) => {
                    if self.strict_mode {
                        error!("Error evaluating compiled rule {}: {}", rule.id, e);
                        return Some((
                            engine_error_result(
                                request,
                                Some(rule.id.clone()),
                                Some(rule.version.clone()),
                                &e.to_string(),
                                start.elapsed().as_millis() as u64,
                            ),
                            None,
                        ));
                    } else {
                        warn!(
                            "Non-strict mode: continuing after error in compiled rule {}",
                            rule.id
                        );
                    }
                }
            }
        }
        None
    }

    fn evaluate_legacy_rules(
        &self,
        request: &EvaluationRequest,
        ctx: &EvaluationContext,
        start: Instant,
    ) -> EvaluationResult {
        let rules = self.rule_registry.get_active_rules();

        for rule in rules {
            if !rule.is_valid_now() {
                continue;
            }

            match rule.evaluate(ctx) {
                Ok(true) => {
                    let result = rule.apply_action(ctx);
                    let evaluation_time = start.elapsed().as_millis() as u64;
                    info!(
                        "Request {}: {} by rule {} ({}ms)",
                        request.request_id,
                        format!("{:?}", result.decision),
                        rule.id,
                        evaluation_time
                    );
                    return build_eval_result(
                        request,
                        result,
                        Some(rule.id.clone()),
                        Some(rule.version.clone()),
                        evaluation_time,
                    );
                }
                Ok(false) => {}
                Err(e) => {
                    if self.strict_mode {
                        error!("Error evaluating rule {}: {}", rule.id, e);
                        return engine_error_result(
                            request,
                            Some(rule.id.clone()),
                            Some(rule.version.clone()),
                            &e.to_string(),
                            start.elapsed().as_millis() as u64,
                        );
                    } else {
                        warn!(
                            "Non-strict mode: continuing after error in rule {}",
                            rule.id
                        );
                    }
                }
            }
        }

        EvaluationResult {
            request_id: request.request_id.clone(),
            decision: Decision::Allow,
            evaluated_at: chrono::Utc::now().to_rfc3339(),
            evaluation_time_ms: start.elapsed().as_millis() as u64,
            ..Default::default()
        }
    }

    /// Set strict mode
    pub fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    /// Get total rule count (compiled + legacy runtime registry)
    pub fn rule_count(&self) -> usize {
        self.compiled_rules.len() + self.rule_registry.len()
    }

    /// Number of compiled rules loaded in VM path.
    pub fn compiled_rule_count(&self) -> usize {
        self.compiled_rules.len()
    }
}

impl Default for CrueEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn compiled_actions_to_result(actions: &[RuleEffect]) -> ActionResult {
    let has_soc_alert = actions.iter().any(RuleEffect::is_alert_only);
    let primary = actions
        .iter()
        .find(|a| !a.is_alert_only())
        .cloned()
        .unwrap_or(RuleEffect::Log);

    let mut result = match primary {
        RuleEffect::Block { code, message } => {
            ActionResult::block(&code, message.as_deref().unwrap_or("Access denied"))
        }
        RuleEffect::Warn { code } => ActionResult::warn(&code, "Policy warning"),
        RuleEffect::RequireApproval {
            code,
            timeout_minutes,
        } => ActionResult::approval_required(&code, timeout_minutes),
        RuleEffect::Log | RuleEffect::AlertSoc => ActionResult::allow(),
    };

    if has_soc_alert {
        result = result.with_soc_alert();
    }
    result
}

fn compile_action_program(actions: &[RuleEffect]) -> Vec<ActionInstruction> {
    let has_soc_alert = actions.iter().any(RuleEffect::is_alert_only);
    let primary = actions
        .iter()
        .find(|a| !a.is_alert_only())
        .cloned()
        .unwrap_or(RuleEffect::Log);

    let mut program = Vec::new();
    match primary {
        RuleEffect::Block { code, message } => {
            program.push(ActionInstruction::SetDecision(Decision::Block));
            program.push(ActionInstruction::SetErrorCode(code));
            program.push(ActionInstruction::SetMessage(
                message.unwrap_or_else(|| "Access denied".to_string()),
            ));
        }
        RuleEffect::Warn { code } => {
            program.push(ActionInstruction::SetDecision(Decision::Warn));
            program.push(ActionInstruction::SetErrorCode(code));
            program.push(ActionInstruction::SetMessage("Policy warning".to_string()));
        }
        RuleEffect::RequireApproval {
            code,
            timeout_minutes,
        } => {
            program.push(ActionInstruction::SetDecision(Decision::ApprovalRequired));
            program.push(ActionInstruction::SetErrorCode(code));
            program.push(ActionInstruction::SetApprovalTimeout(timeout_minutes));
        }
        RuleEffect::Log | RuleEffect::AlertSoc => {
            program.push(ActionInstruction::SetDecision(Decision::Allow));
        }
    }

    if has_soc_alert {
        program.push(ActionInstruction::SetAlertSoc(true));
    }
    program.push(ActionInstruction::Halt);
    program
}

fn hash_policy_ast(ast: &RuleAst) -> Result<String, EngineError> {
    let bytes = serde_json::to_vec(ast).map_err(|e| {
        EngineError::CompilationError(format!("Policy AST serialization error: {}", e))
    })?;
    Ok(crypto_core::hash::hex_encode(&crypto_core::hash::sha256(
        &bytes,
    )))
}

fn build_eval_result(
    request: &EvaluationRequest,
    result: ActionResult,
    rule_id: Option<String>,
    rule_version: Option<String>,
    evaluation_time_ms: u64,
) -> EvaluationResult {
    EvaluationResult {
        request_id: request.request_id.clone(),
        decision: result.decision,
        error_code: result.error_code,
        message: result.message,
        rule_id,
        rule_version,
        evaluated_at: chrono::Utc::now().to_rfc3339(),
        evaluation_time_ms,
    }
}

fn engine_error_result(
    request: &EvaluationRequest,
    rule_id: Option<String>,
    rule_version: Option<String>,
    msg: &str,
    evaluation_time_ms: u64,
) -> EvaluationResult {
    EvaluationResult {
        request_id: request.request_id.clone(),
        decision: Decision::Block,
        error_code: Some("ENGINE_ERROR".to_string()),
        message: Some(format!("Rule evaluation error: {}", msg)),
        rule_id,
        rule_version,
        evaluated_at: chrono::Utc::now().to_rfc3339(),
        evaluation_time_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_default() {
        let engine = CrueEngine::new();
        assert!(engine.rule_count() > 0);
    }

    #[test]
    fn test_evaluate_default_allow() {
        let mut engine = CrueEngine::new();
        engine.load_rules(RuleRegistry::empty());

        let request = EvaluationRequest {
            request_id: "test_001".to_string(),
            agent_id: "AGENT_001".to_string(),
            agent_org: "DGFiP".to_string(),
            agent_level: "standard".to_string(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: None,
            export_format: None,
            result_limit: None,
            requests_last_hour: 0,
            requests_last_24h: 0,
            results_last_query: 0,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 12,
            is_within_mission_hours: true,
        };

        let result = engine.evaluate(&request);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_compiled_rule_path() {
        let source = r#"
RULE CRUE_900 VERSION 1.0
WHEN
    agent.requests_last_hour >= 50
THEN
    BLOCK WITH CODE "VOLUME_EXCEEDED"
"#;
        let mut engine = CrueEngine::new();
        engine.load_rules(RuleRegistry::empty());
        engine.register_compiled_rule_source(source).unwrap();
        assert_eq!(engine.compiled_rule_count(), 1);

        let request = EvaluationRequest {
            request_id: "req".to_string(),
            agent_id: "A".to_string(),
            agent_org: "O".to_string(),
            agent_level: "L".to_string(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: Some("sufficient".to_string()),
            export_format: None,
            result_limit: None,
            requests_last_hour: 51,
            requests_last_24h: 100,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 8,
            is_within_mission_hours: true,
        };
        let result = engine.evaluate(&request);
        assert_eq!(result.decision, Decision::Block);
        assert_eq!(result.rule_id.as_deref(), Some("CRUE_900"));
        let compiled = &engine.compiled_rules[0];
        assert!(!compiled.action_program.is_empty());
        assert!(!compiled.bytecode.action_instructions.is_empty());
    }

    #[test]
    fn test_evaluate_with_proof_returns_binding_for_compiled_path() {
        let source = r#"
RULE CRUE_901 VERSION 1.0
WHEN
    agent.requests_last_hour >= 50
THEN
    BLOCK WITH CODE "VOLUME_EXCEEDED"
"#;
        let mut engine = CrueEngine::new();
        engine.load_rules(RuleRegistry::empty());
        engine.register_compiled_rule_source(source).unwrap();

        let request = EvaluationRequest {
            request_id: "req".to_string(),
            agent_id: "A".to_string(),
            agent_org: "O".to_string(),
            agent_level: "L".to_string(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: Some("sufficient".to_string()),
            export_format: None,
            result_limit: None,
            requests_last_hour: 60,
            requests_last_24h: 100,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 8,
            is_within_mission_hours: true,
        };
        let (result, binding) = engine.evaluate_with_proof(&request, "mock-crypto");
        assert_eq!(result.decision, Decision::Block);
        let binding = binding.expect("compiled path should produce binding");
        let ctx = EvaluationContext::from_request(&request);
        assert!(binding
            .verify_recompute(
                &engine.compiled_rules[0].bytecode,
                &request,
                &ctx,
                result.decision,
                "mock-crypto",
            )
            .unwrap());
    }

    #[test]
    fn test_compiled_path_falls_back_to_legacy_rules() {
        let source = r#"
RULE CRUE_900 VERSION 1.0
WHEN
    agent.requests_last_hour >= 500
THEN
    BLOCK WITH CODE "NEVER"
"#;
        let mut engine = CrueEngine::new();
        engine.register_compiled_rule_source(source).unwrap();

        let request = EvaluationRequest {
            request_id: "req".to_string(),
            agent_id: "A".to_string(),
            agent_org: "O".to_string(),
            agent_level: "L".to_string(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: Some("ok justification".to_string()),
            export_format: None,
            result_limit: None,
            requests_last_hour: 60, // triggers built-in CRUE_001
            requests_last_24h: 100,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 8,
            is_within_mission_hours: true,
        };
        let result = engine.evaluate(&request);
        assert_eq!(result.decision, Decision::Block);
        assert_eq!(result.rule_id.as_deref(), Some("CRUE_001"));

        let (result2, binding) = engine.evaluate_with_proof(&request, "mock-crypto");
        assert_eq!(result2.decision, Decision::Block);
        assert_eq!(result2.rule_id.as_deref(), Some("CRUE_001"));
        assert!(binding.is_none());
    }

    #[test]
    fn test_evaluate_with_signed_proof_ed25519_compiled_path() {
        let source = r#"
RULE CRUE_902 VERSION 1.0
WHEN
    agent.requests_last_hour >= 50
THEN
    BLOCK WITH CODE "VOLUME_EXCEEDED"
"#;
        let mut engine = CrueEngine::new();
        engine.load_rules(RuleRegistry::empty());
        engine.register_compiled_rule_source(source).unwrap();

        let request = EvaluationRequest {
            request_id: "req".to_string(),
            agent_id: "A".to_string(),
            agent_org: "O".to_string(),
            agent_level: "L".to_string(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: Some("sufficient".to_string()),
            export_format: None,
            result_limit: None,
            requests_last_hour: 70,
            requests_last_24h: 100,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 8,
            is_within_mission_hours: true,
        };
        let kp = crypto_core::signature::Ed25519KeyPair::generate().unwrap();
        let pk = kp.verifying_key();
        let (result, envelope) =
            engine.evaluate_with_signed_proof_ed25519(&request, "mock-crypto", "proof-key-1", &kp);
        assert_eq!(result.decision, Decision::Block);
        let envelope = envelope.expect("compiled path should produce signed envelope");
        assert_eq!(envelope.binding.crypto_backend_id, "mock-crypto");
        assert!(envelope.verify_ed25519(&pk).unwrap());
    }

    #[test]
    fn test_evaluate_with_signed_proof_v1_ed25519_compiled_path() {
        let source = r#"
RULE CRUE_902B VERSION 1.0
WHEN
    agent.requests_last_hour >= 50
THEN
    BLOCK WITH CODE "VOLUME_EXCEEDED"
"#;
        let mut engine = CrueEngine::new();
        engine.load_rules(RuleRegistry::empty());
        engine.register_compiled_rule_source(source).unwrap();

        let request = EvaluationRequest {
            request_id: "req".to_string(),
            agent_id: "A".to_string(),
            agent_org: "O".to_string(),
            agent_level: "L".to_string(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: Some("sufficient".to_string()),
            export_format: None,
            result_limit: None,
            requests_last_hour: 70,
            requests_last_24h: 100,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 8,
            is_within_mission_hours: true,
        };
        let kp = crypto_core::signature::Ed25519KeyPair::generate().unwrap();
        let pk = kp.verifying_key();
        let (result, envelope) = engine.evaluate_with_signed_proof_v1_ed25519(
            &request,
            "mock-crypto",
            "proof-key-v1",
            &kp,
        );
        assert_eq!(result.decision, Decision::Block);
        let envelope = envelope.expect("compiled path should produce v1 envelope");
        assert_eq!(envelope.decision().unwrap(), Decision::Block);
        assert!(envelope.verify_ed25519(&pk).unwrap());
        assert!(!envelope.canonical_bytes().unwrap().is_empty());
    }

    #[cfg(feature = "pq-proof")]
    #[test]
    fn test_evaluate_with_signed_proof_hybrid_compiled_path() {
        let source = r#"
RULE CRUE_903 VERSION 1.0
WHEN
    agent.requests_last_hour >= 50
THEN
    BLOCK WITH CODE "VOLUME_EXCEEDED"
"#;
        let mut engine = CrueEngine::new();
        engine.load_rules(RuleRegistry::empty());
        engine.register_compiled_rule_source(source).unwrap();

        let request = EvaluationRequest {
            request_id: "req".to_string(),
            agent_id: "A".to_string(),
            agent_org: "O".to_string(),
            agent_level: "L".to_string(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: Some("sufficient".to_string()),
            export_format: None,
            result_limit: None,
            requests_last_hour: 70,
            requests_last_24h: 100,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 8,
            is_within_mission_hours: true,
        };
        let signer = pqcrypto::hybrid::HybridSigner::new(pqcrypto::DilithiumLevel::Dilithium2);
        let keypair = signer.generate_keypair().unwrap();
        let public_key = keypair.public_key();
        let (result, envelope) =
            engine.evaluate_with_signed_proof_hybrid(&request, "pq-proof-key-1", &signer, &keypair);
        assert_eq!(result.decision, Decision::Block);
        let envelope = envelope.expect("compiled path should produce signed PQ envelope");
        assert_eq!(envelope.pq_backend_id, signer.backend_id());
        assert!(envelope.verify_hybrid(&public_key).unwrap());
    }

    #[cfg(feature = "pq-proof")]
    #[test]
    fn test_evaluate_with_signed_proof_v1_hybrid_compiled_path() {
        let source = r#"
RULE CRUE_903B VERSION 1.0
WHEN
    agent.requests_last_hour >= 50
THEN
    BLOCK WITH CODE "VOLUME_EXCEEDED"
"#;
        let mut engine = CrueEngine::new();
        engine.load_rules(RuleRegistry::empty());
        engine.register_compiled_rule_source(source).unwrap();

        let request = EvaluationRequest {
            request_id: "req".to_string(),
            agent_id: "A".to_string(),
            agent_org: "O".to_string(),
            agent_level: "L".to_string(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: Some("sufficient".to_string()),
            export_format: None,
            result_limit: None,
            requests_last_hour: 70,
            requests_last_24h: 100,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 8,
            is_within_mission_hours: true,
        };
        let signer = pqcrypto::hybrid::HybridSigner::new(pqcrypto::DilithiumLevel::Dilithium2);
        let keypair = signer.generate_keypair().unwrap();
        let public_key = keypair.public_key();
        let (result, envelope) = engine.evaluate_with_signed_proof_v1_hybrid(
            &request,
            "proof-key-v1-pq",
            &signer,
            &keypair,
        );
        assert_eq!(result.decision, Decision::Block);
        let envelope = envelope.expect("compiled path should produce v1 hybrid envelope");
        assert_eq!(envelope.decision().unwrap(), Decision::Block);
        assert!(envelope.verify_hybrid(&public_key).unwrap());
        assert!(!envelope.canonical_bytes().unwrap().is_empty());
    }

    #[test]
    fn test_compile_action_program_warn_soc() {
        let program = compile_action_program(&[
            RuleEffect::Warn {
                code: "WARN_1".to_string(),
            },
            RuleEffect::AlertSoc,
        ]);
        let result = ActionVm::execute(&program).unwrap();
        assert_eq!(result.decision, Decision::Warn);
        assert_eq!(result.error_code.as_deref(), Some("WARN_1"));
        assert!(result.alert_soc);
    }

    #[test]
    fn test_compiled_rule_prefers_dsl_emitted_action_program() {
        let source = r#"
RULE CRUE_904 VERSION 1.0
WHEN
    agent.requests_last_hour >= 1
THEN
    BLOCK WITH CODE "MANUAL_REVIEW"
"#;
        let rule = CompiledPolicyRule::from_source(source).unwrap();
        assert!(!rule.bytecode.action_instructions.is_empty());
        let result = ActionVm::execute(&rule.action_program).unwrap();
        assert_eq!(result.decision, Decision::Block);
        assert_eq!(result.error_code.as_deref(), Some("MANUAL_REVIEW"));
    }
}
