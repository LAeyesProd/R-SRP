//! Bytecode VM for compiled CRUE DSL rules (Phase 2 bootstrap).

use crate::context::{EvaluationContext, FieldValue};
use crate::decision::{ActionResult, Decision};
use crate::error::EngineError;
use crate::ir::ActionInstruction;
use crue_dsl::compiler::{Bytecode, Constant, Opcode};

#[derive(Debug, Clone, PartialEq)]
enum VmValue {
    Bool(bool),
    Number(i64),
    String(String),
}

/// Explicit VM instruction set used by the decoded execution path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    LoadField(u16),
    LoadConst(u32),
    LoadTrue,
    LoadFalse,
    Gt,
    Lt,
    Gte,
    Lte,
    Eq,
    Neq,
    And,
    Or,
    Not,
    JumpIfFalse(usize),
    Jump(usize),
    Ret,
    EmitDecision(Decision),
}

/// VM exit value, allowing either a boolean gate or an emitted decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmExit {
    Bool(bool),
    Decision(Decision),
}

pub struct BytecodeVm;
pub struct ActionVm;

impl BytecodeVm {
    /// Evaluate a compiled CRUE bytecode condition to a boolean decision gate.
    pub fn eval(bytecode: &Bytecode, ctx: &EvaluationContext) -> Result<bool, EngineError> {
        let program = Self::decode(bytecode)?;
        match Self::eval_program(&program, bytecode, ctx)? {
            VmExit::Bool(v) => Ok(v),
            VmExit::Decision(_) => Err(EngineError::EvaluationError(
                "VM emitted decision in boolean eval path".to_string(),
            )),
        }
    }

    /// Decode raw CRUE bytecode into an explicit instruction sequence.
    pub fn decode(bytecode: &Bytecode) -> Result<Vec<Instruction>, EngineError> {
        let mut pc = 0usize;
        let code = &bytecode.instructions;
        let mut program = Vec::new();

        while pc < code.len() {
            let op = decode_opcode(code[pc])?;
            pc += 1;
            match op {
                Opcode::LoadField => {
                    program.push(Instruction::LoadField(read_u16(code, &mut pc)?));
                }
                Opcode::LoadConst => {
                    program.push(Instruction::LoadConst(read_u32(code, &mut pc)?));
                }
                Opcode::LoadTrue => program.push(Instruction::LoadTrue),
                Opcode::LoadFalse => program.push(Instruction::LoadFalse),
                Opcode::Gt => program.push(Instruction::Gt),
                Opcode::Lt => program.push(Instruction::Lt),
                Opcode::Gte => program.push(Instruction::Gte),
                Opcode::Lte => program.push(Instruction::Lte),
                Opcode::Eq => program.push(Instruction::Eq),
                Opcode::Neq => program.push(Instruction::Neq),
                Opcode::And => program.push(Instruction::And),
                Opcode::Or => program.push(Instruction::Or),
                Opcode::Not => program.push(Instruction::Not),
                Opcode::Ret => program.push(Instruction::Ret),
                Opcode::Jmp | Opcode::JmpF => {
                    return Err(EngineError::EvaluationError(
                        "Raw jump opcodes not supported in decoded VM yet".to_string(),
                    ));
                }
            }
        }

        Ok(program)
    }

    /// Evaluate a decoded VM program against bytecode metadata/context.
    pub fn eval_program(
        program: &[Instruction],
        bytecode: &Bytecode,
        ctx: &EvaluationContext,
    ) -> Result<VmExit, EngineError> {
        let mut pc = 0usize;
        let mut stack: Vec<VmValue> = Vec::new();

        while pc < program.len() {
            match &program[pc] {
                Instruction::LoadField(idx) => {
                    let field = bytecode.fields.get(*idx as usize).ok_or_else(|| {
                        EngineError::EvaluationError("Invalid field index".to_string())
                    })?;
                    let value = ctx
                        .get_field(field)
                        .ok_or_else(|| EngineError::FieldNotFound(field.clone()))?;
                    stack.push(field_to_vm(value)?);
                    pc += 1;
                }
                Instruction::LoadConst(idx) => {
                    let c = bytecode.constants.get(*idx as usize).ok_or_else(|| {
                        EngineError::EvaluationError("Invalid constant index".to_string())
                    })?;
                    stack.push(constant_to_vm(c));
                    pc += 1;
                }
                Instruction::LoadTrue => {
                    stack.push(VmValue::Bool(true));
                    pc += 1;
                }
                Instruction::LoadFalse => {
                    stack.push(VmValue::Bool(false));
                    pc += 1;
                }
                Instruction::Gt => {
                    binary_compare(&mut stack, |a, b| a > b)?;
                    pc += 1;
                }
                Instruction::Lt => {
                    binary_compare(&mut stack, |a, b| a < b)?;
                    pc += 1;
                }
                Instruction::Gte => {
                    binary_compare(&mut stack, |a, b| a >= b)?;
                    pc += 1;
                }
                Instruction::Lte => {
                    binary_compare(&mut stack, |a, b| a <= b)?;
                    pc += 1;
                }
                Instruction::Eq => {
                    binary_eq(&mut stack, true)?;
                    pc += 1;
                }
                Instruction::Neq => {
                    binary_eq(&mut stack, false)?;
                    pc += 1;
                }
                Instruction::And => {
                    binary_bool(&mut stack, |a, b| a && b)?;
                    pc += 1;
                }
                Instruction::Or => {
                    binary_bool(&mut stack, |a, b| a || b)?;
                    pc += 1;
                }
                Instruction::Not => {
                    let v = pop_bool(&mut stack)?;
                    stack.push(VmValue::Bool(!v));
                    pc += 1;
                }
                Instruction::JumpIfFalse(target) => {
                    let cond = pop_bool(&mut stack)?;
                    if !cond {
                        ensure_target(*target, program.len())?;
                        pc = *target;
                    } else {
                        pc += 1;
                    }
                }
                Instruction::Jump(target) => {
                    ensure_target(*target, program.len())?;
                    pc = *target;
                }
                Instruction::Ret => {
                    return Ok(VmExit::Bool(pop_bool(&mut stack)?));
                }
                Instruction::EmitDecision(decision) => {
                    return Ok(VmExit::Decision(*decision));
                }
            }
        }

        Err(EngineError::EvaluationError(
            "VM program terminated without RET/EmitDecision".to_string(),
        ))
    }

    /// Evaluate a compiled rule condition and emit a typed decision via VM instructions.
    pub fn eval_decision(
        bytecode: &Bytecode,
        ctx: &EvaluationContext,
        on_true: Decision,
        on_false: Decision,
    ) -> Result<Decision, EngineError> {
        let mut program = Self::decode(bytecode)?;
        if !matches!(program.last(), Some(Instruction::Ret)) {
            return Err(EngineError::EvaluationError(
                "Bytecode terminated without RET".to_string(),
            ));
        }
        program.pop();

        let false_target = program.len() + 2;
        program.push(Instruction::JumpIfFalse(false_target));
        program.push(Instruction::EmitDecision(on_true));
        program.push(Instruction::EmitDecision(on_false));

        match Self::eval_program(&program, bytecode, ctx)? {
            VmExit::Decision(d) => Ok(d),
            VmExit::Bool(_) => Err(EngineError::EvaluationError(
                "VM returned bool in decision eval path".to_string(),
            )),
        }
    }

    /// Build a decoded VM program that emits `on_match` when the bytecode condition matches,
    /// and returns `false` (boolean) when it does not match.
    pub fn build_match_program(
        bytecode: &Bytecode,
        on_match: Decision,
    ) -> Result<Vec<Instruction>, EngineError> {
        let mut program = Self::decode(bytecode)?;
        if !matches!(program.last(), Some(Instruction::Ret)) {
            return Err(EngineError::EvaluationError(
                "Bytecode terminated without RET".to_string(),
            ));
        }
        program.pop();

        // Stack holds the condition boolean at this point.
        // false -> push false + RET (signals "no match")
        // true  -> EmitDecision(on_match)
        let false_target = program.len() + 2;
        program.push(Instruction::JumpIfFalse(false_target));
        program.push(Instruction::EmitDecision(on_match));
        program.push(Instruction::LoadFalse);
        program.push(Instruction::Ret);
        Ok(program)
    }

    /// Evaluate a prebuilt match program and return:
    /// - `Some(decision)` when rule matched and emitted a decision
    /// - `None` when rule condition evaluated to false
    pub fn eval_match_program(
        program: &[Instruction],
        bytecode: &Bytecode,
        ctx: &EvaluationContext,
    ) -> Result<Option<Decision>, EngineError> {
        match Self::eval_program(program, bytecode, ctx)? {
            VmExit::Decision(d) => Ok(Some(d)),
            VmExit::Bool(false) => Ok(None),
            VmExit::Bool(true) => Err(EngineError::EvaluationError(
                "VM match program returned unexpected true boolean".to_string(),
            )),
        }
    }
}

impl ActionVm {
    /// Execute a compiled action program into a deterministic `ActionResult`.
    pub fn execute(program: &[ActionInstruction]) -> Result<ActionResult, EngineError> {
        let mut decision = Decision::Allow;
        let mut error_code: Option<String> = None;
        let mut message: Option<String> = None;
        let mut approval_timeout: Option<u32> = None;
        let mut alert_soc = false;

        for insn in program {
            match insn {
                ActionInstruction::SetDecision(d) => decision = *d,
                ActionInstruction::SetErrorCode(code) => error_code = Some(code.clone()),
                ActionInstruction::SetMessage(msg) => message = Some(msg.clone()),
                ActionInstruction::SetApprovalTimeout(timeout) => approval_timeout = Some(*timeout),
                ActionInstruction::SetAlertSoc(v) => alert_soc = *v,
                ActionInstruction::Halt => break,
            }
        }

        let final_message = match decision {
            Decision::ApprovalRequired => {
                if let Some(m) = message {
                    Some(m)
                } else {
                    Some(format!(
                        "Approval required within {} minutes",
                        approval_timeout.unwrap_or(30)
                    ))
                }
            }
            _ => message,
        };

        Ok(ActionResult {
            decision,
            error_code,
            message: final_message,
            alert_soc,
        })
    }
}

fn ensure_target(target: usize, len: usize) -> Result<(), EngineError> {
    if target >= len {
        return Err(EngineError::EvaluationError(format!(
            "Invalid jump target {} (program len {})",
            target, len
        )));
    }
    Ok(())
}

fn decode_opcode(byte: u8) -> Result<Opcode, EngineError> {
    let op = match byte {
        0x01 => Opcode::LoadField,
        0x02 => Opcode::LoadConst,
        0x03 => Opcode::LoadTrue,
        0x04 => Opcode::LoadFalse,
        0x10 => Opcode::Gt,
        0x11 => Opcode::Lt,
        0x12 => Opcode::Gte,
        0x13 => Opcode::Lte,
        0x14 => Opcode::Eq,
        0x15 => Opcode::Neq,
        0x20 => Opcode::And,
        0x21 => Opcode::Or,
        0x22 => Opcode::Not,
        0x30 => Opcode::JmpF,
        0x31 => Opcode::Jmp,
        0xFF => Opcode::Ret,
        _ => {
            return Err(EngineError::EvaluationError(format!(
                "Unknown opcode 0x{byte:02x}"
            )))
        }
    };
    Ok(op)
}

fn read_u16(code: &[u8], pc: &mut usize) -> Result<u16, EngineError> {
    if *pc + 2 > code.len() {
        return Err(EngineError::EvaluationError(
            "Truncated u16 operand".to_string(),
        ));
    }
    let v = u16::from_be_bytes([code[*pc], code[*pc + 1]]);
    *pc += 2;
    Ok(v)
}

fn read_u32(code: &[u8], pc: &mut usize) -> Result<u32, EngineError> {
    if *pc + 4 > code.len() {
        return Err(EngineError::EvaluationError(
            "Truncated u32 operand".to_string(),
        ));
    }
    let v = u32::from_be_bytes([code[*pc], code[*pc + 1], code[*pc + 2], code[*pc + 3]]);
    *pc += 4;
    Ok(v)
}

fn constant_to_vm(c: &Constant) -> VmValue {
    match c {
        Constant::Number(n) => VmValue::Number(*n),
        Constant::String(s) => VmValue::String(s.clone()),
        Constant::Boolean(b) => VmValue::Bool(*b),
    }
}

fn field_to_vm(v: &FieldValue) -> Result<VmValue, EngineError> {
    match v {
        FieldValue::Number(n) => Ok(VmValue::Number(*n)),
        FieldValue::String(s) => Ok(VmValue::String(s.clone())),
        FieldValue::Boolean(b) => Ok(VmValue::Bool(*b)),
        FieldValue::Float(_) => Err(EngineError::TypeMismatch(
            "float field unsupported in VM".into(),
        )),
    }
}

fn pop(stack: &mut Vec<VmValue>) -> Result<VmValue, EngineError> {
    stack
        .pop()
        .ok_or_else(|| EngineError::EvaluationError("VM stack underflow".to_string()))
}

fn pop_bool(stack: &mut Vec<VmValue>) -> Result<bool, EngineError> {
    match pop(stack)? {
        VmValue::Bool(v) => Ok(v),
        _ => Err(EngineError::TypeMismatch("Expected bool".to_string())),
    }
}

fn pop_number(stack: &mut Vec<VmValue>) -> Result<i64, EngineError> {
    match pop(stack)? {
        VmValue::Number(v) => Ok(v),
        _ => Err(EngineError::TypeMismatch("Expected number".to_string())),
    }
}

fn binary_compare(
    stack: &mut Vec<VmValue>,
    cmp: impl Fn(i64, i64) -> bool,
) -> Result<(), EngineError> {
    let right = pop_number(stack)?;
    let left = pop_number(stack)?;
    stack.push(VmValue::Bool(cmp(left, right)));
    Ok(())
}

fn binary_bool(
    stack: &mut Vec<VmValue>,
    op: impl Fn(bool, bool) -> bool,
) -> Result<(), EngineError> {
    let right = pop_bool(stack)?;
    let left = pop_bool(stack)?;
    stack.push(VmValue::Bool(op(left, right)));
    Ok(())
}

fn binary_eq(stack: &mut Vec<VmValue>, eq: bool) -> Result<(), EngineError> {
    let right = pop(stack)?;
    let left = pop(stack)?;
    let result = match (left, right) {
        (VmValue::Bool(a), VmValue::Bool(b)) => a == b,
        (VmValue::Number(a), VmValue::Number(b)) => a == b,
        (VmValue::String(a), VmValue::String(b)) => a == b,
        _ => {
            return Err(EngineError::TypeMismatch(
                "Incompatible equality operands".to_string(),
            ))
        }
    };
    stack.push(VmValue::Bool(if eq { result } else { !result }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ActionInstruction;
    use crate::EvaluationRequest;
    use crue_dsl::ast::{ActionNode, Expression, MetadataNode, RuleAst, Value};

    #[test]
    fn test_vm_eval_compiled_rule() {
        let src = r#"
RULE CRUE_001 VERSION 1.0
WHEN
    agent.requests_last_hour >= 50
THEN
    BLOCK WITH CODE "VOLUME_EXCEEDED"
"#;
        let ast = crue_dsl::parser::parse(src).unwrap();
        let bytecode = crue_dsl::compiler::Compiler::compile(&ast).unwrap();

        let req = EvaluationRequest {
            request_id: "req".into(),
            agent_id: "a".into(),
            agent_org: "o".into(),
            agent_level: "standard".into(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: Some("demo justification".into()),
            export_format: None,
            result_limit: Some(1),
            requests_last_hour: 60,
            requests_last_24h: 100,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 10,
            is_within_mission_hours: true,
        };
        let ctx = EvaluationContext::from_request(&req);
        assert!(BytecodeVm::eval(&bytecode, &ctx).unwrap());
    }

    #[test]
    fn test_vm_eval_decision_emits_decision() {
        let src = r#"
RULE CRUE_001 VERSION 1.0
WHEN
    agent.requests_last_hour >= 50
THEN
    BLOCK WITH CODE "VOLUME_EXCEEDED"
"#;
        let ast = crue_dsl::parser::parse(src).unwrap();
        let bytecode = crue_dsl::compiler::Compiler::compile(&ast).unwrap();
        let mut req = EvaluationRequest {
            request_id: "req".into(),
            agent_id: "a".into(),
            agent_org: "o".into(),
            agent_level: "standard".into(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: Some("demo justification".into()),
            export_format: None,
            result_limit: Some(1),
            requests_last_hour: 60,
            requests_last_24h: 100,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 10,
            is_within_mission_hours: true,
        };
        let ctx = EvaluationContext::from_request(&req);
        assert_eq!(
            BytecodeVm::eval_decision(&bytecode, &ctx, Decision::Block, Decision::Allow).unwrap(),
            Decision::Block
        );

        req.requests_last_hour = 1;
        let ctx2 = EvaluationContext::from_request(&req);
        assert_eq!(
            BytecodeVm::eval_decision(&bytecode, &ctx2, Decision::Block, Decision::Allow).unwrap(),
            Decision::Allow
        );
    }

    #[test]
    fn test_vm_explicit_jump_and_emit_program() {
        let bytecode = Bytecode {
            instructions: vec![],
            constants: vec![],
            fields: vec![],
            action_instructions: vec![],
        };
        let req = EvaluationRequest {
            request_id: "req".into(),
            agent_id: "a".into(),
            agent_org: "o".into(),
            agent_level: "standard".into(),
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
            request_hour: 0,
            is_within_mission_hours: true,
        };
        let ctx = EvaluationContext::from_request(&req);
        let program = vec![
            Instruction::LoadFalse,
            Instruction::JumpIfFalse(3),
            Instruction::EmitDecision(Decision::Block),
            Instruction::EmitDecision(Decision::Allow),
        ];
        assert_eq!(
            BytecodeVm::eval_program(&program, &bytecode, &ctx).unwrap(),
            VmExit::Decision(Decision::Allow)
        );
    }

    #[test]
    fn test_action_vm_exec_block_with_soc_alert() {
        let program = vec![
            ActionInstruction::SetDecision(Decision::Block),
            ActionInstruction::SetErrorCode("VOLUME_EXCEEDED".into()),
            ActionInstruction::SetMessage("Demo policy matched".into()),
            ActionInstruction::SetAlertSoc(true),
            ActionInstruction::Halt,
        ];
        let result = ActionVm::execute(&program).unwrap();
        assert_eq!(result.decision, Decision::Block);
        assert_eq!(result.error_code.as_deref(), Some("VOLUME_EXCEEDED"));
        assert_eq!(result.message.as_deref(), Some("Demo policy matched"));
        assert!(result.alert_soc);
    }

    #[test]
    fn test_action_vm_exec_approval_default_message() {
        let program = vec![
            ActionInstruction::SetDecision(Decision::ApprovalRequired),
            ActionInstruction::SetErrorCode("APPROVAL_REQUIRED".into()),
            ActionInstruction::SetApprovalTimeout(15),
            ActionInstruction::Halt,
        ];
        let result = ActionVm::execute(&program).unwrap();
        assert_eq!(result.decision, Decision::ApprovalRequired);
        assert_eq!(
            result.message.as_deref(),
            Some("Approval required within 15 minutes")
        );
    }

    #[test]
    fn test_vm_eval_in_operator() {
        let ast = RuleAst {
            id: "CRUE_IN_VM".to_string(),
            version: "1.0.0".to_string(),
            signed: false,
            when_clause: Expression::In(
                Box::new(Expression::field("request.export_format")),
                vec![
                    Value::String("PDF".to_string()),
                    Value::String("CSV".to_string()),
                ],
            ),
            then_clause: vec![ActionNode::Log],
            metadata: MetadataNode {
                name: "IN".to_string(),
                description: "IN".to_string(),
                severity: "LOW".to_string(),
                category: "TEST".to_string(),
                author: "system".to_string(),
                created_at: "2026-01-01".to_string(),
                validated_by: None,
            },
        };
        let bytecode = crue_dsl::compiler::Compiler::compile(&ast).unwrap();

        let mut req = EvaluationRequest {
            request_id: "req".into(),
            agent_id: "a".into(),
            agent_org: "o".into(),
            agent_level: "standard".into(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: None,
            export_format: Some("PDF".into()),
            result_limit: None,
            requests_last_hour: 0,
            requests_last_24h: 0,
            results_last_query: 0,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 12,
            is_within_mission_hours: true,
        };
        let ctx = EvaluationContext::from_request(&req);
        assert!(BytecodeVm::eval(&bytecode, &ctx).unwrap());

        req.export_format = Some("XML".into());
        let ctx = EvaluationContext::from_request(&req);
        assert!(!BytecodeVm::eval(&bytecode, &ctx).unwrap());
    }

    #[test]
    fn test_vm_eval_between_operator() {
        let ast = RuleAst {
            id: "CRUE_BETWEEN_VM".to_string(),
            version: "1.0.0".to_string(),
            signed: false,
            when_clause: Expression::Between(
                Box::new(Expression::field("context.request_hour")),
                Box::new(Expression::number(8)),
                Box::new(Expression::number(18)),
            ),
            then_clause: vec![ActionNode::Log],
            metadata: MetadataNode {
                name: "BETWEEN".to_string(),
                description: "BETWEEN".to_string(),
                severity: "LOW".to_string(),
                category: "TEST".to_string(),
                author: "system".to_string(),
                created_at: "2026-01-01".to_string(),
                validated_by: None,
            },
        };
        let bytecode = crue_dsl::compiler::Compiler::compile(&ast).unwrap();

        let mut req = EvaluationRequest {
            request_id: "req".into(),
            agent_id: "a".into(),
            agent_org: "o".into(),
            agent_level: "standard".into(),
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
            request_hour: 9,
            is_within_mission_hours: true,
        };
        let ctx = EvaluationContext::from_request(&req);
        assert!(BytecodeVm::eval(&bytecode, &ctx).unwrap());

        req.request_hour = 22;
        let ctx = EvaluationContext::from_request(&req);
        assert!(!BytecodeVm::eval(&bytecode, &ctx).unwrap());
    }
}
