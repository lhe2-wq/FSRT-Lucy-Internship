//! Forge Remote path enumeration (EAS-4574).
//!
//! Walks the IR looking for [`Intrinsic::InvokeRemote`] calls — i.e.
//! `invokeRemote(remoteKey, options)` from `@forge/api` — and extracts the
//! remote *key* and the request *path* so the Forge Remote scanner can narrow
//! the set of endpoints to fuzz.
//!
//! # Scope (Tier A)
//!
//! This module currently resolves paths only when they are **statically
//! recoverable within a single function body**:
//!
//! * a string literal assigned to the options object's `path` property
//!   (`opts["path"] = "/x"`), including one level of trivial copy
//!   (`a = b; b["path"] = "/x"`).
//!
//! Anything that requires following a value *across function boundaries* (e.g.
//! `options` arriving as a parameter) is reported as [`RemotePath::path`] =
//! `None` (rendered as `<dynamic>`). Interprocedural resolution and header
//! extraction are deliberately out of scope here and tracked as follow-ups.

use crate::ir::{Base, Body, Inst, Intrinsic, Literal, Operand, Projection, Rvalue, VarId};

/// Maximum number of `a = b` copy hops to follow when resolving the options
/// object within a single body. Keeps the walk terminating and cheap.
const MAX_COPY_DEPTH: u8 = 8;

/// A single `invokeRemote` call site discovered in the IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePath {
    /// The remote key (first argument), if it was a string literal. Maps to a
    /// `remotes:` entry in `manifest.yml`.
    pub remote_key: Option<String>,
    /// The request path (`options.path`), if statically resolved within the
    /// body. `None` means it could not be resolved (e.g. it flows in from a
    /// parameter) and should be surfaced as `<dynamic>`.
    pub path: Option<String>,
}

impl RemotePath {
    /// Whether the request path was statically resolved.
    pub fn is_resolved(&self) -> bool {
        self.path.is_some()
    }
}

/// Scans a single function [`Body`] and returns one [`RemotePath`] per
/// `invokeRemote` call site found within it.
pub fn collect_remote_paths(body: &Body) -> Vec<RemotePath> {
    let mut out = Vec::new();
    for (_, block) in body.iter_blocks_enumerated() {
        for inst in &block.insts {
            // An intrinsic can appear either as a plain expression statement
            // (`invokeRemote(...)`) or bound to a variable
            // (`const r = invokeRemote(...)`). Both carry the same rvalue.
            let rvalue = inst.rvalue();
            let Rvalue::Intrinsic(Intrinsic::InvokeRemote, operands) = rvalue else {
                continue;
            };

            out.push(RemotePath {
                remote_key: operands.first().and_then(operand_as_str),
                path: operands.get(1).and_then(|opts| resolve_path(body, opts)),
            });
        }
    }
    out
}

/// Returns the string value of an operand when it is a string literal.
fn operand_as_str(op: &Operand) -> Option<String> {
    match op {
        Operand::Lit(Literal::Str(s)) => Some(s.to_string()),
        _ => None,
    }
}

/// Resolves the `path` property of the `options` operand passed to
/// `invokeRemote`. Handles the object literal being decomposed by the IR into
/// `opts["path"] = <literal>` assignments, following trivial `a = b` copies.
fn resolve_path(body: &Body, options: &Operand) -> Option<String> {
    // The options object is (almost) always a variable; a bare literal here
    // would be unusual, but a literal string cannot carry a `path` property.
    let var = match options {
        Operand::Var(v) => v.as_var_id()?,
        Operand::Lit(_) => return None,
    };
    resolve_path_for_var(body, var, MAX_COPY_DEPTH)
}

/// Looks for `var["path"] = <string literal>` assigned to `var` within `body`.
/// If instead `var` is a plain copy of another variable (`var = other`), it
/// follows that copy up to `depth` levels.
fn resolve_path_for_var(body: &Body, var: VarId, depth: u8) -> Option<String> {
    if depth == 0 {
        return None;
    }
    for (_, block) in body.iter_blocks_enumerated() {
        for inst in &block.insts {
            let Inst::Assign(assigned, rvalue) = inst else {
                continue;
            };
            if assigned.base != Base::Var(var) {
                continue;
            }

            // Case 1: direct property assignment `var["path"] = "..."`.
            if is_path_projection(&assigned.projections)
                && let Rvalue::Read(Operand::Lit(Literal::Str(s))) = rvalue
            {
                return Some(s.to_string());
            }

            // Case 2: trivial copy `var = other` (no projections) — follow it.
            if assigned.projections.is_empty()
                && let Rvalue::Read(Operand::Var(src)) = rvalue
                && src.projections.is_empty()
                && let Base::Var(src_var) = src.base
            {
                if let Some(found) = resolve_path_for_var(body, src_var, depth - 1) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// True if the projection list is exactly a single known `path` key
/// (case-insensitive), i.e. it represents the `.path` of the options object.
fn is_path_projection(projections: &[Projection]) -> bool {
    matches!(
        projections,
        [Projection::Known(name)] if name.eq_ignore_ascii_case("path")
    )
}
