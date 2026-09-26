use core::fmt::Display;

use proc_macro2::Span;
use syn::{
    spanned::Spanned,
    visit::{self, Visit},
    BinOp, Error, Expr, ExprBinary, ExprBreak, ExprConst, ExprContinue, ExprIf, ExprIndex,
    ExprLoop, ExprMatch, ExprRepeat, ExprReturn, ExprWhile, ItemConst, ItemFn, ItemImpl, Local,
    Macro, Path, TypeArray,
};

const COLLECTIONS: &[&str] = &["Vec", "VecDeque", "HashMap", "BTreeMap", "String"];

pub(crate) const IF: &str = "a circuit does not branch on values: write `if const { .. }` for a compile-time condition, or `select` for a value";
pub(crate) const IF_LET: &str = "`if let` branches on a value; a circuit has one shape";
pub(crate) const MATCH: &str =
    "a circuit does not branch on values: write `match const { .. }` for a compile-time value";
pub(crate) const GUARD: &str = "a match guard branches on a value";
pub(crate) const WHILE: &str =
    "a circuit has a fixed shape: iterate a fixed-size array instead of `while`";
pub(crate) const LOOP: &str =
    "a circuit has a fixed shape: iterate a fixed-size array instead of `loop`";
pub(crate) const BREAK: &str = "a circuit has a fixed shape: no `break`";
pub(crate) const CONTINUE: &str = "a circuit has a fixed shape: no `continue`";
pub(crate) const RETURN: &str =
    "a circuit has one exit: end with the value and leave on errors with `?`";
pub(crate) const LET_ELSE: &str = "`let ... else` branches on a value";
pub(crate) const SHORT_CIRCUIT: &str = "`&&` and `||` short-circuit, which is a branch";
pub(crate) const INDEX: &str = "no indexing in a circuit: destructure the array or iterate over it";
pub(crate) const MACRO: &str = "the circuit lint cannot see inside a macro, so circuits use none";

pub(crate) fn collection(name: &str) -> String {
    format!("`{name}` has no fixed length: use an array `[T; N]`")
}

pub(crate) fn check_impl(item: &ItemImpl) -> Vec<Error> {
    let mut lint = Lint::default();
    lint.visit_item_impl(item);
    lint.violations
}

pub(crate) fn check_fn(item: &ItemFn) -> Vec<Error> {
    let mut lint = Lint::default();
    lint.visit_item_fn(item);
    lint.violations
}

#[derive(Default)]
struct Lint {
    violations: Vec<Error>,
}

impl Lint {
    fn reject(&mut self, span: Span, message: impl Display) {
        self.violations.push(Error::new(span, message));
    }
}

fn is_const_block(expr: &Expr) -> bool {
    matches!(expr, Expr::Const(_))
}

impl<'ast> Visit<'ast> for Lint {
    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        match &*node.cond {
            Expr::Const(_) => {}
            Expr::Let(_) => self.reject(node.if_token.span, IF_LET),
            _ => self.reject(node.if_token.span, IF),
        }
        if !is_const_block(&node.cond) {
            self.visit_expr(&node.cond);
        }
        self.visit_block(&node.then_branch);
        if let Some((_, else_branch)) = &node.else_branch {
            self.visit_expr(else_branch);
        }
    }

    fn visit_expr_match(&mut self, node: &'ast ExprMatch) {
        if !is_const_block(&node.expr) {
            self.reject(node.match_token.span, MATCH);
            self.visit_expr(&node.expr);
        }
        for arm in &node.arms {
            if let Some((if_token, guard)) = &arm.guard {
                self.reject(if_token.span, GUARD);
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
        }
    }

    fn visit_expr_while(&mut self, node: &'ast ExprWhile) {
        self.reject(node.while_token.span, WHILE);
        visit::visit_expr_while(self, node);
    }

    fn visit_expr_loop(&mut self, node: &'ast ExprLoop) {
        self.reject(node.loop_token.span, LOOP);
        visit::visit_expr_loop(self, node);
    }

    fn visit_expr_break(&mut self, node: &'ast ExprBreak) {
        self.reject(node.break_token.span, BREAK);
        visit::visit_expr_break(self, node);
    }

    fn visit_expr_continue(&mut self, node: &'ast ExprContinue) {
        self.reject(node.continue_token.span, CONTINUE);
        visit::visit_expr_continue(self, node);
    }

    fn visit_expr_return(&mut self, node: &'ast ExprReturn) {
        self.reject(node.return_token.span, RETURN);
        visit::visit_expr_return(self, node);
    }

    fn visit_local(&mut self, node: &'ast Local) {
        if let Some((else_token, _)) = node.init.as_ref().and_then(|init| init.diverge.as_ref()) {
            self.reject(else_token.span, LET_ELSE);
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if matches!(node.op, BinOp::And(_) | BinOp::Or(_)) {
            self.reject(node.op.span(), SHORT_CIRCUIT);
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast ExprIndex) {
        self.reject(node.bracket_token.span.join(), INDEX);
        visit::visit_expr_index(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        self.reject(node.path.span(), MACRO);
    }

    fn visit_path(&mut self, node: &'ast Path) {
        if let Some(segment) = node
            .segments
            .iter()
            .find(|segment| COLLECTIONS.iter().any(|name| segment.ident == name))
        {
            self.reject(segment.ident.span(), collection(&segment.ident.to_string()));
        }
        visit::visit_path(self, node);
    }

    fn visit_expr_const(&mut self, _node: &'ast ExprConst) {}

    fn visit_item_const(&mut self, _node: &'ast ItemConst) {}

    fn visit_type_array(&mut self, node: &'ast TypeArray) {
        self.visit_type(&node.elem);
    }

    fn visit_expr_repeat(&mut self, node: &'ast ExprRepeat) {
        self.visit_expr(&node.expr);
    }
}
