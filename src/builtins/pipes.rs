//! Contains a [`RuleSet`] for allowing pipes

use crate::{RuleSet, Sysno};

/// [`Pipes`] allows you to create anonymous pipes for inter-process communication via the `pipe`
/// syscalls.
pub struct Pipes;
impl RuleSet<[Sysno; 2]> for Pipes {
    fn simple_rules(&self) -> [Sysno; 2] {
        [Sysno::pipe, Sysno::pipe2]
    }

    fn name(&self) -> &'static str {
        "Pipes"
    }
}
