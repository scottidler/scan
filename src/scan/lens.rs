//! One per-target lens's outcome: a value, nothing there, or why it could not be read. A lens
//! failure is shown on its own row and never fails the scan it rides on.

/// What one lens found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LensOutcome<T> {
    /// The lens read a value.
    Present(T),
    /// The lens asked and the answer was "nothing here" (no record, no header, a 404).
    Absent,
    /// The lens could not get an answer: a timeout, a resolver or connect error.
    Failed(String),
}

impl<T> LensOutcome<T> {
    /// The value, when there is one.
    pub fn present(&self) -> Option<&T> {
        match self {
            LensOutcome::Present(value) => Some(value),
            _ => None,
        }
    }

    /// `Present(f(value))`, the other outcomes unchanged.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> LensOutcome<U> {
        match self {
            LensOutcome::Present(value) => LensOutcome::Present(f(value)),
            LensOutcome::Absent => LensOutcome::Absent,
            LensOutcome::Failed(reason) => LensOutcome::Failed(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn present_returns_only_a_value() {
        assert_eq!(LensOutcome::Present(3).present(), Some(&3));
        assert_eq!(LensOutcome::<u8>::Absent.present(), None);
        assert_eq!(LensOutcome::<u8>::Failed("timed out".into()).present(), None);
    }

    #[test]
    fn map_touches_only_a_value() {
        assert_eq!(LensOutcome::Present(2).map(|n| n * 2), LensOutcome::Present(4));
        assert_eq!(LensOutcome::<u8>::Absent.map(|n| n * 2), LensOutcome::Absent);
        assert_eq!(
            LensOutcome::<u8>::Failed("x".into()).map(|n| n * 2),
            LensOutcome::Failed("x".into())
        );
    }
}
