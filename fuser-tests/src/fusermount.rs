/// Override path to `fusermount` for running tests.
pub(crate) enum Fusermount {
    Fusermount,
    Fusermount3,
    /// `/bin/false`.
    False,
}

impl Fusermount {
    pub(crate) const ENV_VAR: &str = "FUSER_TESTS_FUSERMOUNT";

    pub(crate) fn as_path(&self) -> &'static str {
        match self {
            Fusermount::Fusermount => "fusermount",
            Fusermount::Fusermount3 => "fusermount3",
            Fusermount::False => "/bin/false",
        }
    }
}
