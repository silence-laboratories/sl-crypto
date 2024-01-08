use std::ops::Deref;

/// Domain separation lavbel
pub struct Label([u8; 8]);

const LABEL_BITS: usize = 48;

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Label {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Label {
    /// Create a new label.
    pub const fn new(ver: u16, label: u64) -> Self {
        assert!(label < (1 << LABEL_BITS));
        let label = ((ver as u64) << LABEL_BITS) | label;
        Self(label.to_be_bytes())
    }
}
