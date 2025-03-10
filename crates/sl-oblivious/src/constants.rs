// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::label::Label;

/// Domain labels version
pub const VERSION: u16 = 1;

/// LABEL for Discrete Log Proof challenge
pub const DLOG_CHALLENGE_LABEL: Label = Label::new(VERSION, 1);

/// LABEL for EndemicOT
pub const ENDEMIC_OT_LABEL: Label = Label::new(VERSION, 2);

/// LABEL for All-but-One OT
pub const ALL_BUT_ONE_LABEL: Label = Label::new(VERSION, 3);

/// LABEL for All-but-One PPRF
pub const ALL_BUT_ONE_PPRF_LABEL: Label = Label::new(VERSION, 4);

/// LABEL for All-but-One PPRF Hash
pub const ALL_BUT_ONE_PPRF_HASH_LABEL: Label = Label::new(VERSION, 5);

/// LABEL for All-but-One PPRF Proof
pub const ALL_BUT_ONE_PPRF_PROOF_LABEL: Label = Label::new(VERSION, 6);

/// LABEL for SoftSpokenOT
pub const SOFT_SPOKEN_LABEL: Label = Label::new(VERSION, 7);

/// LABEL for SoftSpokenOT expand seeds
pub const SOFT_SPOKEN_EXPAND_LABEL: Label = Label::new(VERSION, 8);

/// LABEL for SoftSpokenOT matrix hash
pub const SOFT_SPOKEN_MATRIX_HASH_LABEL: Label = Label::new(VERSION, 9);

/// LABEL for SoftSpokenOT randomize
pub const SOFT_SPOKEN_RANDOMIZE_LABEL: Label = Label::new(VERSION, 10);

/// LABEL for RandomVOLE gadget vector
pub const RANDOM_VOLE_GADGET_VECTOR_LABEL: Label = Label::new(VERSION, 11);

/// LABEL for RandomVOLE theta
pub const RANDOM_VOLE_THETA_LABEL: Label = Label::new(VERSION, 12);

/// LABEL for RandomVOLE mu
pub const RANDOM_VOLE_MU_LABEL: Label = Label::new(VERSION, 13);

/// LABEL for baseOT in RandomVOLE OT variant
pub const RANDOM_VOLE_BASE_OT: Label = Label::new(VERSION, 14);
