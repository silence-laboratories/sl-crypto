// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(clippy::field_reassign_with_default)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use k256::Scalar;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

use sl_oblivious::{
    endemic_ot::{
        generate_seed_ot_for_test, EndemicOTMsg1, EndemicOTMsg2,
        EndemicOTReceiver, EndemicOTSender,
    },
    params::consts::L_BYTES,
    soft_spoken::{
        build_pprf, eval_pprf, generate_all_but_one_seed_ot, PPRFOutput,
        ReceiverExtendedOutput, ReceiverOTSeed, Round1Output, SenderOTSeed,
        SoftSpokenOTReceiver, SoftSpokenOTSender,
    },
};

fn all_but_one_bench(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
    let session_id: [u8; 32] = rng.gen();

    let (sender_ot_seed, receiver_ot_seed) = generate_seed_ot_for_test();

    c.bench_function("build_pprf", |b| {
        let mut _all_but_one_sender_seed2 = SenderOTSeed::default();
        let mut output_2 = PPRFOutput::default();
        b.iter(|| {
            build_pprf(
                &session_id,
                &sender_ot_seed,
                &mut _all_but_one_sender_seed2,
                &mut output_2,
            );
        });
    });

    c.bench_function("eval_pprf", |b| {
        let mut _all_but_one_sender_seed2 = SenderOTSeed::default();
        let mut output_2 = PPRFOutput::default();
        build_pprf(
            &session_id,
            &sender_ot_seed,
            &mut _all_but_one_sender_seed2,
            &mut output_2,
        );
        let mut _all_but_one_receiver_seed2 = ReceiverOTSeed::default();

        b.iter(|| {
            eval_pprf(
                &session_id,
                &receiver_ot_seed,
                &output_2,
                &mut _all_but_one_receiver_seed2,
            )
            .unwrap();
        });
    });
}

fn endemic_ot_bench(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
    let session_id: [u8; 32] = rng.gen();

    c.bench_function("EndemicOTReceiver::new", |b| {
        let mut msg1 = EndemicOTMsg1::default();

        b.iter(|| {
            let _receiver = black_box(EndemicOTReceiver::new(
                &session_id,
                &mut msg1,
                &mut rng,
            ));
        });
    });

    c.bench_function("EndemicOTSender::process", |b| {
        let mut msg1 = EndemicOTMsg1::default();

        let _receiver =
            EndemicOTReceiver::new(&session_id, &mut msg1, &mut rng);

        let mut msg2 = EndemicOTMsg2::default();

        b.iter(|| {
            let _sender_output = black_box(
                EndemicOTSender::process(
                    &session_id,
                    &msg1,
                    &mut msg2,
                    &mut rng,
                )
                .unwrap(),
            );
        });
    });

    c.bench_function("EndemicOTReceiver::process", |b| {
        let mut msg1 = EndemicOTMsg1::default();

        let receiver =
            EndemicOTReceiver::new(&session_id, &mut msg1, &mut rng);

        let mut msg2 = EndemicOTMsg2::default();

        let _sender_output =
            EndemicOTSender::process(&session_id, &msg1, &mut msg2, &mut rng)
                .unwrap();

        b.iter(|| {
            let _receiver_output =
                black_box(receiver.process(&msg2).unwrap());
        });
    });
}

fn soft_spoken_bench(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from_seed([0x55; 32]);

    let (sender_ot_results, receiver_ot_results) =
        generate_all_but_one_seed_ot(&mut rng);

    let session_id: [u8; 32] = rng.gen();
    let mut choices = [0u8; L_BYTES];
    rng.fill_bytes(&mut choices);

    c.bench_function("SoftSpokenOTReceiver::process", |b| {
        let mut round1 = Round1Output::default();
        let mut receiver_extended_output = ReceiverExtendedOutput::default();
        receiver_extended_output.choices = choices;

        b.iter(|| {
            SoftSpokenOTReceiver::process(
                &session_id,
                &sender_ot_results,
                &mut round1,
                &mut receiver_extended_output,
                &mut rng,
            );
        });
    });

    let mut round1 = Round1Output::default();
    let mut receiver_extended_output = ReceiverExtendedOutput::default();
    receiver_extended_output.choices = choices;

    SoftSpokenOTReceiver::process(
        &session_id,
        &sender_ot_results,
        &mut round1,
        &mut receiver_extended_output,
        &mut rng,
    );

    c.bench_function("SoftSpokenOTSender::process", |b| {
        b.iter(|| {
            let _sender_extended_output = black_box(
                SoftSpokenOTSender::process(
                    &session_id,
                    &receiver_ot_results,
                    &round1,
                )
                .unwrap(),
            );
        });
    });
}

fn rvole_bench(c: &mut Criterion) {
    use sl_oblivious::rvole::*;

    let mut rng = ChaCha20Rng::from_seed([0x55; 32]);

    let (sender_ot_seed, receiver_ot_seed) =
        generate_all_but_one_seed_ot(&mut rng);

    let session_id: [u8; 32] = rng.gen();

    let mut round1_output = Round1Output::default();

    let (receiver, _beta) = RVOLEReceiver::new(
        session_id,
        &sender_ot_seed,
        &mut round1_output,
        &mut rng,
    );

    let (alpha1, alpha2) = (
        Scalar::generate_biased(&mut rng),
        Scalar::generate_biased(&mut rng),
    );

    let mut round2_output = Default::default();

    let _sender_shares = RVOLESender::process(
        &session_id,
        &receiver_ot_seed,
        &[alpha1, alpha2],
        &round1_output,
        &mut round2_output,
        &mut rng,
    )
    .unwrap();

    c.bench_function("RVOLEReceiver::new", |b| {
        b.iter(|| {
            let mut round1_output = Round1Output::default();

            black_box(RVOLEReceiver::new(
                session_id,
                &sender_ot_seed,
                &mut round1_output,
                &mut rng,
            ));
        })
    });

    c.bench_function("RVOLESender::process", |b| {
        b.iter(|| {
            let mut round2_output = Default::default();

            let _sender_shares = black_box(
                RVOLESender::process(
                    &session_id,
                    &receiver_ot_seed,
                    &[alpha1, alpha2],
                    &round1_output,
                    &mut round2_output,
                    &mut rng,
                )
                .unwrap(),
            );
        });
    });

    c.bench_function("RVOLEReceiver::process", |b| {
        b.iter(|| {
            let _ = black_box(receiver.process(&round2_output));
        });
    });
}

// fn rvole_ot_variant_bench(c: &mut Criterion) {
//     use sl_oblivious::rvole_ot_variant::*;

//     let mut rng = ChaCha20Rng::from_seed([0x55; 32]);

//     let session_id: [u8; 32] = rng.gen();

//     let mut round1_output = RVOLEMsg1::default();

//     let (receiver, ot_r_a, ot_r_b, _beta) =
//         RVOLEReceiver::new(session_id, &mut round1_output, &mut rng);

//     let (alpha1, alpha2) = (
//         Scalar::generate_biased(&mut rng),
//         Scalar::generate_biased(&mut rng),
//     );

//     let mut round2_output = Default::default();

//     let _sender_shares = black_box(
//         RVOLESender::process(
//             &session_id,
//             &[alpha1, alpha2],
//             &round1_output,
//             &mut round2_output,
//             &mut rng,
//         )
//         .unwrap(),
//     );

//     c.bench_function("RVOLEReceiver-2::new", |b| {
//         b.iter(|| {
//             let mut round1_output = RVOLEMsg1::default();

//             black_box(RVOLEReceiver::new(
//                 session_id,
//                 &mut round1_output,
//                 &mut rng,
//             ));
//         })
//     });

//     c.bench_function("RVOLESender-2::process", |b| {
//         b.iter(|| {
//             let mut round2_output = Default::default();

//             let _sender_shares = black_box(
//                 RVOLESender::process(
//                     &session_id,
//                     &[alpha1, alpha2],
//                     &round1_output,
//                     &mut round2_output,
//                     &mut rng,
//                 )
//                 .unwrap(),
//             );
//         });
//     });

//     c.bench_function("RVOLEReceiver-2::process", |b| {
//         b.iter(|| {
//             let _ =
//                 black_box(receiver.process(&round2_output, &ot_r_a, &ot_r_b));
//         });
//     });
// }
//criterion_group!(rvole_ot_variant, rvole_ot_variant_bench);


criterion_group!(soft_spoken, soft_spoken_bench);
criterion_group!(rvole, rvole_bench);
criterion_group!(endemic_ot, endemic_ot_bench);
criterion_group!(pprf, all_but_one_bench);

criterion_main!(
    rvole,
    // rvole_ot_variant,
    soft_spoken,
    endemic_ot,
    pprf,
);
