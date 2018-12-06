use bencher::Bencher;
use bencher::{benchmark_group, benchmark_main};
use spake2::{Ed25519Group, Identity, Password, SPAKE2};

fn spake2_start(bench: &mut Bencher) {
    bench.iter(|| {
        let (_, _) = SPAKE2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
    })
}

/*
fn spake2_finish(bench: &mut Bencher) {
    // this doesn't work, because s1 is consumed by doing finish()
    let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(
        &Password::new(b"password"),
        &Identity::new(b"idA"),
        &Identity::new(b"idB"),
    );
    let (s2, msg2) = SPAKE2::<Ed25519Group>::start_b(
        &Password::new(b"password"),
        &Identity::new(b"idA"),
        &Identity::new(b"idB"),
    );
    let msg2_slice = msg2.as_slice();
    bench.iter(|| s1.finish(msg2_slice))
}
*/

fn spake2_start_and_finish(bench: &mut Bencher) {
    let (_, msg2) = SPAKE2::<Ed25519Group>::start_b(
        &Password::new(b"password"),
        &Identity::new(b"idA"),
        &Identity::new(b"idB"),
    );
    let msg2_slice = msg2.as_slice();
    bench.iter(|| {
        let (s1, _) = SPAKE2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
        s1.finish(msg2_slice)
    })
}

benchmark_group!(
    benches,
    spake2_start,
    //spake2_finish,
    spake2_start_and_finish
);
benchmark_main!(benches);
