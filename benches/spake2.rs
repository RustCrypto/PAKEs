#[macro_use]
extern crate bencher;

extern crate spake2;

use bencher::Bencher;
use spake2::{SPAKE2, Ed25519Group};

fn spake2_start(bench: &mut Bencher) {
    bench.iter(|| {
        let (_, _) = SPAKE2::<Ed25519Group>::start_a(b"password", b"A", b"B");
    })
}

/*
fn spake2_finish(bench: &mut Bencher) {
    // this doesn't work, because s1 is consumed by doing finish()
    let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(b"password",
                                                     b"idA", b"idB");
    let (s2, msg2) = SPAKE2::<Ed25519Group>::start_b(b"password",
                                                     b"idA", b"idB");
    let msg2_slice = msg2.as_slice();
    bench.iter(|| {
        s1.finish(msg2_slice)
    })
}*/

fn spake2_start_and_finish(bench: &mut Bencher) {
    let (_, msg2) = SPAKE2::<Ed25519Group>::start_b(b"password",
                                                    b"idA", b"idB");
    let msg2_slice = msg2.as_slice();
    bench.iter(|| {
        let (s1, _) = SPAKE2::<Ed25519Group>::start_a(b"password",
                                                      b"idA", b"idB");
        s1.finish(msg2_slice)
    })
}


benchmark_group!(benches,
                 spake2_start,
                 //spake2_finish,
                 spake2_start_and_finish);
benchmark_main!(benches);
