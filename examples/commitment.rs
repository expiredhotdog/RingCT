// SPDX short identifier: Unlicense

use ringct::{
    curve::{
        Scalar,
        Random
    },
    Commitment,
};

fn main() {
    //Value of the Pedersen commitment (in atomic units, for example piconeros:
        //https://web.getmonero.org/resources/moneropedia/atomic-units.html)
    let value: u64 = 123;
    //Blinding factor of the Pedersen commitment
    let blinding: Scalar = Scalar::generate();

    //Create a commitment
    let commitment = Commitment::commit(value, blinding.clone());

    //Create another commitment with the same blinding factor, but different value
    let commitment_2 = Commitment::commit(120, blinding);

    //Difference between the values
    let extra = 123 - 120;
    //Verify that the "equation" is balanced: c1 == c2 + extra.
    //Both the values and blinding factors must be perfectly balanced on each side.
    assert!(Commitment::is_balanced(vec!(commitment), vec!(commitment_2), extra));


    //A more complex equation:
    let blinding_1 = Scalar::generate();
    let blinding_2 = Scalar::generate();
    let blinding_3 = blinding_1 - blinding_2;

    let commitment_1 = Commitment::commit(1000, blinding_1);
    let commitment_2 = Commitment::commit(750, blinding_2);
    let commitment_3 = Commitment::commit(200, blinding_3);

    //c1 == c2 + c3 + extra
    assert!(Commitment::is_balanced(vec!(commitment_1), vec!(commitment_2, commitment_3), 50));


    //More complex:
    let in_blinding_1 = Scalar::generate();
    let in_blinding_2 = Scalar::generate();
    let in_blinding_3 = Scalar::generate();

    let out_blinding_1 = Scalar::generate();
    let out_blinding_2 = (in_blinding_1 + in_blinding_2 + in_blinding_3) - out_blinding_1;

    let in_commitment_1 = Commitment::commit(100_000, in_blinding_1);
    let in_commitment_2 = Commitment::commit(50_000, in_blinding_2);
    let in_commitment_3 = Commitment::commit(200_000, in_blinding_3);
    let ins = vec!(in_commitment_1, in_commitment_2, in_commitment_3);

    let out_commitment_1 = Commitment::commit(175_000, out_blinding_1);
    let out_commitment_2 = Commitment::commit(150_000, out_blinding_2);
    let outs = vec!(out_commitment_1, out_commitment_2);

    let extra = 25_000;

    assert!(Commitment::is_balanced(ins, outs, extra));
}