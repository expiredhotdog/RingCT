// SPDX short identifier: Unlicense

use ringct::{
    common::*,
    hashes::h_bytes,
    signature::CLSAGSignature,
    rangeproof::BulletPlusRangeProof,
    address::{
        Recipient,
        cryptonote::CryptoNotePrivate
    }
};

//Generate random enote keys.
//In a real transaction protocol these would be determined by previous transactions
fn random_enote_keys(value: u64) -> EnoteKeys {
    return EnoteKeys {
        owner: Scalar::generate(),
        value,
        blinding: Scalar::generate()
    }
}

//Generate random enotes to use as decoys.
//In a real transaction protocol these would be created in previous transactions
fn generate_decoys(n: usize) -> Vec<Enote> {
    let mut enotes: Vec<Enote> = vec!();
    for _ in 0..n {
        enotes.push(Enote{
            owner: RistrettoPoint::generate(),
            commitment: Commitment(RistrettoPoint::generate())
        })
    }
    return enotes
}

//This is the message which is signed to authorize the transaction.
//This isn't really a secure way to hash the transaction
fn get_output_hash(outputs: &Vec<(Recipient, Commitment)>) -> [u8; 32] {
    let mut output_bytes: Vec<u8> = vec!();
    for output in outputs {
        let bytes = [
            output.0.to_bytes().expect("Real software should have proper error handling."), //Recipient
            output.1.to_bytes().expect("Real software should have proper error handling.")  //Commitment
        ].concat();
        output_bytes.extend(bytes);
    }
    return h_bytes(&output_bytes)
}

const RINGSIZE: usize = 16;

struct Transaction {
    inputs: Vec<(
        Ring,  //ring members
        CLSAGSignature,     //ring signature
        Commitment          //input commitment
    )>,

    outputs: Vec<(Recipient, Commitment)>,
    rangeproof: BulletPlusRangeProof,

    fee: u64
}

fn main() {
    //See the relevant examples before this.
    //Note that this is meant to be a quick example, and is likely insecure and inefficient

    let sender_enote_keys = random_enote_keys(1_000);
    let sender_enote = sender_enote_keys.to_enote();
    let sender_address_keys = CryptoNotePrivate::generate();
    let sender_address = sender_address_keys.to_public();

    let receiver_address_keys = CryptoNotePrivate::generate();
    let receiver_address = receiver_address_keys.to_public();


    // **Create transaction**

    //payment to recipient
    let (out_blinding_1, recipient_1) = receiver_address.send(600);
    //"change" for sender
    let (out_blinding_2, recipient_2) = sender_address.send(350);

    let (commitments, rangeproof) = BulletPlusRangeProof::prove(
        vec!(600, 350),
        vec!(out_blinding_1, out_blinding_2)
    ).expect("Real software should have proper error handling.");

    //create outputs
    let outputs = vec!(
        (recipient_1, commitments[0]),
        (recipient_2, commitments[1])
    );

    //create ring
    let mut ring = Ring(generate_decoys(RINGSIZE - 1));
    ring.push(sender_enote);
    ring.sort();

    //create ring signature
    let input_blinding = out_blinding_1 + out_blinding_2; //inputs and outputs must be balanced
    let (in_commitment, signature) = CLSAGSignature::sign(
        &ring, sender_enote_keys, input_blinding, &get_output_hash(&outputs)
    ).expect("Real software should have proper error handling.");
    //we only have 1 input in this example, but there can be more
    let inputs = vec!((ring, signature, in_commitment));

    //The input is 1000, and the outputs are 600 and 350.
    //1000 - (600 + 350) = 50 remaining fee
    let fee = 50;

    let transaction = Transaction{inputs, outputs, rangeproof, fee};


    // **Verify transaction**

    //verify balance
    let in_commitments: Vec<Commitment> = transaction.inputs.iter()
        .map(|input| input.2).collect();
    let out_commitments: Vec<Commitment> = transaction.outputs.iter()
        .map(|input| input.1).collect();
    assert!(Commitment::is_balanced(
        in_commitments, out_commitments.clone(), transaction.fee));

    //verify rangeproof
    BulletPlusRangeProof::verify(out_commitments, transaction.rangeproof)
        .expect("Real software should have proper error handling.");

    //verify signature
    let output_hash = get_output_hash(&transaction.outputs);
    //remember we only have 1 input in this example,
    //but if there were more then we'd have to verify all of them
    let (ring, signature, in_commitment) = transaction.inputs[0].to_owned();
    CLSAGSignature::verify(signature, &ring, in_commitment, &output_hash)
        .expect("Real software should have proper error handling.");


    // **Receive from transaction**

    //In practice, we would need to scan every output in every transaction for an incoming payment

    let (recipient_1, commitment_1) = transaction.outputs[0].to_owned();
    assert!(receiver_address_keys.receive(&recipient_1, &commitment_1).is_some());

    let (recipient_2, commitment_2) = transaction.outputs[1].to_owned();
    assert!(sender_address_keys.receive(&recipient_2, &commitment_2).is_some());
}
