/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Bulletproofs+ rangeproofs

use crate::{internal_common::*, rangeproof::MAX_VALUE};
use super::{
    BIT_RANGE, MAX_AGGREGATION_SIZE
};
use std::iter::zip;

use bulletproofs_plus::{
    range_parameters::RangeParameters,
    range_witness::RangeWitness,
    commitment_opening::CommitmentOpening,
    range_statement::RangeStatement,
    range_proof::{
        RangeProof as TariRangeProof,
        VerifyAction
    },
    generators::pedersen_gens::{
        ExtensionDegree,
        PedersenGens
    },
    errors::ProofError as TariProofError,
};

///Maximum number of proofs allowed in 1 round of batch verification.
///This is an internal limitation, and made transparent to the user by splitting large batches into groups.
///Do not increase this above 256.
const MAX_BATCH_GROUP_SIZE: usize = 256;

const EXTENSION_DEGREE: ExtensionDegree = ExtensionDegree::DefaultPedersen;
const TRANSCRIPT_LABEL: &'static str = "Bulletproofs+ Rangeproofs";

lazy_static! {
    static ref RANGE_PARAMETERS: Vec<RangeParameters<RistrettoPoint>> = generate_range_parameters();
    static ref ZERO_COMMITMENT_OPENING: CommitmentOpening = CommitmentOpening::new(0, vec!(Scalar::zero()));
    static ref ZERO_COMMITMENT: Commitment = Commitment(&Scalar::zero() * G);
}

/// pre-generate range parameters
fn generate_range_parameters() -> Vec<RangeParameters<RistrettoPoint>> {
    let pedersen_gens: PedersenGens<RistrettoPoint> = PedersenGens {
        h_base: *PEDERSEN_H_POINT,
        h_base_compressed: PEDERSEN_H_POINT.compress(),
        g_base_vec: vec!(*PEDERSEN_G_POINT),
        g_base_compressed_vec: vec!(PEDERSEN_G_POINT.compress()),
        extension_degree: EXTENSION_DEGREE
    };

    let max_agg_factor = (MAX_AGGREGATION_SIZE as f64).log2() as usize;
    let mut result: Vec<RangeParameters<RistrettoPoint>> = Vec::new();
    for i in 0 .. max_agg_factor + 1 {
        result.push(RangeParameters::init(
            BIT_RANGE,
            2usize.pow(i as u32),
            pedersen_gens.clone(),
        ).expect("failed to generate range parameters"));
    }
    return result;
}


///Bulletproofs+ rangeproof.
///
///These proofs scale logarithmically, and support highly efficient batch verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulletPlusRangeProof (
    TariRangeProof<RistrettoPoint>

); impl BulletPlusRangeProof {
    ///Create a Bulletproofs+ rangeproof, given values and blinding factors.
    ///
    ///Return a vector of commitments and a BP+ rangeproof if proving was successful,
    ///or `RangeProofError` if an error occurred.
    pub fn prove(values: Vec<u64>, blindings: Vec<Scalar>
    ) -> Result<(Vec<Commitment>, Self), RangeProofError> {

        //wrapped so we don't have to deal wtih TariProofError
        fn inner(values: Vec<u64>, blindings: Vec<Scalar>
        ) -> Result<(Vec<Commitment>, BulletPlusRangeProof), TariProofError> {

            let mut commitment_openings: Vec<CommitmentOpening> = Vec::new();
            let mut commitments: Vec<Commitment> = Vec::new();
            for (value, blinding) in zip(values, blindings) {
                commitment_openings.push(
                    CommitmentOpening::new(value, vec!(blinding))
                );
                commitments.push(Commitment::commit(value, blinding));
            }

            //power = closest value of log_2( commitments.len() ), rounded up
            let power = (commitments.len() as f64).log2().ceil();
            //n = closest power of 2, rounded up
            let n = 1 << (power as u32);
            //pad_len = distance to closest power of 2, rounded up
            let pad_len = n - commitments.len();
            //commitments must be padded to the next power of 2
            let padded_openings = [
                vec![ZERO_COMMITMENT_OPENING.clone(); pad_len], commitment_openings
            ].concat();
            let padded_commitments = [
                vec![*ZERO_COMMITMENT; pad_len], commitments.to_owned()
            ].concat();
            let padded_commitments = Commitment::to_ristretto(padded_commitments);

            let witness = RangeWitness::init(padded_openings)?;

            let none_vec = vec![None; n];
            let statement = RangeStatement::init(
                RANGE_PARAMETERS[power as usize].to_owned(), padded_commitments, none_vec, None
            )?;

            let proof = TariRangeProof::prove(
                TRANSCRIPT_LABEL, &statement, &witness
            )?;

            return Ok((commitments, BulletPlusRangeProof(proof)))
        }

        if values.len() != blindings.len() {
            return Err(RangeProofError::Malformed)
        }
        if values.len() > MAX_AGGREGATION_SIZE {
            return Err(RangeProofError::TooLargeAggregationSize)
        }
        for value in &values {
            if value > &MAX_VALUE {
                return Err(RangeProofError::OutOfRange)
            }
        }
        return match inner(values, blindings) {
            Ok(proof) => Ok(proof),
            Err(_) => Err(
                RangeProofError::Unspecified("failed to create rangeproof".to_string())
            )
        }
    }

    ///Verify a Bulletproofs+ rangeproof given its associated commitments.
    ///
    ///Returns `Ok()` if the proof is valid,
    ///or `Err(RangeProofError)` if it's invalid.
    ///
    ///`batch_verify` should be preferred when verifying multiple proofs.
    pub fn verify(commitments: Vec<Commitment>, proof: BulletPlusRangeProof
    ) -> Result<(), RangeProofError> {
        return Self::batch_verify(vec!(commitments), vec!(proof));
    }

    ///Batch-verify several Bulletproofs+ rangeproofs given their associated commitments.
    ///
    ///Returns `Ok()` if the proof is valid,
    ///or `Err(RangeProofError)` if it's invalid.
    ///
    ///Batch verification provides significant performance gains.
    pub fn batch_verify(commitments: Vec<Vec<Commitment>>, proofs: Vec<BulletPlusRangeProof>
    ) -> Result<(), RangeProofError> {

        //wrapped so we don't have to deal wtih TariProofError
        fn inner(commitments: Vec<Vec<Commitment>>, proofs: Vec<BulletPlusRangeProof>
        ) -> Result<(), TariProofError> {
            let mut statements: Vec<RangeStatement<RistrettoPoint>>;

            //power = closest value of log_2( commitment_group.len() ), rounded up
            let mut power: f64;
            //n = closest power of 2, rounded up
            let mut n: usize;
            //pad_len = distance to closest power of 2, rounded up
            let mut pad_len: usize;

            let mut padded_commitments: Vec<Commitment>;
            let mut none_vec: Vec<Option<u64>>;
            //extracted TariRangeProofs from BulletPlusRangeProof
            let mut _proofs: Vec<TariRangeProof<RistrettoPoint>>;

            //Split the proofs and commitments into smaller batches
            //Tari's BP+ implementation limits batch sizes to 256
            //This is a way to get around that
            for (commitment_group, proof_group) in zip(
                commitments.chunks(MAX_BATCH_GROUP_SIZE), proofs.chunks(MAX_BATCH_GROUP_SIZE)
            ) {
                statements = Vec::new();
                for coms in commitment_group {
                    power = (coms.len() as f64).log2().ceil();
                    n = 1 << (power as u32);
                    pad_len = n - coms.len();

                    //commitments must be padded to the next power of 2
                    padded_commitments = [
                        vec![*ZERO_COMMITMENT; pad_len], coms.to_owned()
                    ].concat();
                    let padded_commitments = Commitment::to_ristretto(padded_commitments);

                    none_vec = vec![None; n];
                    statements.push(RangeStatement::init(
                        RANGE_PARAMETERS[power as usize].to_owned(), padded_commitments, none_vec, None
                    )?);
                }
                //extract TariRangeProofs from BulletPlusRangeProof
                _proofs = proof_group.iter().map(|proof| proof.0.to_owned()).collect();

                match TariRangeProof::verify_batch(
                    TRANSCRIPT_LABEL, &statements, &_proofs, VerifyAction::VerifyOnly
                ) {
                    //continue to the next group if valid
                    Ok(_) => (),
                    Err(e) => return Err(e)
                };
            }
            //if no group returned an error, then the batch is valid
            return Ok(());
        }

        if commitments.len() != proofs.len() {
            return Err(RangeProofError::Malformed)
        }

        //check maximum aggregation size
        for commitment_group in &commitments {
            if commitment_group.len() > MAX_AGGREGATION_SIZE {
                return Err(RangeProofError::TooLargeAggregationSize)
            }
        }

        match inner(commitments, proofs) {
            Ok(result) => Ok(result),
            Err(e) => match e {
                TariProofError::VerificationFailed(_) => Err(RangeProofError::Invalid),
                _ => Err(RangeProofError::Unspecified("failed to verify rangeproof".to_string()))
            }
        }
    }

} impl ToBytes<'_> for BulletPlusRangeProof {
    //TariRangeProof has its own encoding system so we don't need bincode
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok(self.0.to_bytes());
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        return match TariRangeProof::from_bytes(bytes) {
            Ok(proof) => Ok(Self(proof)),
            Err(_) => Err(SerializationError::DecodingError)
        };
    }
}
