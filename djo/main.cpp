/**
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <iostream>

#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libff/algebra/fields/field_utils.hpp>

#include <libsnark/gadgetlib1/gadgets/fields/fp2_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp3_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp4_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp6_gadgets.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "main.hpp"

using namespace libsnark;

template<typename ppT_A, typename ppT_B>
void test_verifier(const std::string &annotation_A, const std::string &annotation_B)
{
    // Protoboard to prove `x^3 + x + 5 == y`
    typedef libff::Fr<ppT_A> FieldT_A;

    // Describe Circuit
    protoboard<FieldT_A> pb_A;

    // Define Wires
    pb_variable<FieldT_A> x;
    pb_variable<FieldT_A> t1;
    pb_variable<FieldT_A> t2;
    pb_variable<FieldT_A> t3;
    pb_variable<FieldT_A> y;

    // Allocate Wires
    y.allocate(pb_A, "y");
    x.allocate(pb_A, "x");
    t1.allocate(pb_A, "t1");
    t2.allocate(pb_A, "t2");
    t3.allocate(pb_A, "t3");

    pb_A.set_input_sizes(1); // first n inputs are public

    pb_A.add_r1cs_constraint(r1cs_constraint<FieldT_A>(x, x, t1));
    pb_A.add_r1cs_constraint(r1cs_constraint<FieldT_A>(t1, x, t2));
    pb_A.add_r1cs_constraint(r1cs_constraint<FieldT_A>(t2 + x, 1, t3));
    pb_A.add_r1cs_constraint(r1cs_constraint<FieldT_A>(t3 + 5, 1, y));

    // Evaluate Circuit
    pb_A.val(y) = 35;
    pb_A.val(x) = 3;
    pb_A.val(t1) = 9;
    pb_A.val(t2) = 27;
    pb_A.val(t3) = 30;

    // At this stage, Witness is calculated since we evaluate all intermediate wires

    // Setup Circuit
    const r1cs_ppzksnark_keypair<ppT_A> keypair = r1cs_ppzksnark_generator<ppT_A>(pb_A.get_constraint_system());

    // Generate Proof
    const r1cs_ppzksnark_proof<ppT_A> pi = r1cs_ppzksnark_prover<ppT_A>(keypair.pk, pb_A.primary_input(), pb_A.auxiliary_input()); // primary is public

    // Verify Proof
    bool verified = r1cs_ppzksnark_verifier_strong_IC<ppT_A>(keypair.vk, pb_A.primary_input(), pi);

    if (verified) {
        std::cerr << "Simple Proof : OK\n";
    } else {
        std::cerr << "Simple Proof : KO\n";
    }


    typedef libff::Fr<ppT_B> FieldT_B;

    const size_t primary_input_size = pb_A.primary_input().size();
    const size_t elt_size = FieldT_A::size_in_bits();
    const size_t primary_input_size_in_bits = elt_size * primary_input_size;
    const size_t vk_size_in_bits = r1cs_ppzksnark_verification_key_variable<ppT_B>::size_in_bits(primary_input_size);

    protoboard<FieldT_B> pb;

    // Define Wires
    pb_variable_array<FieldT_B> vk_bits;
    pb_variable_array<FieldT_B> primary_input_bits;
    pb_variable<FieldT_B> result;

    // Allocate Wires
    vk_bits.allocate(pb, vk_size_in_bits, "vk_bits");
    primary_input_bits.allocate(pb, primary_input_size_in_bits, "primary_input_bits");
    result.allocate(pb, "result");

    // Helpers
    r1cs_ppzksnark_verification_key_variable<ppT_B> vk(pb, vk_bits, primary_input_size, "vk");
    r1cs_ppzksnark_proof_variable<ppT_B> proof(pb, "proof");
    r1cs_ppzksnark_verifier_gadget<ppT_B> verifier(pb, vk, primary_input_bits, elt_size, proof, result, "verifier");

    // Build Circuit
    PROFILE_CONSTRAINTS(pb, "check that proofs lies on the curve")
    {
        proof.generate_r1cs_constraints();
    }
    verifier.generate_r1cs_constraints();

    // Evaluate Circuit (Witness)
    libff::bit_vector input_as_bits;
    for (const FieldT_A &el : pb_A.primary_input())
    {
        libff::bit_vector v = libff::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }
    primary_input_bits.fill_with_bits(pb, input_as_bits);

    // Calculate Witness
    vk.generate_r1cs_witness(keypair.vk);
    proof.generate_r1cs_witness(pi);
    verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    if (pb.is_satisfied()) {
        std::cerr << "Recursive Proof : OK\n";
    } else {
        std::cerr << "Recursive Proof : KO\n";
    }
}

int main(void)
{
    libff::start_profiling();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();

    std::cerr << "***** Test of recursive SNARKs over MNT4-6 curves *****" << "\n";

    std::cerr << "proof over mnt4 + proof of proof over mnt6" << "\n";
    test_verifier<libff::mnt4_pp, libff::mnt6_pp>("mnt4", "mnt6");

    std::cerr << "proof over mnt6 + proof of proof over mnt4" << "\n";
    test_verifier<libff::mnt6_pp, libff::mnt4_pp>("mnt6", "mnt4");
}
