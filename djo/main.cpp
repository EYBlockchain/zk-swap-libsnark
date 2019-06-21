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
    const r1cs_ppzksnark_keypair<ppT_A> setup_A = r1cs_ppzksnark_generator<ppT_A>(pb_A.get_constraint_system());

    // Generate Proof
    const r1cs_ppzksnark_proof<ppT_A> proof_A = r1cs_ppzksnark_prover<ppT_A>(setup_A.pk, pb_A.primary_input(), pb_A.auxiliary_input()); // primary is public

    proof_A.g_A.g.print();

    // Verify Proof
    bool proof_ok_A = r1cs_ppzksnark_verifier_strong_IC<ppT_A>(setup_A.vk, pb_A.primary_input(), proof_A);

    if (proof_ok_A) {
        std::cout << "Simple Proof : OK\n";
    } else {
        std::cout << "Simple Proof : KO\n";
    }


    typedef libff::Fr<ppT_B> FieldT_B;

    // TODO
    const size_t primary_input_size = pb_A.primary_input().size();
    const size_t elt_size = FieldT_A::size_in_bits();
    const size_t primary_input_size_in_bits = elt_size * primary_input_size;
    const size_t vk_size_in_bits = r1cs_ppzksnark_verification_key_variable<ppT_B>::size_in_bits(primary_input_size);

    protoboard<FieldT_B> pb_B;

    // Define Wires
    pb_variable_array<FieldT_B> vk_bits;
    pb_variable_array<FieldT_B> primary_input_bits;
    pb_variable<FieldT_B> result;

    // Allocate Wires
    vk_bits.allocate(pb_B, vk_size_in_bits, "vk_bits");
    primary_input_bits.allocate(pb_B, primary_input_size_in_bits, "primary_input_bits");
    result.allocate(pb_B, "result");

    // Helpers
    r1cs_ppzksnark_verification_key_variable<ppT_B> vk_var(pb_B, vk_bits, primary_input_size, "vk");
    r1cs_ppzksnark_proof_variable<ppT_B> proof_var(pb_B, "proof");
    r1cs_ppzksnark_verifier_gadget<ppT_B> B_gadget(pb_B, vk_var, primary_input_bits, elt_size, proof_var, result, "verifier");

    // Build Circuit TODO
    PROFILE_CONSTRAINTS(pb_B, "check that proofs lies on the curve")
    {
        proof_var.generate_r1cs_constraints();
    }
    B_gadget.generate_r1cs_constraints();

    // Evaluate Circuit (Witness) TODO
    libff::bit_vector input_as_bits;
    for (const FieldT_A &el : pb_A.primary_input())
    {
        libff::bit_vector v = libff::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }
    primary_input_bits.fill_with_bits(pb_B, input_as_bits);

    // Calculate Witness
    vk_var.generate_r1cs_witness(setup_A.vk);
    proof_var.generate_r1cs_witness(proof_A);

    // std::cout << "Proof value\n";
    // proof_A.g_A.g.print();
    // std::cout << "Gate value\n";
    // std::cout << pb_B.lc_val((*proof_var.g_A_g).X) << "\n";

    B_gadget.generate_r1cs_witness();
    pb_B.val(result) = FieldT_B::one();

    // Setup Circuit
    const r1cs_ppzksnark_keypair<ppT_B> setup_B = r1cs_ppzksnark_generator<ppT_B>(pb_B.get_constraint_system());

    // Generate Proof
    const r1cs_ppzksnark_proof<ppT_B> proof_B = r1cs_ppzksnark_prover<ppT_B>(setup_B.pk, pb_B.primary_input(), pb_B.auxiliary_input()); // primary is public

    // Verify Proof
    bool proof_ok_B = r1cs_ppzksnark_verifier_strong_IC<ppT_B>(setup_B.vk, pb_B.primary_input(), proof_B);

    proof_B.g_A.g.print();

    if (proof_ok_B) {
        std::cout << "Recursive Proof : OK\n";
    } else {
        std::cout << "Recursive Proof : KO\n";
    }
}

int main(void)
{
    libff::start_profiling();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();
    test_verifier<libff::mnt4_pp, libff::mnt6_pp>("mnt4", "mnt6");
}
