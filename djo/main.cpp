/**
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <iostream>

#include <libff/algebra/fields/field_utils.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <libsnark/gadgetlib1/gadgets/fields/fp2_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp3_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp4_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp6_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp>

#include "aggregator_circuit.hpp"

using namespace libsnark;

template<typename ppT_A, typename ppT_B>
void test_verifier(const std::string &annotation_A, const std::string &annotation_B)
{
    // Protoboard to prove `x^3 + x + 5 == y` where `y` is public
    typedef libff::Fr<ppT_A> FieldT_A;
    protoboard<FieldT_A> pb_A;

    // Define Wires
    pb_variable<FieldT_A> x;
    x.allocate(pb_A, "x");
    pb_variable<FieldT_A> t1;
    t1.allocate(pb_A, "t1");
    pb_variable<FieldT_A> t2;
    t2.allocate(pb_A, "t2");
    pb_variable<FieldT_A> t3;
    t3.allocate(pb_A, "t3");
    pb_variable<FieldT_A> y;
    y.allocate(pb_A, "y");

    pb_A.set_input_sizes(1); // first n inputs are public

    // Define Constraints
    pb_A.add_r1cs_constraint(r1cs_constraint<FieldT_A>(x, x, t1));
    pb_A.add_r1cs_constraint(r1cs_constraint<FieldT_A>(t1, x, t2));
    pb_A.add_r1cs_constraint(r1cs_constraint<FieldT_A>(t2 + x, 1, t3));
    pb_A.add_r1cs_constraint(r1cs_constraint<FieldT_A>(t3 + 5, 1, y));

    // Evaluate Circuit
    pb_A.val(y) = 35; // public
    pb_A.val(x) = 3;
    pb_A.val(t1) = 9;
    pb_A.val(t2) = 27;
    pb_A.val(t3) = 30;

    // At this stage, Witness is calculated since we evaluate all intermediate wires

    // Setup Proof System (PGHR13)
    const r1cs_ppzksnark_keypair<ppT_A> setup_A = r1cs_ppzksnark_generator<ppT_A>(pb_A.get_constraint_system());

    // Generate Proof
    const r1cs_ppzksnark_proof<ppT_A> proof_A = r1cs_ppzksnark_prover<ppT_A>(setup_A.pk, pb_A.primary_input(), pb_A.auxiliary_input()); // primary is public

    // Verify Proof
    bool proof_ok_A = r1cs_ppzksnark_verifier_strong_IC<ppT_A>(setup_A.vk, pb_A.primary_input(), proof_A);

    // DEBUG
    proof_A.g_B.g.print();
    std::cout << pb_A.num_constraints() << "\n";
    std::cout << pb_A.num_inputs() << "\n";
    std::cout << pb_A.num_variables() << "\n";
    std::cout << pb_A.get_constraint_system().primary_input_size << "\n";
    std::cout << pb_A.primary_input().size() << "\n";
    if (proof_ok_A) {
        std::cout << "Simple Proof : OK\n";
    } else {
        std::cout << "Simple Proof : KO\n";
    }


    // Protoboard to prove the correct verification of proof_A (Proof of a Proof)
    typedef libff::Fr<ppT_B> FieldT_B;
    protoboard<FieldT_B> pb_B;

    const size_t primary_input_size = pb_A.primary_input().size();

    // Define Wires
    pb_variable_array<FieldT_B> vk_bits;
    const size_t vk_size_in_bits = r1cs_ppzksnark_verification_key_variable<ppT_B>::size_in_bits(primary_input_size);
    vk_bits.allocate(pb_B, vk_size_in_bits, "vk_bits");

    pb_variable_array<FieldT_B> primary_input_bits;
    const size_t elt_size = FieldT_A::size_in_bits();
    const size_t primary_input_size_in_bits = elt_size * primary_input_size;
    primary_input_bits.allocate(pb_B, primary_input_size_in_bits, "primary_input_bits");

    pb_variable<FieldT_B> result;
    result.allocate(pb_B, "result");

    // Define Constraints
    r1cs_ppzksnark_verification_key_variable<ppT_B> vk_var(pb_B, vk_bits, primary_input_size, "vk");
    vk_var.generate_r1cs_constraints(false);
    r1cs_ppzksnark_proof_variable<ppT_B> proof_var(pb_B, "proof");
    proof_var.generate_r1cs_constraints();

    r1cs_ppzksnark_verifier_gadget<ppT_B> B_gadget(pb_B, vk_var, primary_input_bits, elt_size, proof_var, result, "verifier");
    B_gadget.generate_r1cs_constraints();

    // Evaluate Circuit
    // => Kind of copy last wire (public) from circuit A
    libff::bit_vector input_as_bits;
    for (const FieldT_A &el : pb_A.primary_input())
    {
        libff::bit_vector v = libff::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }
    primary_input_bits.fill_with_bits(pb_B, input_as_bits);
    // => Fill values from vk and proof of circuit A
    vk_var.generate_r1cs_witness(setup_A.vk);
    proof_var.generate_r1cs_witness(proof_A);
    B_gadget.generate_r1cs_witness();
    pb_B.val(result) = FieldT_B::one();

    // Setup Proof System (PGHR13)
    const r1cs_ppzksnark_keypair<ppT_B> setup_B = r1cs_ppzksnark_generator<ppT_B>(pb_B.get_constraint_system());

    // Generate Proof
    const r1cs_ppzksnark_proof<ppT_B> proof_B = r1cs_ppzksnark_prover<ppT_B>(setup_B.pk, pb_B.primary_input(), pb_B.auxiliary_input()); // primary is public

    // Verify Proof
    bool proof_ok_B = r1cs_ppzksnark_verifier_strong_IC<ppT_B>(setup_B.vk, pb_B.primary_input(), proof_B);

    // DEBUG
    proof_B.g_B.g.print();
    std::cout << pb_B.num_constraints() << "\n";
    std::cout << pb_B.num_inputs() << "\n";
    std::cout << pb_B.num_variables() << "\n";
    std::cout << pb_B.get_constraint_system().primary_input_size << "\n";
    std::cout << pb_B.primary_input().size() << "\n";
    if (proof_ok_B) {
        std::cout << "Recursive Proof : OK\n";
    } else {
        std::cout << "Recursive Proof : KO\n";
    }
}

template<typename curve_A_pp, typename curve_B_pp>
void test_batch_verifier(const std::string &annotation_A, const std::string &annotation_B)
{

    using Field_A = libff::Fr<curve_A_pp>;
    using Field_B = libff::Fr<curve_B_pp>;

    // Generate example circuit
    protoboard<Field_A> example;

    // Define Wires
    pb_variable<Field_A> x;
    x.allocate(example, "x");
    pb_variable<Field_A> t1;
    t1.allocate(example, "t1");
    pb_variable<Field_A> t2;
    t2.allocate(example, "t2");
    pb_variable<Field_A> t3;
    t3.allocate(example, "t3");
    pb_variable<Field_A> y;
    y.allocate(example, "y");

    example.set_input_sizes(1); // first n inputs are public

    // Define Constraints
    example.add_r1cs_constraint(r1cs_constraint<Field_A>(x, x, t1));
    example.add_r1cs_constraint(r1cs_constraint<Field_A>(t1, x, t2));
    example.add_r1cs_constraint(r1cs_constraint<Field_A>(t2 + x, 1, t3));
    example.add_r1cs_constraint(r1cs_constraint<Field_A>(t3 + 5, 1, y));

    // Evaluate Circuit
    example.val(y) = 35; // public
    example.val(x) = 3;
    example.val(t1) = 9;
    example.val(t2) = 27;
    example.val(t3) = 30;

    // At this stage, Witness is calculated since we evaluate all intermediate wires

    // Setup Proof System (PGHR13)
    const r1cs_ppzksnark_keypair<curve_A_pp> setup_A = r1cs_ppzksnark_generator<curve_A_pp>(example.get_constraint_system());
    // const r1cs_ppzksnark_keypair<curve_A_pp> setup_A = r1cs_ppzksnark_generator<curve_A_pp>(example.constraint_system);

    // Generate Proof
    const r1cs_ppzksnark_proof<curve_A_pp> proof_A = r1cs_ppzksnark_prover<curve_A_pp>(setup_A.pk, example.primary_input(), example.auxiliary_input()); // primary is public

    // Verify Proof
    bool proof_ok_A = r1cs_ppzksnark_verifier_strong_IC<curve_A_pp>(setup_A.vk, example.primary_input(), proof_A);

    if (proof_ok_A) {
        std::cout << "simple proof: ok\n";
    } else {
        std::cout << "simple proof: ko\n";
    }

    // Build aggregator circuit
    aggregator_circuit<curve_A_pp, curve_B_pp> circuit(2);
    circuit.generate_r1cs_constraints();

    vector<r1cs_ppzksnark_verification_key<curve_A_pp>> vks;
    vector<r1cs_primary_input<Field_A>> inputs;
    vector<r1cs_ppzksnark_proof<curve_A_pp>> proofs;

    for(size_t k=0; k<2; k++)
    {
        vks.emplace_back(setup_A.vk);
        inputs.emplace_back(example.primary_input());
        proofs.emplace_back(proof_A);
    }

    circuit.generate_r1cs_witness(vks, inputs, proofs);

    // Run generator
    r1cs_constraint_system<Field_B> aggregator_constraint_system = circuit.pb.get_constraint_system();
    r1cs_ppzksnark_keypair<curve_B_pp> aggregator_key_pair = r1cs_ppzksnark_generator<curve_B_pp>(aggregator_constraint_system);


    // Run prover and verifier on valid proof
    r1cs_ppzksnark_proof<curve_B_pp> aggregation_proof = r1cs_ppzksnark_prover<curve_B_pp>(
        aggregator_key_pair.pk,
        circuit.pb.primary_input(),
        circuit.pb.auxiliary_input()
    );
    bool aggregation_verified = r1cs_ppzksnark_verifier_strong_IC<curve_B_pp>(
        aggregator_key_pair.vk,
        circuit.pb.primary_input(),
        aggregation_proof
    );
    if (aggregation_verified) {
        std::cout << "aggregated proof: ok\n";
    } else {
        std::cout << "aggregated proof: ko\n";
    }
    assert(aggregation_verified);

    // Do it with a fakeproof
    circuit.pb.val(circuit.aggregator_input_var[0]) = 0;
    assert(!circuit.pb.is_satisfied());
}


int main(void)
{
    libff::start_profiling();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();

    test_verifier<libff::mnt4_pp, libff::mnt6_pp>("mnt4", "mnt6");
    // test_verifier<libff::mnt6_pp, libff::mnt4_pp>("mnt6", "mnt4");

    test_batch_verifier<libff::mnt4_pp, libff::mnt6_pp>("mnt4", "mnt6");
}
