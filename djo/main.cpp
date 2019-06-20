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
<<<<<<< HEAD
    pb_A.val(out) = 35;
    pb_A.val(sym_1) = 10;
    pb_A.val(y) = 27;
    pb_A.val(sym_2) = 30;
=======
    pb_A.val(t1) = 9;
    pb_A.val(t2) = 27;
    pb_A.val(t3) = 30;

    // At this stage, Witness is calculated since we evaluate all intermediate wires
>>>>>>> 5d34c255d389f2bbae0767c3344903ef6017b898

    // Setup Circuit
    const r1cs_ppzksnark_keypair<ppT_A> keypair = r1cs_ppzksnark_generator<ppT_A>(pb_A.get_constraint_system());

    // Generate Proof
    const r1cs_ppzksnark_proof<ppT_A> pi = r1cs_ppzksnark_prover<ppT_A>(keypair.pk, pb_A.primary_input(), pb_A.auxiliary_input()); // primary is public

    // Verify Proof
    bool verified = r1cs_ppzksnark_verifier_strong_IC<ppT_A>(keypair.vk, pb_A.primary_input(), pi);

<<<<<<< HEAD
    std::cout << "\n" << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << "\n" ;
    std::cout << "This is the first proof:" << " \n"; 
    std::cout << "g_A_g: \n" ; 
    pi.g_A.g.print();
    std::cout << "g_A_h: \n"; 
    pi.g_A.h.print();
    std::cout << "g_B_g (G2): ";
    pi.g_B.g.print();
    std::cout << "g_B_h: ";
    pi.g_B.h.print(); 
    std::cout << "g_C_g: ";
    pi.g_C.g.print();
    std::cout << "g_C_h: ";
    pi.g_C.h.print(); 
    std::cout << "g_H: ";
    pi.g_H.print();
    std::cout << "g_K: ";
    pi.g_K.print(); 
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << "\n" ;

    // const size_t num_constraints = 50;
    // const size_t primary_input_size = 3;
=======
    if (verified) {
        std::cerr << "Simple Proof : OK\n";
    } else {
        std::cerr << "Simple Proof : KO\n";
    }
>>>>>>> 5d34c255d389f2bbae0767c3344903ef6017b898


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
<<<<<<< HEAD

=======
>>>>>>> 5d34c255d389f2bbae0767c3344903ef6017b898
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

<<<<<<< HEAD
    std::cout << "\n" << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << "\n" ;
    std::cout << "This is the proof of a proof:" << " \n";
    
    std::cout << "g_A_g: " << proof.g_A_g << " \n"; 
    std::cout << "g_A_h: " << proof.g_A_h << " \n"; 
    std::cout << "g_B_g (G2): " << proof.g_B_g << " \n"; 
    std::cout << "g_B_h: " << proof.g_B_h << " \n"; 
    std::cout << "g_C_g: " << proof.g_C_g << " \n"; 
    std::cout << "g_C_h: " << proof.g_C_h << " \n"; 
    std::cout << "g_H: " << proof.g_H << " \n"; 
    std::cout << "g_K: " << proof.g_K << " \n"; 
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << "\n" ;

    // printf("positive test:\n");
    // assert(pb.is_satisfied());

    // pb.val(primary_input_bits[0]) = FieldT_B::one() - pb.val(primary_input_bits[0]);
    // verifier.generate_r1cs_witness();
    // pb.val(result) = FieldT_B::one();

    // printf("negative test:\n");
    // assert(!pb.is_satisfied());
    // PRINT_CONSTRAINT_PROFILING();
    // printf("number of constraints for verifier: %zu (verifier is implemented in %s constraints and verifies %s proofs))\n",
           // pb.num_constraints(), annotation_B.c_str(), annotation_A.c_str());
}
/*
template<typename ppT_A, typename ppT_B>
void test_hardcoded_verifier(const std::string &annotation_A, const std::string &annotation_B)
{
    typedef libff::Fr<ppT_A> FieldT_A;
    typedef libff::Fr<ppT_B> FieldT_B;

    const size_t num_constraints = 50;
    const size_t primary_input_size = 3;

    r1cs_example<FieldT_A> example = generate_r1cs_example_with_field_input<FieldT_A>(num_constraints, primary_input_size);
    assert(example.primary_input.size() == primary_input_size);

    assert(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));
    const r1cs_ppzksnark_keypair<ppT_A> keypair = r1cs_ppzksnark_generator<ppT_A>(example.constraint_system);
    const r1cs_ppzksnark_proof<ppT_A> pi = r1cs_ppzksnark_prover<ppT_A>(keypair.pk, example.primary_input, example.auxiliary_input);
    bool bit = r1cs_ppzksnark_verifier_strong_IC<ppT_A>(keypair.vk, example.primary_input, pi);
    assert(bit);

    const size_t elt_size = FieldT_A::size_in_bits();
    const size_t primary_input_size_in_bits = elt_size * primary_input_size;

    protoboard<FieldT_B> pb;
    r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT_B> hardcoded_vk(pb, keypair.vk, "hardcoded_vk");
    pb_variable_array<FieldT_B> primary_input_bits;
    primary_input_bits.allocate(pb, primary_input_size_in_bits, "primary_input_bits");

    r1cs_ppzksnark_proof_variable<ppT_B> proof(pb, "proof");

    pb_variable<FieldT_B> result;
    result.allocate(pb, "result");

    r1cs_ppzksnark_online_verifier_gadget<ppT_B> online_verifier(pb, hardcoded_vk, primary_input_bits, elt_size, proof, result, "online_verifier");

    PROFILE_CONSTRAINTS(pb, "check that proofs lies on the curve")
    {
        proof.generate_r1cs_constraints();
    }
    online_verifier.generate_r1cs_constraints();

    libff::bit_vector input_as_bits;
    for (const FieldT_A &el : example.primary_input)
    {
        libff::bit_vector v = libff::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }

    primary_input_bits.fill_with_bits(pb, input_as_bits);

    proof.generate_r1cs_witness(pi);
    online_verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("positive test:\n");
    assert(pb.is_satisfied());

    pb.val(primary_input_bits[0]) = FieldT_B::one() - pb.val(primary_input_bits[0]);
    online_verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("negative test:\n");
    assert(!pb.is_satisfied());
    PRINT_CONSTRAINT_PROFILING();
    printf("number of constraints for verifier: %zu (verifier is implemented in %s constraints and verifies %s proofs))\n",
           pb.num_constraints(), annotation_B.c_str(), annotation_A.c_str());
}
*/

=======
    if (pb.is_satisfied()) {
        std::cerr << "Recursive Proof : OK\n";
    } else {
        std::cerr << "Recursive Proof : KO\n";
    }
}
>>>>>>> 5d34c255d389f2bbae0767c3344903ef6017b898

int main(void)
{
    libff::start_profiling();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();

<<<<<<< HEAD
    std::cout << "***** Test of recursive SNARKs over MNT4-6 curves *****" << "\n";
  
    std::cout << "proof over mnt4 + proof of proof over mnt6" << "\n";
=======
    std::cerr << "***** Test of recursive SNARKs over MNT4-6 curves *****" << "\n";

    std::cerr << "proof over mnt4 + proof of proof over mnt6" << "\n";
>>>>>>> 5d34c255d389f2bbae0767c3344903ef6017b898
    test_verifier<libff::mnt4_pp, libff::mnt6_pp>("mnt4", "mnt6");

    std::cerr << "proof over mnt6 + proof of proof over mnt4" << "\n";
    test_verifier<libff::mnt6_pp, libff::mnt4_pp>("mnt6", "mnt4");
}
