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

template<typename ppT>
protoboard<libff::Fr<ppT>> djo_build_example_1()
{
    // Protoboard to prove `x^3 + x + 5 == y` where `y` is public
    typedef libff::Fr<ppT> FieldT;
    protoboard<FieldT> pb = protoboard<FieldT>();

    // Define Wires
    pb_variable<FieldT> x;
    x.allocate(pb, "x");
    pb_variable<FieldT> t1;
    t1.allocate(pb, "t1");
    pb_variable<FieldT> t2;
    t2.allocate(pb, "t2");
    pb_variable<FieldT> t3;
    t3.allocate(pb, "t3");
    pb_variable<FieldT> y;
    y.allocate(pb, "y");

    pb.set_input_sizes(1); // first n inputs are public

    // Define Constraints
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, t1));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(t1, x, t2));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(t2 + x, 1, t3));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(t3 + 5, 1, y));

    // Evaluate Circuit
    pb.val(y) = 35; // public
    pb.val(x) = 3;
    pb.val(t1) = 9;
    pb.val(t2) = 27;
    pb.val(t3) = 30;

    return pb;
}

template<typename ppT>
protoboard<libff::Fr<ppT>> djo_build_example_2()
{
    // Protoboard to prove `a^2 = b` where `b` is public
    typedef libff::Fr<ppT> FieldT;
    protoboard<FieldT> pb = protoboard<FieldT>();

    // Define Wires
    pb_variable<FieldT> a;
    a.allocate(pb, "a");
    pb_variable<FieldT> b;
    b.allocate(pb, "b");

    pb.set_input_sizes(1); // first n inputs are public

    // Define Constraints
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(a, a, b));

    // Evaluate Circuit
    pb.val(b) = 1745041 ;// public
    pb.val(a) = 1321;

    return pb;
}

template<typename ppT>
r1cs_ppzksnark_keypair<ppT> djo_setup(const protoboard<libff::Fr<ppT>> pb)
{
    const r1cs_ppzksnark_keypair<ppT> kaypair = r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());
    return kaypair;
}

template<typename ppT>
r1cs_ppzksnark_proof<ppT> djo_generate_proof(const protoboard<libff::Fr<ppT>> pb, const r1cs_ppzksnark_proving_key<ppT> proving_key)
{
    const r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
    return proof;
}

template<typename ppT>
bool djo_verify(const protoboard<libff::Fr<ppT>> pb, const r1cs_ppzksnark_verification_key<ppT> verification_key, const r1cs_ppzksnark_proof<ppT> proof)
{
    return r1cs_ppzksnark_verifier_strong_IC<ppT>(verification_key, pb.primary_input(), proof);
}

template<typename ppT>
void djo_trace(const protoboard<libff::Fr<ppT>> pb, const r1cs_ppzksnark_keypair<ppT> keypair, const r1cs_ppzksnark_proof<ppT> proof)
{
    std::cout << "proof.g_B_g:\n";
    proof.g_B.g.print();
    std::cout << "num_constraints   :" << pb.num_constraints() << "\n";
    std::cout << "num_inputs        :" << pb.num_inputs() << "\n";
    std::cout << "num_variables     :" << pb.num_variables() << "\n";
    std::cout << "primary_input_size:" << pb.get_constraint_system().primary_input_size << "\n";
}

template<typename ppT_A, typename ppT_B>
void djo_batch()
{
    using FieldT_A = libff::Fr<ppT_A>;

    // Simple proof 1
    protoboard<FieldT_A> pb1 = djo_build_example_1<ppT_A>();
    r1cs_ppzksnark_keypair<ppT_A> keypair1 = djo_setup<ppT_A>(pb1);
    r1cs_ppzksnark_proof<ppT_A> proof1 = djo_generate_proof<ppT_A>(pb1, keypair1.pk);
    bool ok1 = djo_verify<ppT_A>(pb1, keypair1.vk, proof1);

    // Simple proof 2 (different)
    protoboard<FieldT_A> pb2 = djo_build_example_2<ppT_A>();
    r1cs_ppzksnark_keypair<ppT_A> keypair2 = djo_setup<ppT_A>(pb2);
    r1cs_ppzksnark_proof<ppT_A> proof2 = djo_generate_proof<ppT_A>(pb2, keypair2.pk);
    bool ok2 = djo_verify<ppT_A>(pb2, keypair2.vk, proof2);
    
    // Aggregation
    aggregator_circuit<ppT_A, ppT_B> aggregator(2);
    aggregator.generate_r1cs_constraints();

    vector<r1cs_ppzksnark_verification_key<ppT_A>> vks;
    vector<r1cs_primary_input<FieldT_A>> inputs;
    vector<r1cs_ppzksnark_proof<ppT_A>> proofs;

    vks.emplace_back(keypair1.vk);
    vks.emplace_back(keypair2.vk);

    inputs.emplace_back(pb1.primary_input());
    inputs.emplace_back(pb2.primary_input());
    
    proofs.emplace_back(proof1);
    proofs.emplace_back(proof2);

    aggregator.generate_r1cs_witness(vks, inputs, proofs);

    // Aggregated proof
    r1cs_ppzksnark_keypair<ppT_B> agg_keypair = djo_setup<ppT_B>(aggregator.pb);
    r1cs_ppzksnark_proof<ppT_B> agg_proof = djo_generate_proof<ppT_B>(aggregator.pb, agg_keypair.pk);
    bool ok = djo_verify<ppT_B>(aggregator.pb, agg_keypair.vk, agg_proof);

    // DEBUG
    std::cout << "\n*** DEBUG ***\n";

    if (ok1) {
        std::cout << "Simple Proof1 OK\n";
    } else {
        std::cout << "Simple Proof1 KO\n";
    }
    djo_trace<ppT_A>(pb1, keypair1, proof1);

    if (ok2) {
        std::cout << "Simple Proof2 OK\n";
    } else {
        std::cout << "Simple Proof2 KO\n";
    }
    djo_trace<ppT_A>(pb2, keypair2, proof2);

    if (ok) {
        std::cout << "Aggregated Proof OK\n";
    } else {
        std::cout << "Aggregated Proof KO\n";
    }
    djo_trace<ppT_B>(aggregator.pb, agg_keypair, agg_proof);
}


int main(void)
{
    libff::start_profiling();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();

    // Simple proofs over MNT4 and aggregated proof over MNT6
    djo_batch<libff::mnt4_pp, libff::mnt6_pp>();
}
