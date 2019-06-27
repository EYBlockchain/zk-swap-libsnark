#ifndef DJO_UTILS
#define DJO_UTILS

#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp>

#include "aggregator.tcc"

using namespace libsnark;

template<typename ppT>
class djo_pinocchio_pset {
    public:
        const r1cs_ppzksnark_proving_key<ppT> pk;
        const r1cs_primary_input<libff::Fr<ppT>> prim;
        const r1cs_auxiliary_input<libff::Fr<ppT>> aux;
        djo_pinocchio_pset(
                const r1cs_ppzksnark_proving_key<ppT> &pk,
                const r1cs_primary_input<libff::Fr<ppT>> &prim,
                const r1cs_auxiliary_input<libff::Fr<ppT>> &aux):
            pk(pk), prim(prim), aux(aux) {}
};

template<typename ppT>
class djo_pinocchio_vset {
    public:
        const r1cs_ppzksnark_verification_key<ppT> vk;
        const r1cs_primary_input<libff::Fr<ppT>> prim;
        const r1cs_ppzksnark_proof<ppT> proof;
        djo_pinocchio_vset(
                const r1cs_ppzksnark_verification_key<ppT> &vk,
                const r1cs_primary_input<libff::Fr<ppT>> &prim,
                const r1cs_ppzksnark_proof<ppT> &proof):
            vk(vk), prim(prim), proof(proof) {}
};

    template<typename ppT>
protoboard<libff::Fr<ppT>> djo_pinocchio_1()
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

    assert(pb.is_satisfied());

    return pb;
}

    template<typename ppT>
r1cs_ppzksnark_keypair<ppT> djo_pinocchio_generate(const r1cs_constraint_system<libff::Fr<ppT>> &r1cs)
{
    return r1cs_ppzksnark_generator<ppT>(r1cs);
}

    template<typename ppT>
r1cs_ppzksnark_proof<ppT> djo_pinocchio_prove(const djo_pinocchio_pset<ppT> &pset)
{
    return r1cs_ppzksnark_prover<ppT>(pset.pk, pset.prim, pset.aux);
}

    template<typename ppT>
bool djo_pinocchio_verify(const djo_pinocchio_vset<ppT> &vset)
{
    return r1cs_ppzksnark_verifier_strong_IC<ppT>(vset.vk, vset.prim, vset.proof);
}

    template<typename ppT_F, typename ppT_T>
djo_pinocchio_vset<ppT_T> djo_pinocchio_batch(std::vector<djo_pinocchio_vset<ppT_F>> vsets)
{
    aggregator<ppT_F, ppT_T> agg(vsets.size());
    agg.generate_r1cs_constraints();

    std::vector<r1cs_ppzksnark_verification_key<ppT_F>> vks;
    std::vector<r1cs_primary_input<libff::Fr<ppT_F>>> prims;
    std::vector<r1cs_ppzksnark_proof<ppT_F>> proofs;
    for (auto const& vset: vsets) {
        vks.emplace_back(vset.vk);
        prims.emplace_back(vset.prim);
        proofs.emplace_back(vset.proof);
    }
    r1cs_ppzksnark_keypair<ppT_T> keypair = djo_pinocchio_generate<ppT_T>(agg.pb.get_constraint_system());
    agg.generate_r1cs_witness(vks, prims, proofs);
    r1cs_ppzksnark_proof<ppT_T> proof = djo_pinocchio_prove<ppT_T>(djo_pinocchio_pset<ppT_T>(keypair.pk, agg.pb.primary_input(), agg.pb.auxiliary_input()));
    return djo_pinocchio_vset<ppT_T>(keypair.vk, agg.pb.primary_input(), proof);
}

#endif
