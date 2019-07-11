#ifndef DJO_UTILS
#define DJO_UTILS

#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp>

#include "aggregator.tcc"

using namespace libsnark;

template<typename ppT>
class _djo_pinocchio_pset {
    public:
        const r1cs_ppzksnark_proving_key<ppT> pk;
        const r1cs_primary_input<libff::Fr<ppT>> prim;
        const r1cs_auxiliary_input<libff::Fr<ppT>> aux;
        _djo_pinocchio_pset(
                const r1cs_ppzksnark_proving_key<ppT> &pk,
                const r1cs_primary_input<libff::Fr<ppT>> &prim,
                const r1cs_auxiliary_input<libff::Fr<ppT>> &aux):
            pk(pk), prim(prim), aux(aux) {}
};

template<typename ppT>
class _djo_pinocchio_vset {
    public:
        const r1cs_ppzksnark_verification_key<ppT> vk;
        const r1cs_primary_input<libff::Fr<ppT>> prim;
        const r1cs_ppzksnark_proof<ppT> proof;
        _djo_pinocchio_vset(
                const r1cs_ppzksnark_verification_key<ppT> &vk,
                const r1cs_primary_input<libff::Fr<ppT>> &prim,
                const r1cs_ppzksnark_proof<ppT> &proof):
            vk(vk), prim(prim), proof(proof) {}
};

    template<typename ppT>
protoboard<libff::Fr<ppT>> _djo_pinocchio_example_1()
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
protoboard<libff::Fr<ppT>> _djo_pinocchio_example_2()
{
    // Protoboard to prove factorization of an 768-RSA modulus
    // (normally it would require 2^32 operations to factor it) 
    typedef libff::Fr<ppT> FieldT;
    protoboard<FieldT> pb = protoboard<FieldT>();

    // Define Wires
    pb_variable<FieldT> a;
    a.allocate(pb, "a");
    pb_variable<FieldT> b;
    b.allocate(pb, "b");
    pb_variable<FieldT> c;
    b.allocate(pb, "c");

    pb.set_input_sizes(1); // first n inputs are public

    // Define Constraints
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(a, b, c));

    // Evaluate Circuit
    pb.val(c) = 1230186684530117755130494958384962720772853569595334792197322452151726400507263657518745202199786469389956474942774063845925192557326303453731548268507917026122142913461670429214311602221240479274737794080665351419597459856902143413; // public
    pb.val(a) = 33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489;
    pb.val(b) = 36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917;

    return pb;
}

    template<typename ppT>
r1cs_ppzksnark_keypair<ppT> _djo_pinocchio_generate(const r1cs_constraint_system<libff::Fr<ppT>> &r1cs)
{
    return r1cs_ppzksnark_generator<ppT>(r1cs);
}

    template<typename ppT>
r1cs_ppzksnark_proof<ppT> _djo_pinocchio_prove(const _djo_pinocchio_pset<ppT> &pset)
{
    return r1cs_ppzksnark_prover<ppT>(pset.pk, pset.prim, pset.aux);
}

    template<typename ppT>
bool _djo_pinocchio_verify(const _djo_pinocchio_vset<ppT> &vset)
{
    return r1cs_ppzksnark_verifier_strong_IC<ppT>(vset.vk, vset.prim, vset.proof);
}

    template<typename ppT_F, typename ppT_T>
_djo_pinocchio_vset<ppT_T> _djo_pinocchio_batch(std::vector<_djo_pinocchio_vset<ppT_F>> vsets)
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
    r1cs_ppzksnark_keypair<ppT_T> keypair = _djo_pinocchio_generate<ppT_T>(agg.pb.get_constraint_system());
    agg.generate_r1cs_witness(vks, prims, proofs);
    r1cs_ppzksnark_proof<ppT_T> proof = _djo_pinocchio_prove<ppT_T>(_djo_pinocchio_pset<ppT_T>(keypair.pk, agg.pb.primary_input(), agg.pb.auxiliary_input()));
    return _djo_pinocchio_vset<ppT_T>(keypair.vk, agg.pb.primary_input(), proof);
}

#endif
