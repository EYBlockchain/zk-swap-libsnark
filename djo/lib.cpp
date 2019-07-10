#include "lib.h"
#include "utils.tcc"
#include "serialize.tcc"

void djo_initialize() {
    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();
}

void djo_pinocchio_pset_free(struct djo_pinocchio_pset *pset) {}

void djo_pinocchio_vset_free(struct djo_pinocchio_vset *vset) {}

bool djo_test_pinocchio_mnt4() {
    using ppT = libff::mnt4_pp;
    protoboard<libff::Fr<ppT>> pb = _djo_pinocchio_example<ppT>();
    r1cs_ppzksnark_keypair<ppT> keypair = _djo_pinocchio_generate<ppT>(pb.get_constraint_system());
    r1cs_ppzksnark_proof<ppT> proof = _djo_pinocchio_prove<ppT>(_djo_pinocchio_pset<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input()));
    return _djo_pinocchio_verify<ppT>(_djo_pinocchio_vset<ppT>(keypair.vk, pb.primary_input(), proof));
}

bool djo_test_pinocchio_mnt6() {
    using ppT = libff::mnt6_pp;
    protoboard<libff::Fr<ppT>> pb = _djo_pinocchio_example<ppT>();
    r1cs_ppzksnark_keypair<ppT> keypair = _djo_pinocchio_generate<ppT>(pb.get_constraint_system());
    r1cs_ppzksnark_proof<ppT> proof = _djo_pinocchio_prove<ppT>(_djo_pinocchio_pset<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input()));
    return _djo_pinocchio_verify<ppT>(_djo_pinocchio_vset<ppT>(keypair.vk, pb.primary_input(), proof));
}

bool djo_test_pinocchio_mnt4_mnt6_batch(unsigned int arity) {
    using ppT_F = libff::mnt4_pp;
    using ppT_T = libff::mnt6_pp;

    // Generate a simple proof
    protoboard<libff::Fr<ppT_F>> pb = _djo_pinocchio_example<ppT_F>();
    r1cs_ppzksnark_keypair<ppT_F> keypair = _djo_pinocchio_generate<ppT_F>(pb.get_constraint_system());
    r1cs_ppzksnark_proof<ppT_F> proof = _djo_pinocchio_prove<ppT_F>(_djo_pinocchio_pset<ppT_F>(keypair.pk, pb.primary_input(), pb.auxiliary_input()));

    // Batch simple proofs
    std::vector<_djo_pinocchio_vset<ppT_F>> vsets;
    for(size_t i=0; i<arity; i++)
    {
        vsets.emplace_back(_djo_pinocchio_vset<ppT_F>(keypair.vk, pb.primary_input(), proof));
    }
    _djo_pinocchio_vset<ppT_T> vset = _djo_pinocchio_batch<ppT_F, ppT_T>(vsets);
    return _djo_pinocchio_verify<ppT_T>(vset);
}

bool djo_test_pinocchio_mnt6_mnt4_batch(unsigned int arity) {
    using ppT_F = libff::mnt6_pp;
    using ppT_T = libff::mnt4_pp;

    // Generate a simple proof
    protoboard<libff::Fr<ppT_F>> pb = _djo_pinocchio_example<ppT_F>();
    r1cs_ppzksnark_keypair<ppT_F> keypair = _djo_pinocchio_generate<ppT_F>(pb.get_constraint_system());
    r1cs_ppzksnark_proof<ppT_F> proof = _djo_pinocchio_prove<ppT_F>(_djo_pinocchio_pset<ppT_F>(keypair.pk, pb.primary_input(), pb.auxiliary_input()));

    // Batch simple proofs
    std::vector<_djo_pinocchio_vset<ppT_F>> vsets;
    for(size_t i=0; i<arity; i++)
    {
        vsets.emplace_back(_djo_pinocchio_vset<ppT_F>(keypair.vk, pb.primary_input(), proof));
    }
    _djo_pinocchio_vset<ppT_T> vset = _djo_pinocchio_batch<ppT_F, ppT_T>(vsets);
    return _djo_pinocchio_verify<ppT_T>(vset);
}
