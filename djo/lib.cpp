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
    protoboard<libff::Fr<ppT>> pb = _djo_pinocchio_example_1<ppT>();
    r1cs_ppzksnark_keypair<ppT> keypair = _djo_pinocchio_generate<ppT>(pb.get_constraint_system());
    r1cs_ppzksnark_proof<ppT> proof = _djo_pinocchio_prove<ppT>(_djo_pinocchio_pset<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input()));
    return _djo_pinocchio_verify<ppT>(_djo_pinocchio_vset<ppT>(keypair.vk, pb.primary_input(), proof));
}

bool djo_test_pinocchio_mnt6() {
    using ppT = libff::mnt6_pp;
    protoboard<libff::Fr<ppT>> pb = _djo_pinocchio_example_2<ppT>();
    r1cs_ppzksnark_keypair<ppT> keypair = _djo_pinocchio_generate<ppT>(pb.get_constraint_system());
    r1cs_ppzksnark_proof<ppT> proof = _djo_pinocchio_prove<ppT>(_djo_pinocchio_pset<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input()));
    return _djo_pinocchio_verify<ppT>(_djo_pinocchio_vset<ppT>(keypair.vk, pb.primary_input(), proof));
}

bool djo_test_pinocchio_mnt4_mnt6_batch(unsigned int arity) {
    using ppT_F = libff::mnt4_pp;
    using ppT_T = libff::mnt6_pp;

    // Generate a simple proof
    protoboard<libff::Fr<ppT_F>> pb = _djo_pinocchio_example_1<ppT_F>();
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
    protoboard<libff::Fr<ppT_F>> pb = _djo_pinocchio_example_1<ppT_F>();
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

bool djo_test_pinocchio_batch_3() {
    using ppT_F = libff::mnt6_pp;
    using ppT_T = libff::mnt4_pp;

    // Generate a simple proof on ppT_F
    protoboard<libff::Fr<ppT_F>> pb_F = _djo_pinocchio_example_1<ppT_F>();
    r1cs_ppzksnark_keypair<ppT_F> keypair_F = _djo_pinocchio_generate<ppT_F>(pb_F.get_constraint_system());
    r1cs_ppzksnark_proof<ppT_F> proof_F = _djo_pinocchio_prove<ppT_F>(_djo_pinocchio_pset<ppT_F>(keypair_F.pk, pb_F.primary_input(), pb_F.auxiliary_input()));
    
    // Generate a (different) simple proof on ppT_T
    protoboard<libff::Fr<ppT_T>> pb_T = _djo_pinocchio_example_2<ppT_T>();
    r1cs_ppzksnark_keypair<ppT_T> keypair_T = _djo_pinocchio_generate<ppT_T>(pb_T.get_constraint_system());
    r1cs_ppzksnark_proof<ppT_T> proof_T = _djo_pinocchio_prove<ppT_T>(_djo_pinocchio_pset<ppT_T>(keypair_T.pk, pb_T.primary_input(), pb_T.auxiliary_input()));

    // Batch 2 (different) simple proofs on ppT_F
    std::vector<_djo_pinocchio_vset<ppT_F>> vsets;
    vsets.emplace_back(_djo_pinocchio_vset<ppT_F>(keypair_F.vk, pb_F.primary_input(), proof_F));
    vsets.emplace_back(_djo_pinocchio_vset<ppT_F>(keypair_F.vk, pb_F.primary_input(), proof_F));
    _djo_pinocchio_vset<ppT_T> vset = _djo_pinocchio_batch<ppT_F, ppT_T>(vsets);

    // Batch simple proof on ppT_T with the 2-aggregated proof on ppT_T
    std::vector<_djo_pinocchio_vset<ppT_T>> vsets_final;
    vsets_final.emplace_back(_djo_pinocchio_vset<ppT_T>(keypair_T.vk, pb_T.primary_input(), proof_T));
    vsets_final.emplace_back(_djo_pinocchio_vset<ppT_T>(vset.vk, vset.prim, vset.proof));
    _djo_pinocchio_vset<ppT_F> vset_final = _djo_pinocchio_batch<ppT_T, ppT_F>(vsets_final);

    return _djo_pinocchio_verify<ppT_F>(vset_final);
}
