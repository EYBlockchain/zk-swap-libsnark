#include "lib.h"
#include "utils.tcc"

void djo_initialize() {
    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();
}

bool djo_test_pinocchio_1_mnt4() {
    using ppT = libff::mnt4_pp;
    protoboard<libff::Fr<ppT>> pb = djo_pinocchio_1<ppT>();
    r1cs_ppzksnark_keypair<ppT> keypair = djo_pinocchio_generate<ppT>(pb.get_constraint_system());
    r1cs_ppzksnark_proof<ppT> proof = djo_pinocchio_prove<ppT>(djo_pinocchio_pset<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input()));
    return djo_pinocchio_verify<ppT>(djo_pinocchio_vset<ppT>(keypair.vk, pb.primary_input(), proof));
}

bool djo_test_pinocchio_1_mnt6() {
    using ppT = libff::mnt6_pp;
    protoboard<libff::Fr<ppT>> pb = djo_pinocchio_1<ppT>();
    r1cs_ppzksnark_keypair<ppT> keypair = djo_pinocchio_generate<ppT>(pb.get_constraint_system());
    r1cs_ppzksnark_proof<ppT> proof = djo_pinocchio_prove<ppT>(djo_pinocchio_pset<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input()));
    return djo_pinocchio_verify<ppT>(djo_pinocchio_vset<ppT>(keypair.vk, pb.primary_input(), proof));
}

bool djo_test_batch_mnt4_mnt6_pinocchio_1(unsigned int arity) {
    using ppT_F = libff::mnt4_pp;
    using ppT_T = libff::mnt6_pp;

    // Generate a simple proof
    protoboard<libff::Fr<ppT_F>> pb = djo_pinocchio_1<ppT_F>();
    r1cs_ppzksnark_keypair<ppT_F> keypair = djo_pinocchio_generate<ppT_F>(pb.get_constraint_system());
    r1cs_ppzksnark_proof<ppT_F> proof = djo_pinocchio_prove<ppT_F>(djo_pinocchio_pset<ppT_F>(keypair.pk, pb.primary_input(), pb.auxiliary_input()));

    // Batch simple proofs
    std::vector<djo_pinocchio_vset<ppT_F>> vsets;
    for(size_t i=0; i<arity; i++)
    {
        vsets.emplace_back(djo_pinocchio_vset<ppT_F>(keypair.vk, pb.primary_input(), proof));
    }
    djo_pinocchio_vset<ppT_T> vset = djo_pinocchio_batch<ppT_F, ppT_T>(vsets);
    return djo_pinocchio_verify<ppT_T>(vset);
}

unsigned int djo_test_length(struct djo_test *s) {
    return strlen(s->c);
}
