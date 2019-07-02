#ifndef DJO_SERIALIZE
#define DJO_SERIALIZE

#include "utils.tcc"
#include "lib.h"

// Basic serializers

template<typename ppT>
void _djo_serialize_vk(const r1cs_ppzksnark_verification_key<ppT> src, djo_pinocchio_vk *target) {
    const char *c = "123";
    target->alpha_a.x = (char *)malloc(4);
    strcpy(target->alpha_a.x, c);
}

template<typename ppT>
void _djo_serialize_prim(const r1cs_ppzksnark_primary_input<ppT> src, djo_pinocchio_prim *target) {}

template<typename ppT>
void _djo_serialize_proof(const r1cs_ppzksnark_proof<ppT> src, djo_pinocchio_proof *target) {}

// High level serializers
template<typename ppT>
void _djo_serialize_vset(const _djo_pinocchio_vset<ppT> *src, struct djo_pinocchio_vset *target) {}

template<typename ppT>
void _djo_serialize_pset(const _djo_pinocchio_pset<ppT> *src, struct djo_pinocchio_pset *target) {}


// High level deserializes
template<typename ppT>
void _djo_deserialize_vset(const struct djo_pinocchio_vset *src, _djo_pinocchio_vset<ppT> *target) {}

template<typename ppT>
void _djo_deserialize_pset(const struct djo_pinocchio_pset *src, _djo_pinocchio_pset<ppT> *target) {}

#endif
