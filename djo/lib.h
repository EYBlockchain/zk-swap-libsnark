#ifndef DJO_LIB_H
#define DJO_LIB_H

#ifndef __cplusplus
#ifndef bool
#include <stdbool.h>
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

    struct djo_pinocchio_g1 {
        char *x;
        char *y;
        char *z;
    };
    struct djo_pinocchio_g2 {
        char *x;
        char *y;
        char *z;
    };
    struct djo_pinocchio_kc11 {
        struct djo_pinocchio_g1 g;
        struct djo_pinocchio_g1 h;
    };
    struct djo_pinocchio_kc21 {
        struct djo_pinocchio_g2 g;
        struct djo_pinocchio_g1 h;
    };
    struct djo_pinocchio_pk {
        struct djo_pinocchio_kc11 *a_query;
        struct djo_pinocchio_kc21 *b_query;
        struct djo_pinocchio_kc11 *c_query;
        struct djo_pinocchio_g1 *h_query;
        struct djo_pinocchio_g1 *k_query;
    };
    struct djo_pinocchio_vk {
        struct djo_pinocchio_g2 alpha_a;
        struct djo_pinocchio_g1 alpha_b;
        struct djo_pinocchio_g2 alpha_c;
        struct djo_pinocchio_g2 gamma;
        struct djo_pinocchio_g1 gamma_beta_1;
        struct djo_pinocchio_g2 gamma_beta_2;
        struct djo_pinocchio_g2 rc_z;
        struct djo_pinocchio_g1 *encoded_ic_query;
    };
    struct djo_pinocchio_prim {
        struct djo_pinocchio_g1 *g1;
    };
    struct djo_pinocchio_aux {
        struct djo_pinocchio_g1 *g1;
    };
    struct djo_pinocchio_proof {
        struct djo_pinocchio_kc11 g_a;
        struct djo_pinocchio_kc21 g_b;
        struct djo_pinocchio_kc11 g_c;
        struct djo_pinocchio_g1 g_h;
        struct djo_pinocchio_g1 g_k;
    };
    struct djo_pinocchio_pset {
        struct djo_pinocchio_pk pk;
        struct djo_pinocchio_prim prim;
        struct djo_pinocchio_aux aux;
    };
    struct djo_pinocchio_vset {
        struct djo_pinocchio_vk vk;
        struct djo_pinocchio_prim prim;
        struct djo_pinocchio_proof proof;
    };

    void djo_initialize();
    void djo_pinocchio_pset_free(struct djo_pinocchio_pset *pset);
    void djo_pinocchio_vset_free(struct djo_pinocchio_vset *vset);

    bool djo_test_pinocchio_mnt4();
    bool djo_test_pinocchio_mnt6();
    bool djo_test_pinocchio_mnt4_mnt6_batch(unsigned int arity);
    bool djo_test_pinocchio_mnt6_mnt4_batch(unsigned int arity);

    void djo_pinocchio_mnt4_prove(struct djo_pinocchio_vset *vset);

#ifdef __cplusplus
}
#endif

#endif
