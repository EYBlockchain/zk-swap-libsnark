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

    void djo_initialize();
    bool djo_test_pinocchio_1_mnt4();
    bool djo_test_pinocchio_1_mnt6();
    bool djo_test_batch_mnt4_mnt6_pinocchio_1(unsigned int arity);
    struct djo_test {
        char *c;
    };
    unsigned int djo_test_length(struct djo_test *s);

#ifdef __cplusplus
}
#endif

#endif
