package djo

// #cgo CFLAGS: -I../..
// #cgo LDFLAGS: -L${SRCDIR}/deps -lstdc++ -ldjo -lsnark -lff -lgomp -lgmp -lprocps -lm -lcrypto -lgmpxx
// #include <stdlib.h>
// #include <djo/lib.h>
import "C"

func init() {
	C.djo_initialize()
}

func pinocchioPSetFree(pset *C.struct_djo_pinocchio_pset) {
	C.djo_pinocchio_pset_free(pset)
}

func pinocchioVSetFree(vset *C.struct_djo_pinocchio_vset) {
	C.djo_pinocchio_vset_free(vset)
}

// TestPinocchioMNT4 is ...
func TestPinocchioMNT4() bool {
	return bool(C.djo_test_pinocchio_mnt4())
}

// TestPinocchioMNT6 is ...
func TestPinocchioMNT6() bool {
	return bool(C.djo_test_pinocchio_mnt6())
}

// TestPinocchioMN4MNT6Batch is ...
func TestPinocchioMN4MNT6Batch(arity uint) bool {
	return bool(C.djo_test_pinocchio_mnt4_mnt6_batch(C.uint(arity)))
}

// PinocchioMNT4Prove is ...
func PinocchioMNT4Prove() string {
	vset := &C.struct_djo_pinocchio_vset{}
	C.djo_pinocchio_mnt4_prove(vset)
	s := C.GoString(vset.vk.alpha_a.x)
	pinocchioVSetFree(vset)
	return s
}
