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

// TestPinocchioMNT4753 is ...
func TestPinocchioMNT4753() bool {
	return bool(C.djo_test_pinocchio_mnt4753())
}

// TestPinocchioMNT6753 is ...
func TestPinocchioMNT6753() bool {
	return bool(C.djo_test_pinocchio_mnt6753())
}

// TestPinocchioALT_BN128 is ...
func TestPinocchioALT_BN128() bool {
	return bool(C.djo_test_pinocchio_alt_bn128())
}

// TestPinocchioBLS12_377 is ...
func TestPinocchioBLS12_377() bool {
	return bool(C.djo_test_pinocchio_bls12_377())
}

// TestPinocchioSW6 is ...
func TestPinocchioSW6() bool {
	return bool(C.djo_test_pinocchio_sw6())
}

// TestPinocchioSW6_BIS is ...
func TestPinocchioSW6_BIS() bool {
	return bool(C.djo_test_pinocchio_sw6_bis())
}

// TestPinocchioPENDULUM is ...
func TestPinocchioPENDULUM() bool {
	return bool(C.djo_test_pinocchio_pendulum())
}

// TestPinocchioEDWARDS is ...
func TestPinocchioEDWARDS() bool {
	return bool(C.djo_test_pinocchio_edwards())
}

// TestPinocchioTOY_CURVE is ...
func TestPinocchioTOY_CURVE() bool {
	return bool(C.djo_test_pinocchio_toy_curve())
}

// TestPinocchioMNT4 is ...
func TestPinocchioMNT4() bool {
	return bool(C.djo_test_pinocchio_mnt4())
}

// TestPinocchioMNT6 is ...
func TestPinocchioMNT6() bool {
	return bool(C.djo_test_pinocchio_mnt6())
}

// TestPinocchioMNT4MNT6Batch is ...
func TestPinocchioMNT4MNT6Batch(arity uint) bool {
	return bool(C.djo_test_pinocchio_mnt4_mnt6_batch(C.uint(arity)))
}

// TestPinocchioMNT6MNT4Batch is ...
func TestPinocchioMNT6MNT4Batch(arity uint) bool {
	return bool(C.djo_test_pinocchio_mnt6_mnt4_batch(C.uint(arity)))
}

// TestPinocchioBatch3Proofs is ...
func TestPinocchioBatch3Proofs() bool {
	return bool(C.djo_test_pinocchio_batch_3())
}

