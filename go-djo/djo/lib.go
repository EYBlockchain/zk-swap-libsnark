package djo

// #cgo CFLAGS: -I../..
// #cgo LDFLAGS: -L${SRCDIR}/deps -lstdc++ -ldjo -lsnark -lff -lgomp -lgmp -lprocps -lm -lcrypto -lgmpxx
// #include <stdlib.h>
// #include <djo/lib.h>
import "C"
import "unsafe"

func init() {
	C.djo_initialize()
}

// TestPinocchio1MNT4 is ...
func TestPinocchio1MNT4() bool {
	return bool(C.djo_test_pinocchio_1_mnt4())
}

// TestPinocchio1MNT6 is ...
func TestPinocchio1MNT6() bool {
	return bool(C.djo_test_pinocchio_1_mnt4())
}

// TestBatchMN4MNT6Pinocchio1 is ...
func TestBatchMN4MNT6Pinocchio1(arity uint) bool {
	return bool(C.djo_test_batch_mnt4_mnt6_pinocchio_1(C.uint(arity)))
}

// Test is ...
type Test struct {
	C string
}

// TestLength is ...
func TestLength(t *Test) uint {
	c := C.CString(t.C)
	defer C.free(unsafe.Pointer(c))
	s := &C.struct_djo_test{c: c}
	return uint(C.djo_test_length(s))
}
