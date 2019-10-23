package main

import (
	"fmt"

	"github.com/EYBlockchain/libsnark/go-djo/djo"
)

func main() {
    if djo.TestPinocchioMNT4753() {
		fmt.Println("Simple Pinocchio (mnt4753) : OK")
	} else {
		fmt.Println("Simple Pinocchio (mnt4753) : KO")
	}
    if djo.TestPinocchioMNT6753() {
		fmt.Println("Simple Pinocchio (mnt6753) : OK")
	} else {
		fmt.Println("Simple Pinocchio (mnt6753) : KO")
	}
    if djo.TestPinocchioALT_BN128() {
		fmt.Println("Simple Pinocchio (alt_bn128) : OK")
	} else {
		fmt.Println("Simple Pinocchio (alt_bn128) : KO")
	}
    if djo.TestPinocchioBLS12_377() {
		fmt.Println("Simple Pinocchio (bls12_377) : OK")
	} else {
		fmt.Println("Simple Pinocchio (bls12_377) : KO")
	}
    if djo.TestPinocchioEDWARDS() {
		fmt.Println("Simple Pinocchio (edwards) : OK")
	} else {
		fmt.Println("Simple Pinocchio (edwards) : KO")
	}
    if djo.TestPinocchioSW6() {
		fmt.Println("Simple Pinocchio (sw6) : OK")
	} else {
		fmt.Println("Simple Pinocchio (sw6) : KO")
	}
    if djo.TestPinocchioSW6_BIS() {
		fmt.Println("Simple Pinocchio (sw6_bis) : OK")
	} else {
		fmt.Println("Simple Pinocchio (sw6_bis) : KO")
	}
    if djo.TestPinocchioPENDULUM() {
		fmt.Println("Simple Pinocchio (pendulum) : OK")
	} else {
		fmt.Println("Simple Pinocchio (pendulum) : KO")
	}
    if djo.TestPinocchioTOY_CURVE() {
		fmt.Println("Simple Pinocchio (toy_curve) : OK")
	} else {
		fmt.Println("Simple Pinocchio (toy_curve) : KO")
	}
	if djo.TestPinocchioMNT4() {
		fmt.Println("Simple Pinocchio (mnt4) : OK")
	} else {
		fmt.Println("Simple Pinocchio (mnt4) : KO")
	}
	if djo.TestPinocchioMNT6() {
		fmt.Println("Simple Pinocchio (mnt6) : OK")
	} else {
		fmt.Println("Simple Pinocchio (mnt6) : KO")
	}
	// if djo.TestPinocchioMNT4MNT6Batch(2) {
	// 	fmt.Println("Batch Pinocchio (MNT6->MNT4): OK")
	// } else {
	// 	fmt.Println("Batch Pinocchio (MNT6->MNT4): KO")
	// }
	// if djo.TestPinocchioMNT6MNT4Batch(2) {
	// 	fmt.Println("Batch Pinocchio (MNT4->MNT6): OK")
	// } else {
	// 	fmt.Println("Batch Pinocchio (MNT4->MNT6): KO")
	// }
	// if djo.TestPinocchioBatch3Proofs() {
	// 	fmt.Println("Batch 3 proofs (MNT4+MNT4+MNT6->MNT4): OK")
	// } else {
	// 	fmt.Println("Batch Pinocchio (MNT4+MNT4+MNT6->MNT4): KO")
	// }
}
