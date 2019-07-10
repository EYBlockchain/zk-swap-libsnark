package main

import (
	"fmt"

	"github.com/EYBlockchain/libsnark/go-djo/djo"
)

func main() {
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
	if djo.TestPinocchioBatch3Proofs() {
		fmt.Println("Batch 3 proofs (MNT4+MNT4+MNT6->MNT4): OK")
	} else {
		fmt.Println("Batch Pinocchio (MNT4+MNT4+MNT6->MNT4): KO")
	}
}
