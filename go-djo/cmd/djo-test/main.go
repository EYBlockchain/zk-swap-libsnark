package main

import (
	"fmt"

	"github.com/EYBlockchain/libsnark/go-djo/djo"
)

func main() {
	if djo.TestPinocchio1MNT4() {
		fmt.Println("Simple Pinocchio (mnt4) : OK")
	} else {
		fmt.Println("Simple Pinocchio (mnt4) : KO")
	}
	if djo.TestPinocchio1MNT6() {
		fmt.Println("Simple Pinocchio (mnt6) : OK")
	} else {
		fmt.Println("Simple Pinocchio (mnt6) : KO")
	}
	for i := uint(1); i <= 1; i++ {
		if djo.TestBatchMN4MNT6Pinocchio1(i) {
			fmt.Printf("Batching %d Pinocchio proofs (mnt4-mnt6) : OK\n", i)
		} else {
			fmt.Printf("Batching %d Pinocchio proofs (mnt4-mnt6) : KO\n", i)
		}
	}
	if djo.TestLength(&djo.Test{C: "éè"}) == 4 {
		fmt.Println("Bingo")
	} else {
		fmt.Println("Fail")
	}
}
