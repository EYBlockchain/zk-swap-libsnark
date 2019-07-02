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
	fmt.Println(djo.PinocchioMNT4Prove())
}
