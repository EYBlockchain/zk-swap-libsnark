# ZKP aggregation
`go-djo` aggregates two or more zero-knowledge proofs (PGHR13) using the recursive zkSNARK ([paper][1]) mechanism via MNT4/MNT6 cycle of curves.

## Build
In `zk-swap-libsnark` directory

* `git submodule update --init --recursive`
* `mkdir build && cd build && cmake .. && make`
* `cd djo && make`

In `go-djo` directory

* `./do deps`
* `./do build`

## Test
In `go-djo` directory

* `./djo-test`
