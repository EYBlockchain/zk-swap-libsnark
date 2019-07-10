# ZKP aggregation
`go-djo` aggregates two or more zero-knowledge proofs (PGHR13) using the recursive zkSNARK ([paper][1]) mechanism via MNT4-6 cycle of curves.

## Build
In `zk-swap-libsnark` directory

* `mkdir build && cd build && cmake .. && make`
* `cd djo && make`

In `go-djo` directory

* `./do deps`
* `./do build`

## Test
In `go-djo` directory

* `./djo-test`

---

## Curves

* MNT4

Curve equation is `y^2 = x^3 + a*x + b`

where 

```
a = 2
b = 423894536526684178289416011533888240029318103673896002803341544124054745019340795360841685`
```

and
```
q = 475922286169261325753349249653048451545124879242694725395555128576210262817955800483758081
r = 475922286169261325753349249653048451545124878552823515553267735739164647307408490559963137
t = 689871209842287392837045615510547309923794945
k = 4
D = -614144978799019
```

where `q` is the field characteristic, `r` the subgroup order, `t` the Frobenius trace, `k` the embedding degree and `D` the CM discriminant.

* MNT6

Curve equation is `y^2 = x^3 + a*x + b`
where
```
a = 11
b = 106700080510851735677967319632585352256454251201367587890185989362936000262606668469523074
```
and
```
q = 475922286169261325753349249653048451545124878552823515553267735739164647307408490559963137
r = 475922286169261325753349249653048451545124879242694725395555128576210262817955800483758081
t = -689871209842287392837045615510547309923794943
k = 6
D = -3
```
where `q` is the field characteristic, `r` the subgroup order, `t` the Frobenius trace, `k` the embedding degree and `D` the CM discriminant.

[1]: https://eprint.iacr.org/2014/595.pdf

