CXX_FLAGS = -std=c++11 -Wall -Wextra -Wfatal-errors -ggdb3 -O2 -march=native -mtune=native -O2 -g -DNDEBUG

CXX_DEFINES = -DBINARY_OUTPUT -DBN_SUPPORT_SNARK=1 -DCURVE_BN128 -DMONTGOMERY_OUTPUT -DUSE_ASM

CXX_INCLUDES = -I.. -I../depends/libff -I../depends/libfqfft -I../depends/libff/libff/.. -isystem /usr/include/x86_64-linux-gnu

force-build:
	c++ $(CXX_INCLUDES) $(CXX_DEFINES) $(CXX_FLAGS) -o djo main.cpp ../build/libsnark/libsnark.a ../build/depends/libff/libff/libff.a /usr/lib/x86_64-linux-gnu/libgmp.so -lgmp -lgmpxx -lcrypto -lprocps ../build/depends/libzm.a

djo: main.cpp aggregator_circuit.hpp aggregator_circuit.tcc
	c++ $(CXX_INCLUDES) $(CXX_DEFINES) $(CXX_FLAGS) -o djo main.cpp ../build/libsnark/libsnark.a ../build/depends/libff/libff/libff.a /usr/lib/x86_64-linux-gnu/libgmp.so -lgmp -lgmpxx -lcrypto -lprocps ../build/depends/libzm.a 2> /dev/null

test: djo
	./djo > test
	vim test

clean:
	rm -f test djo
