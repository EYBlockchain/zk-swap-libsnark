CXX_FLAGS = -std=c++11 -Wall -Wextra -Wfatal-errors -ggdb3 -O2 -march=native -mtune=native -O2 -g
CXX_DEFINES = -DBINARY_OUTPUT -DBN_SUPPORT_SNARK=1 -DCURVE_BN128 -DMONTGOMERY_OUTPUT -DUSE_ASM
CXX_INCLUDES = -I.. -I../depends/libff -I../depends/libfqfft -I../depends/libff/libff/.. -isystem /usr/include/x86_64-linux-gnu

libdjo.a: lib.o
	ar qc libdjo.a lib.o

lib.o: lib.h lib.cpp serialize.tcc utils.tcc aggregator.tcc
	c++ $(CXX_FLAGS) $(CXX_DEFINES) $(CXX_INCLUDES) -c lib.cpp -o lib.o

clean:
	rm -f *.o *.a
