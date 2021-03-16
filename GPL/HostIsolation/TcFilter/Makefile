
TcFilter.o: TcFilter.c $(wildcard %.h)
	clang -g -O2 -I../../../contrib/kernel_hdrs -emit-llvm -c TcFilter.c -o - | llc -march=bpf -mcpu=v2 -filetype=obj -o TcFilter.o

.PHONY: clean
clean:
	rm TcFilter.o

