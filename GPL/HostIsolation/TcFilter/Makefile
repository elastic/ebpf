
TcFilter.bpf.o: TcFilter.bpf.c $(wildcard %.h)
	clang -g -O2 -I../../../contrib/kernel_hdrs -emit-llvm -c TcFilter.bpf.c -o - | llc -march=bpf -mcpu=v2 -filetype=obj -o TcFilter.bpf.o

.PHONY: clean
clean:
	rm TcFilter.bpf.o

