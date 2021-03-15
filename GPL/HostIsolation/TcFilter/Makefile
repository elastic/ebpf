
tc_loader.o: tc_filter.c $(wildcard %.h)
	clang -g -O2 -emit-llvm -c tc_filter.c -o - | llc -march=bpf -mcpu=v2 -filetype=obj -o tc_filter.o

.PHONY: clean
clean:
	rm tc_filter.o

