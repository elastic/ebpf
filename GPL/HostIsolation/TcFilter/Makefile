# Elastic eBPF
# Copyright 2021 Elasticsearch BV
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


TcFilter.bpf.o: TcFilter.bpf.c $(wildcard %.h) Kerneldefs.h
	clang -g -O2 -I../../../contrib/kernel_hdrs -emit-llvm -c TcFilter.bpf.c -o - | llc -march=bpf -mcpu=v2 -filetype=obj -o TcFilter.bpf.o

.PHONY: clean
clean:
	rm -f TcFilter.bpf.o

