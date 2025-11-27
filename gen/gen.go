package gen

/*
Package bpfgen contains auto-generated eBPF program files.

This package is primarily used to house the Go bindings and byte code
generated from the C source files in the 'bpf/' directory, using bpf2go.
*/

//go:generate go tool bpf2go -tags linux Tc ../bpf/tc.bpf.c
