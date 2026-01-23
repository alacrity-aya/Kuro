package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux Tc ../../../bpf/tc.c -- -I../../../bpf/include
