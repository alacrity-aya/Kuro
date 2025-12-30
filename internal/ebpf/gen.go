// Package ebpf attachs ebpf program to ifaces
package ebpf

//go:generate go tool bpf2go -tags linux Mark ../../bpf/mark.c
//go:generate go tool bpf2go -tags linux Tc ../../bpf/tc.c
