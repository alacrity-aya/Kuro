// Package bpf attachs ebpf program to ifaces
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux Tc tc_edt.c
