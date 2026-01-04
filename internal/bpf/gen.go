// Package bpf attachs ebpf program to ifaces
package bpf

//go:generate go tool bpf2go -tags linux Tc ../../bpf/tc.c -- -I../../bpf/include
