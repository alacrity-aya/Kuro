package main

import (
	"log"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removeing memlock rlimit: {}", err)
	}
}
