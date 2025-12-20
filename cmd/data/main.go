package main

import (
	"log"
	"log/slog"

	"kuro/data"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	hostName := "hostA"
	if err := data.RunDataClient("127.0.0.1:50051", hostName, "", []string{}, ""); err != nil {
		log.Fatalf("Data client stopped with error: %v", err)
	}
}
