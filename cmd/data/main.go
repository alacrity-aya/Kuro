package main

import (
	"flag"
	"log"
	"log/slog"

	"kuro/data"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	serverAddr := flag.String("addr", "127.0.0.1", "Control panel address")

	flag.Parse()
	hostName := "hostA"

	slog.Info("Starting data client", "target", *serverAddr, "host", hostName)

	if err := data.RunDataClient(*serverAddr+":50051", hostName, "", []string{}, ""); err != nil {
		log.Fatalf("Data client stopped with error: %v", err)
	}
}
