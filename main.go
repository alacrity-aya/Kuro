package main

import (
	"log/slog"

	"kuro/config"
	"kuro/utils"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	hostName := "hostA"
	slog.Debug("main start...", "host name", hostName)

	cfg, err := config.LoadHostConfig("config.toml", hostName)
	if err != nil {
		panic(err)
	}
	slog.Debug("LoadConfig complete", "config", cfg)

	programSpecs, routeSpecs, netemSpecs := utils.ConvertToSpecs(*cfg)
	slog.Debug("ConvertToSpecs", "programSpecs", programSpecs, "routeSpecs", routeSpecs, "netemSpecs", netemSpecs)

	// TODO: create network topology here

	// mgr := manager.NewEbpfManager()
	// defer mgr.Close()
	//
	// // FIXME: Not work now because host doesn't have network topology
	// if err := mgr.Sync(programSpecs, routeSpecs); err != nil {
	// 	slog.Error("Failed to load eBPF programs and attachments", "error", err)
	// 	os.Exit(1)
	// }
	// slog.Info("eBPF programs loaded and attached successfully.")
	//
	// ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// defer stop()
	//
	// ticker := time.NewTicker(1 * time.Second)
	// defer ticker.Stop()
	//
	// for {
	// 	select {
	// 	case <-ticker.C:
	// 		// stat, err := manager.GetIfaceStats("veth-a")
	// 		// if err != nil {
	// 		// 	slog.Warn("GetIfaceStats wanring", "error", err)
	// 		// }
	// 		// fmt.Println(stat)
	//
	// 	case <-ctx.Done():
	// 		fmt.Println("\nreceive (SIGINT/SIGTERM)")
	// 		fmt.Println("exit")
	// 		return
	// 	}
	// }
}
