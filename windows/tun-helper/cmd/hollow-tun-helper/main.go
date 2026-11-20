// hollow-tun-helper: the elevated TUN helper for Hollow (T-0/T-1).
//
// It serves the fixed-verb IPC protocol (internal/ipc) over a named pipe
// restricted to the owning user, and — on enable_tun — runs the gVisor
// pump (internal/pump) between a Wintun adapter and the app's loopback
// SOCKS listener. The helper knows nothing about the Hollow protocol.
//
// Usage:
//
//	hollow-tun-helper              serve (blocks; the app launches this)
//	hollow-tun-helper --version    print version + Wintun pin
//	hollow-tun-helper --check-dll  verify wintun.dll next to the exe
//	hollow-tun-helper --restore-tun  emergency netcfg restore (spec §6);
//	                  run elevated; unwinds routes per the held snapshot
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"hollow/tun-helper/internal/netcfg"
	"hollow/tun-helper/internal/pipe"
	"hollow/tun-helper/internal/pump"
	"hollow/tun-helper/internal/server"
	"hollow/tun-helper/internal/tun"
)

const helperVersion = "0.4.0 (T-4)"

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// configDir mirrors the app's config.js: $HOLLOW_HOME or ~/.hollow.
func configDir() string {
	if v := os.Getenv("HOLLOW_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".hollow"
	}
	return filepath.Join(home, ".hollow")
}

// runRestoreTun is the emergency command (self-heal spec §6): unwind the
// netcfg takeover per the held snapshot (or the fingerprint set when the
// snapshot is corrupt), verify by re-reading the table, report per item.
func runRestoreTun() int {
	sys, err := netcfg.NewSystem()
	if err != nil {
		fmt.Fprintln(os.Stderr, "restore-tun:", err)
		return 1
	}
	eng := &netcfg.Engine{
		Dir: configDir(),
		Sys: sys,
		Log: func(s string) { fmt.Fprintln(os.Stderr, s) },
	}
	res, err := eng.Restore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "restore-tun:", err)
		return 1
	}
	fmt.Printf("restore-tun: mode=%s restored=%v verified=%v\n", res.Mode, res.Restored, res.Verified)
	if len(res.Missing) > 0 {
		fmt.Fprintf(os.Stderr, "routes still present: %v (backup kept — re-run elevated)\n", res.Missing)
		return 1
	}
	return 0
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("hollow-tun-helper: ")
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version":
			fmt.Printf("hollow-tun-helper %s; wintun %s (dll sha256 %s)\n", helperVersion, tun.WintunVersion, tun.WintunDLLSHA256)
			return
		case "--check-dll":
			if err := tun.VerifyDLLFile(filepath.Join(exeDir(), "wintun.dll")); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("wintun.dll: pinned build verified")
			return
		case "--restore-tun":
			os.Exit(runRestoreTun())
		}
	}

	sid, err := currentUserSID()
	if err != nil {
		log.Fatalf("user sid: %v", err)
	}
	ln, err := pipe.Listen(sid)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("listening on %s (owner-only ACL)", pipe.PipeName)

	// netcfg is available wherever the OS adapter exists (Windows); on
	// other platforms the helper serves without the takeover discipline
	// (development builds only — production is Windows).
	var nc *netcfg.Engine
	if sys, err := netcfg.NewSystem(); err == nil {
		nc = &netcfg.Engine{
			Dir: configDir(),
			Sys: sys,
			Log: func(s string) { log.Print(s) },
		}
	} else {
		log.Printf("netcfg unavailable: %v", err)
	}

	srv := server.New(server.Deps{
		Elevated: isElevated,
		Shutdown: func() {
			// Grace for the reply frame to flush before exit.
			time.Sleep(150 * time.Millisecond)
			log.Printf("shutdown verb — exiting")
			os.Exit(0)
		},
		NewLinkEndpoint: platformLinkFactory(),
		PumpConfig:      pump.Config{},
		Netcfg:          nc,
	})
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go srv.ServeConn(conn)
	}
}
