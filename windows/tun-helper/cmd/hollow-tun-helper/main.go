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
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"hollow/tun-helper/internal/pipe"
	"hollow/tun-helper/internal/pump"
	"hollow/tun-helper/internal/server"
	"hollow/tun-helper/internal/tun"
)

const helperVersion = "0.1.0 (T-0/T-1)"

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
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

	srv := server.New(server.Deps{
		Elevated:        isElevated,
		NewLinkEndpoint: platformLinkFactory(),
		PumpConfig:      pump.Config{},
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
