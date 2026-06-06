// pod-init-build packs a pod-mode initramfs cpio.gz containing
// /init (weft-init), /bin/crun, and optionally /bin/cfs-client +
// /bin/weft-microvm-agent. Mirrors `weft microvm pod-init-build` but
// lives in weft-microvm-init's own module so the release workflow
// doesn't need to install the full weft binary just to call this one
// function.
//
// Usage :
//
//	pod-init-build --init bin/weft-init-linux-arm64 \
//	               --crun crun-build/dist/crun.linux.arm64 \
//	               -o out/pod-initrd-arm64.cpio.gz
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/openweft/weft-microvm/initbuild"
)

func main() {
	var (
		initBin  = flag.String("init", "", "path to the Linux weft-init ELF (required)")
		crunBin  = flag.String("crun", "", "path to the Linux crun binary -> bin/crun")
		cfsBin   = flag.String("cfs-client", "", "path to the Linux cfs-client binary -> bin/cfs-client")
		agentBin = flag.String("agent", "", "path to the Linux weft-microvm-agent binary -> bin/weft-microvm-agent")
		out      = flag.String("output", "", "output cpio.gz path (required)")
	)
	flag.Parse()
	if *initBin == "" {
		fmt.Fprintln(os.Stderr, "--init is required")
		flag.Usage()
		os.Exit(2)
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "--output is required")
		flag.Usage()
		os.Exit(2)
	}
	if err := initbuild.PodInitrd(*out, *initBin, *crunBin, *cfsBin, *agentBin); err != nil {
		log.Fatalf("pod-init-build: %v", err)
	}
	fmt.Printf("pod initramfs written to %s\n", *out)
}
