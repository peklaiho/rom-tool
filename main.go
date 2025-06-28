package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "ips <rom-file> <patch-file> ...  - apply patches to rom")
		fmt.Fprintln(os.Stderr, "sha1 <file>                      - calculate sha1")
		os.Exit(0)
	}

	if (os.Args[1] == "ips") {
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Give patch files as arguments.")
			os.Exit(1)
		}
		cmdIps(os.Args[2], os.Args[3:])
	} else if (os.Args[1] == "sha1") {
		cmdSha1(os.Args[2])
	} else {
		fmt.Fprintln(os.Stderr, "Unknown command.")
		os.Exit(1)
	}
}

func applyPatch(buffer bytes.Buffer, patch bytes.Reader) {
	// Read and verify header
	header := make([]byte, 5)
	_, err := io.ReadFull(patch, header)
	if err != nil || string(header) != "PATCH" {
		panic("Invalid IPS file")
	}

	for {

	}
}

func cmdIps(romFile string, patchFiles []string) {
	rom, err := os.ReadFile(romFile)
	if err != nil {
		panic(err)
	}

	fmt.Fprintf(os.Stderr, "Patching ROM: %s (%x)\n", romFile, sha1.Sum(rom))

	buffer := bytes.NewBuffer(rom)

	for _, patchFile := range patchFiles {
		ips, err := os.ReadFile(patchFile)
		if err != nil {
			panic(err)
		}

		fmt.Fprintf(os.Stderr, "Applying patch: %s (%x)\n", patchFile, sha1.Sum(ips))

		applyPatch(buffer, bytes.NewReader(ips))
	}

	// Write file
}

func cmdSha1(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	hash := sha1.Sum(data)
	fmt.Printf("%x\n", hash)
}
