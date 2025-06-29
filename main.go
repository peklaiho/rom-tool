package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Buffer that wraps a byte array
type Buffer struct {
	data []byte
}

// Expand buffer if needed
func (b *Buffer) Expand(length int) {
	if len(b.data) < length {
		newBuf := make([]byte, length)
		copy(newBuf, b.data)
		b.data = newBuf
	}
}

func (b *Buffer) WriteByte(offset int, value byte, length int) {
	b.Expand(offset + length)
	for i := 0; i < length; i++ {
		b.data[offset + i] = value
	}
}

func (b *Buffer) WriteBytes(offset int, value []byte) {
	b.Expand(offset + len(value))
	for i := 0; i < len(value); i++ {
		b.data[offset + i] = value[i]
	}
}

func (b *Buffer) GetData() []byte {
	return b.data
}

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

func readData(patch *bytes.Reader, length int) []byte {
	data := make([]byte, length)
	_, err := io.ReadFull(patch, data)
	if err == io.EOF {
		return make([]byte, 0)
	} else if err != nil {
		panic(err)
	}
	return data
}

func applyPatch(buffer *Buffer, patch *bytes.Reader) {
	// Read and verify header
	header := readData(patch, 5)
	if len(header) == 0 || string(header) != "PATCH" {
		panic("Invalid IPS file")
	}

	for {
		// Read patch record
		record := readData(patch, 3)
		if len(record) == 0 || string(record) == "EOF" {
			break
		}

		// Read offset
		offset := int(binary.BigEndian.Uint32(append([]byte{0}, record...)))

		// Read size
		size := int(binary.BigEndian.Uint16(readData(patch, 2)))

		if size == 0 {
			// RLE encoded
			rleSize := int(binary.BigEndian.Uint16(readData(patch, 2)))
			rleValue := readData(patch, 1)
			buffer.WriteByte(offset, rleValue[0], rleSize)
		} else {
			// Normal patch
			data := readData(patch, size)
			buffer.WriteBytes(offset, data)
		}
	}
}

func cmdIps(romFile string, patchFiles []string) {
	rom, err := os.ReadFile(romFile)
	if err != nil {
		panic(err)
	}

	fmt.Fprintf(os.Stderr, "Patching ROM: %s (%x)\n", romFile, sha1.Sum(rom))

	buffer := Buffer{rom}

	for _, patchFile := range patchFiles {
		ips, err := os.ReadFile(patchFile)
		if err != nil {
			panic(err)
		}

		fmt.Fprintf(os.Stderr, "Applying patch: %s (%x)\n", patchFile, sha1.Sum(ips))

		applyPatch(&buffer, bytes.NewReader(ips))
	}

	// Write file
	result := buffer.GetData()
	resultFile := romFile + "-patched"
	fmt.Fprintf(os.Stderr, "Writing result file: %s (%x)\n", resultFile, sha1.Sum(result))
	os.WriteFile(resultFile, result, 0644)
}

func cmdSha1(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	hash := sha1.Sum(data)
	fmt.Printf("%x\n", hash)
}
