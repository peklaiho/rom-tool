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
		fmt.Fprintln(os.Stderr, "del-header <rom-file>            - delete header (512 bytes)")
		fmt.Fprintln(os.Stderr, "info <rom-file>                  - display info about rom")
		fmt.Fprintln(os.Stderr, "ips <rom-file> <patch-file> ...  - apply patches to rom")
		fmt.Fprintln(os.Stderr, "sha1 <file>                      - calculate sha1")
		os.Exit(0)
	}

	if (os.Args[1] == "del-header") {
		cmdDelHeader(os.Args[2])
	} else if (os.Args[1] == "info") {
		cmdInfo(os.Args[2])
	} else if (os.Args[1] == "ips") {
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
		fmt.Fprintln(os.Stderr, "Invalid IPS file.")
		os.Exit(1)
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

func validateHeader(header []byte) bool {
	// Verify title characters are printable
	for _, b := range header[0 : 21] {
		if b < 32 || b > 126 {
			return false
		}
	}

	// Checksum validation
	checksum := int(header[28]) | (int(header[29]) << 8)
	complement := int(header[30]) | (int(header[31]) << 8)
	return (checksum + complement) == 0xffff
}

func readHeader(romData []byte) (int, []byte) {
	offsets := []int {
		0x7fc0, // LoROM
		0xffc0, // HiROM
		0x40ffc0, // ExHiROM
	}

	for _, offset := range offsets {
		if len(romData) >= (offset + 32) {
			header := romData[offset : offset + 32]
			if (validateHeader(header)) {
				return offset, header
			}
		}
	}

	fmt.Fprintln(os.Stderr, "ROM does not contain valid header.")
	os.Exit(1)
	return -1, nil // never gets here
}

func cmdDelHeader(romFile string) {
	rom, err := os.ReadFile(romFile)
	if err != nil {
		panic(err)
	}

	fmt.Fprintf(os.Stderr, "Deleting header: %s (%x)\n", romFile, sha1.Sum(rom))

	result := rom[512:]
	resultFile := romFile + "-no-header"
	fmt.Fprintf(os.Stderr, "Writing result file: %s (%x)\n", resultFile, sha1.Sum(result))
	os.WriteFile(resultFile, result, 0644)
}

func cmdInfo(romFile string) {
	rom, err := os.ReadFile(romFile)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Size: %d (size %% 32KB: %d)\n", len(rom), len(rom) % 32768)

	_, header := readHeader(rom)

	fmt.Printf("Name: %s\n", string(header[0 : 21]))
	fmt.Printf("Mode: %02x\n", header[21])
	fmt.Printf("Chipset: %02x\n", header[22])
	fmt.Printf("ROM size: %02x (%d KB)\n", header[23], 1 << header[23])
	fmt.Printf("RAM size: %02x (%d KB)\n", header[24], 1 << header[24])
	fmt.Printf("Country: %02x\n", header[25])
	fmt.Printf("Developer: %02x\n", header[26])
	fmt.Printf("Version: %02x\n", header[27])
	fmt.Printf("Checksum Complement: %02x%02x\n", header[29], header[28])
	fmt.Printf("Checksum: %02x%02x\n", header[31], header[30])
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
