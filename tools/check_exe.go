// +build ignore

package main

import (
	"fmt"
	"os"
)

func main() {
	data, err := os.ReadFile(`C:\Program Files (x86)\Diablo II Resurrected\D2R.exe`)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("File size: %d bytes\n", len(data))

	// Check common x86 instruction frequency in first 1MB after PE header
	start := 0x1000 // typical .text start
	end := start + 1024*1024
	if end > len(data) {
		end = len(data)
	}
	chunk := data[start:end]

	nops := 0
	rets := 0
	int3s := 0
	zeros := 0
	for _, b := range chunk {
		switch b {
		case 0x90:
			nops++
		case 0xC3:
			rets++
		case 0xCC:
			int3s++
		case 0x00:
			zeros++
		}
	}

	fmt.Printf("\nFirst 1MB of .text section (offset 0x%X to 0x%X):\n", start, end)
	fmt.Printf("  NOP (0x90): %d\n", nops)
	fmt.Printf("  RET (0xC3): %d\n", rets)
	fmt.Printf("  INT3 (0xCC): %d\n", int3s)
	fmt.Printf("  NULL (0x00): %d\n", zeros)
	fmt.Printf("  Total bytes: %d\n", len(chunk))

	// Show entropy-like distribution
	freq := make(map[byte]int)
	for _, b := range chunk {
		freq[b]++
	}
	maxFreq := 0
	minFreq := len(chunk)
	for _, v := range freq {
		if v > maxFreq {
			maxFreq = v
		}
		if v < minFreq {
			minFreq = v
		}
	}
	fmt.Printf("  Unique byte values: %d/256\n", len(freq))
	fmt.Printf("  Max freq: %d, Min freq: %d\n", maxFreq, minFreq)

	// Check if file has known packer signatures
	// Themida: look for ".themida" section
	// VMProtect: look for ".vmp" section
	for i := 0; i < len(data)-8; i++ {
		s := string(data[i : i+8])
		if s == ".themida" || s == ".Themida" {
			fmt.Printf("\nPacker detected: Themida at offset 0x%X\n", i)
		}
		if s == ".vmp0\x00\x00\x00" || s == ".vmp1\x00\x00\x00" {
			fmt.Printf("\nPacker detected: VMProtect at offset 0x%X\n", i)
		}
	}

	// Show first 32 bytes at .text offset
	fmt.Printf("\nFirst 32 bytes at .text (0x1000):\n  ")
	for i := 0; i < 32 && start+i < len(data); i++ {
		fmt.Printf("%02X ", data[start+i])
	}
	fmt.Println()

	// Show 32 bytes at offset 0x100000
	off := 0x100000
	if off+32 < len(data) {
		fmt.Printf("\n32 bytes at offset 0x%X:\n  ", off)
		for i := 0; i < 32; i++ {
			fmt.Printf("%02X ", data[off+i])
		}
		fmt.Println()
	}
}
