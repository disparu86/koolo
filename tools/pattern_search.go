// +build ignore

package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	data, err := os.ReadFile(`C:\Program Files (x86)\Diablo II Resurrected\D2R.exe`)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("File size: %d bytes\n\n", len(data))

	// Patterns to search (exact bytes, no wildcards)
	patterns := map[string][]byte{
		"UnitTable (full)":  {0x48, 0x03, 0xC7, 0x49, 0x8B, 0x8C, 0xC6},
		"UnitTable (part)":  {0x49, 0x8B, 0x8C, 0xC6},
		"UnitTable (alt1)":  {0x49, 0x8B, 0x8C, 0xC5}, // R13 variant
		"UnitTable (alt2)":  {0x49, 0x8B, 0x8C, 0xC4}, // R12 variant
		"UnitTable (alt3)":  {0x49, 0x8B, 0x8C, 0xC7}, // R15 variant
		"UnitTable (alt4)":  {0x48, 0x8B, 0x8C, 0xC6}, // RSI variant (non-REX.B)
		"UnitTable (alt5)":  {0x48, 0x8B, 0x8C, 0xC7}, // RDI variant
		"ADD RAX,RDI":       {0x48, 0x03, 0xC7},
		"Roster":            {0x02, 0x45, 0x33, 0xD2, 0x4D, 0x8B},
		"Expansion (part)":  {0x48, 0x8B, 0xD9, 0xF3, 0x0F, 0x10, 0x50},
		"WidgetStates (p)":  {0x4C, 0x8D, 0x44, 0x24},
	}

	for name, pat := range patterns {
		count := 0
		for i := 0; i <= len(data)-len(pat); i++ {
			match := true
			for j := 0; j < len(pat); j++ {
				if data[i+j] != pat[j] {
					match = false
					break
				}
			}
			if match {
				count++
				if count <= 5 {
					start := i - 10
					if start < 0 {
						start = 0
					}
					end := i + len(pat) + 10
					if end > len(data) {
						end = len(data)
					}
					fmt.Printf("  %s: FOUND at file offset 0x%X\n", name, i)
					fmt.Printf("    context: %s\n", hex.EncodeToString(data[start:end]))
				}
			}
		}
		if count == 0 {
			fmt.Printf("  %s: NOT FOUND\n", name)
		} else if count > 5 {
			fmt.Printf("  %s: found %d total matches\n", name, count)
		}
	}
}
