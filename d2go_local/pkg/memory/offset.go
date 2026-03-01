package memory

import (
	"encoding/binary"
	"log"
	"os"
	"sync"
	"time"
)

type Offset struct {
	GameData                    uintptr
	UnitTable                   uintptr
	UI                          uintptr
	Hover                       uintptr
	Expansion                   uintptr
	RosterOffset                uintptr
	PanelManagerContainerOffset uintptr
	WidgetStatesOffset          uintptr
	WaypointsOffset             uintptr
	FPS                         uintptr
	MapSeedAddr                 uintptr // Absolute address for direct map seed reading (from D2RMH pattern)
}

var d2goLogOnce sync.Once

func initD2goLog() {
	d2goLogOnce.Do(func() {
		os.MkdirAll("logs", os.ModePerm)
		f, err := os.OpenFile("logs/d2go-debug.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err == nil {
			log.SetOutput(f)
		}
	})
}

func calculateOffsets(process Process) Offset {
	return calculateOffsetsWithRetries(process, 3)
}

func calculateOffsetsWithRetries(process Process, maxAttempts int) Offset {
	initD2goLog()

	var offset Offset
	for attempt := range maxAttempts {
		offset = doCalculateOffsets(process, attempt+1)
		if offset.UnitTable != 0 {
			log.Printf("[d2go] All critical offsets found on attempt %d", attempt+1)
			return offset
		}
		if attempt < maxAttempts-1 {
			log.Printf("[d2go] UnitTable still 0, retrying in 2 seconds (attempt %d/%d)...", attempt+1, maxAttempts)
			time.Sleep(2 * time.Second)
		}
	}

	log.Printf("[d2go] WARNING: UnitTable not found after %d attempts (will retry when in-game)", maxAttempts)
	return offset
}

func doCalculateOffsets(process Process, attempt int) Offset {
	memory, err := process.getProcessMemory()
	if err != nil {
		log.Printf("[d2go] [attempt %d] getProcessMemory error: %v", attempt, err)
	}

	// Count non-zero bytes to verify memory was read
	nonZero := 0
	for _, b := range memory {
		if b != 0 {
			nonZero++
		}
	}
	log.Printf("[d2go] [attempt %d] Memory read: total=%d bytes, nonZero=%d bytes (%.1f%%)", attempt, len(memory), nonZero, float64(nonZero)/float64(len(memory))*100)

	// GameReader
	pattern := process.FindPattern(memory, "\x44\x88\x25\x00\x00\x00\x00\x66\x44\x89\x25\x00\x00\x00\x00", "xxx????xxxx????")
	log.Printf("[d2go] [attempt %d] GameData pattern: 0x%X", attempt, pattern)
	bytes := process.ReadBytesFromMemory(pattern+0x3, 4)
	offsetInt := uintptr(binary.LittleEndian.Uint32(bytes))
	gameDataOffset := (pattern - process.moduleBaseAddressPtr) - 0x121 + offsetInt

	// UnitTable
	// Pattern: 48 03 C7 49 8B 8C C6 = add rax,rdi; mov rcx,[r14+rax*8+OFFSET]
	// The 4 bytes at pattern+7 give the UnitTable offset (should be > 0x100000)
	pattern = process.FindPattern(memory, "\x48\x03\xC7\x49\x8B\x8C\xC6", "xxxxxxx")
	log.Printf("[d2go] [attempt %d] UnitTable pattern (external): 0x%X", attempt, pattern)
	var unitTableOffset uintptr
	if pattern != 0 {
		bytes = process.ReadBytesFromMemory(pattern+7, 4)
		unitTableOffset = uintptr(binary.LittleEndian.Uint32(bytes))
	} else {
		// Fallback: search from within D2R process (bypasses anti-cheat read protection)
		log.Printf("[d2go] [attempt %d] UnitTable: trying in-process search via remote thread...", attempt)
		_, val, ok := process.searchPatternViaRemoteThread(
			[]byte{0x48, 0x03, 0xC7, 0x49, 0x8B, 0x8C, 0xC6},
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			7, // read 4 bytes at pattern+7
		)
		if ok {
			unitTableOffset = uintptr(val)
			log.Printf("[d2go] [attempt %d] UnitTable found via remote thread! offset=0x%X", attempt, unitTableOffset)
		} else {
			log.Printf("[d2go] [attempt %d] UnitTable NOT found via remote thread either", attempt)
		}
	}
	// Sanity check: UnitTable offset should be large (> 0x100000), reject small values as false positives
	if unitTableOffset > 0 && unitTableOffset < 0x100000 {
		log.Printf("[d2go] [attempt %d] UnitTable offset 0x%X rejected (too small, likely false positive)", attempt, unitTableOffset)
		unitTableOffset = 0
	}

	// UI
	pattern = process.FindPattern(memory, "\x40\x84\xed\x0f\x94\x05", "xxxxxx")
	log.Printf("[d2go] [attempt %d] UI pattern: 0x%X", attempt, pattern)
	uiOffset := process.ReadUInt(pattern+6, Uint32)
	uiOffsetPtr := (pattern - process.moduleBaseAddressPtr) + 10 + uintptr(uiOffset)

	// Hover
	pattern = process.FindPattern(memory, "\xc6\x84\xc2\x00\x00\x00\x00\x00\x48\x8b\x74", "xxx?????xxx")
	log.Printf("[d2go] [attempt %d] Hover pattern: 0x%X", attempt, pattern)
	hoverOffset := process.ReadUInt(pattern+3, Uint32) - 1

	// Expansion
	pattern = process.FindPattern(memory, "\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\xD9\xF3\x0F\x10\x50\x00", "xxx????xxxxxxx?")
	log.Printf("[d2go] [attempt %d] Expansion pattern (external): 0x%X", attempt, pattern)
	var expOffset uintptr
	if pattern != 0 {
		offsetPtr := uintptr(process.ReadUInt(pattern+3, Uint32))
		expOffset = pattern - process.moduleBaseAddressPtr + 7 + offsetPtr
	} else {
		log.Printf("[d2go] [attempt %d] Expansion: trying in-process search...", attempt)
		off, val, ok := process.searchPatternViaRemoteThread(
			[]byte{0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xD9, 0xF3, 0x0F, 0x10, 0x50, 0x00},
			buildMaskFromString("xxx????xxxxxxx?"),
			3, // read 4 bytes at pattern+3
		)
		if ok {
			expOffset = off + 7 + uintptr(val)
			log.Printf("[d2go] [attempt %d] Expansion found via remote thread! offset=0x%X", attempt, expOffset)
		}
	}

	// Party members offset
	pattern = process.FindPattern(memory, "\x02\x45\x33\xD2\x4D\x8B", "xxxxxx")
	log.Printf("[d2go] [attempt %d] Roster pattern (external): 0x%X", attempt, pattern)
	var rosterOffset uintptr
	if pattern != 0 {
		offsetPtr := uintptr(process.ReadUInt(pattern-3, Uint32))
		rosterOffset = pattern - process.moduleBaseAddressPtr + 1 + offsetPtr
	} else {
		log.Printf("[d2go] [attempt %d] Roster: trying in-process search...", attempt)
		off, val, ok := process.searchPatternViaRemoteThread(
			[]byte{0x02, 0x45, 0x33, 0xD2, 0x4D, 0x8B},
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			-3, // read 4 bytes at pattern-3
		)
		if ok {
			rosterOffset = off + 1 + uintptr(val)
			log.Printf("[d2go] [attempt %d] Roster found via remote thread! offset=0x%X", attempt, rosterOffset)
		}
	}

	// PanelManagerContainer
	pattern = process.FindPatternByOperand(memory, "\x48\x89\x05\x00\x00\x00\x00\x48\x85\xDB\x74\x1E", "xxx????xxxxx")
	log.Printf("[d2go] [attempt %d] PanelManager pattern: 0x%X", attempt, pattern)
	bytes = process.ReadBytesFromMemory(pattern, 8)
	panelManagerContainerOffset := (pattern - process.moduleBaseAddressPtr)

	// WidgetStates
	pattern = process.FindPattern(memory, "\x48\x8B\x0D\x00\x00\x00\x00\x4C\x8D\x44\x24\x00\x48\x03\xC2", "xxx????xxxx?xxx")
	log.Printf("[d2go] [attempt %d] WidgetStates pattern (external): 0x%X", attempt, pattern)
	var WidgetStatesOffset uintptr
	if pattern != 0 {
		WidgetStatesPtr := process.ReadUInt(pattern+3, Uint32)
		WidgetStatesOffset = pattern - process.moduleBaseAddressPtr + 7 + uintptr(WidgetStatesPtr)
	} else {
		log.Printf("[d2go] [attempt %d] WidgetStates: trying in-process search...", attempt)
		off, val, ok := process.searchPatternViaRemoteThread(
			[]byte{0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x44, 0x24, 0x00, 0x48, 0x03, 0xC2},
			buildMaskFromString("xxx????xxxx?xxx"),
			3, // read 4 bytes at pattern+3
		)
		if ok {
			WidgetStatesOffset = off + 7 + uintptr(val)
			log.Printf("[d2go] [attempt %d] WidgetStates found via remote thread! offset=0x%X", attempt, WidgetStatesOffset)
		}
	}

	// Waypoints
	pattern = process.FindPattern(memory, "\x48\x89\x05\x00\x00\x00\x00\x0F\x11\x00", "xxx????xxx")
	log.Printf("[d2go] [attempt %d] Waypoints pattern: 0x%X", attempt, pattern)
	offsetBuffer := process.ReadUInt(pattern+3, Uint32)
	WaypointsOffset := pattern - process.moduleBaseAddressPtr + 23 + uintptr(offsetBuffer)

	// FPS
	pattern = process.FindPattern(memory, "\x8B\x1D\x00\x00\x00\x00\x48\x8D\x05\x00\x00\x00\x00\x48\x8D\x4C\x24\x40", "xx????xxx????xxxxx")
	log.Printf("[d2go] [attempt %d] FPS pattern: 0x%X", attempt, pattern)
	fpsOffsetPtr := uintptr(process.ReadUInt(pattern+2, Uint32))
	fpsOffset := pattern - process.moduleBaseAddressPtr + 6 + fpsOffsetPtr

	// MapSeed (from D2RMH) — direct pointer to map seed, no UnitTable needed
	// Pattern: 41 8B F9 48 8D 0D xx xx xx xx
	// At pattern+6: 4-byte relative offset → mapSeedAddr = baseAddr + off + 0xEA + rel
	pattern = process.FindPattern(memory, "\x41\x8B\xF9\x48\x8D\x0D", "xxxxxx")
	log.Printf("[d2go] [attempt %d] MapSeed pattern (external): 0x%X", attempt, pattern)
	var mapSeedAbsAddr uintptr
	if pattern != 0 {
		rel := int32(binary.LittleEndian.Uint32(process.ReadBytesFromMemory(pattern+6, 4)))
		mapSeedAbsAddr = uintptr(int64(pattern) + 0xEA + int64(rel))
		log.Printf("[d2go] [attempt %d] MapSeed addr: 0x%X (rel=0x%X)", attempt, mapSeedAbsAddr, rel)
	} else {
		// Fallback: try in-process search
		log.Printf("[d2go] [attempt %d] MapSeed: trying in-process search...", attempt)
		off, val, ok := process.searchPatternViaRemoteThread(
			[]byte{0x41, 0x8B, 0xF9, 0x48, 0x8D, 0x0D},
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			6, // read 4 bytes at pattern+6
		)
		if ok {
			// off is relative to module base, val is the rel32 operand
			absOff := int64(process.moduleBaseAddressPtr) + int64(off) + 0xEA + int64(int32(val))
			mapSeedAbsAddr = uintptr(absOff)
			log.Printf("[d2go] [attempt %d] MapSeed found via remote thread! addr=0x%X", attempt, mapSeedAbsAddr)
		} else {
			log.Printf("[d2go] [attempt %d] MapSeed NOT found", attempt)
		}
	}

	log.Printf("[d2go] [attempt %d] Final offsets: GameData=0x%X UnitTable=0x%X UI=0x%X Expansion=0x%X Roster=0x%X PanelMgr=0x%X WidgetStates=0x%X MapSeed=0x%X",
		attempt, gameDataOffset, unitTableOffset, uiOffsetPtr, expOffset, rosterOffset, panelManagerContainerOffset, WidgetStatesOffset, mapSeedAbsAddr)

	_ = bytes // suppress unused warning

	return Offset{
		GameData:                    gameDataOffset,
		UnitTable:                   unitTableOffset,
		UI:                          uiOffsetPtr,
		Hover:                       uintptr(hoverOffset),
		Expansion:                   expOffset,
		RosterOffset:                rosterOffset,
		PanelManagerContainerOffset: panelManagerContainerOffset,
		WidgetStatesOffset:          WidgetStatesOffset,
		WaypointsOffset:             WaypointsOffset,
		FPS:                         fpsOffset,
		MapSeedAddr:                 mapSeedAbsAddr,
	}
}
