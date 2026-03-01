package memory

import (
	"encoding/binary"
	"log"
	"sync"

	"github.com/hectorgimenez/d2go/pkg/data"
	"github.com/hectorgimenez/d2go/pkg/data/skill"
)

var (
	cachedBlobOffset      uintptr
	cachedBlobSkillOffset uintptr
	kbScanOnce            sync.Once
	kbScanDone            bool
)

func (gd *GameReader) GetKeyBindings() data.KeyBindings {
	blob, blobSkills := gd.readKeyBindingBlobs()


	skillsKB := [16]data.SkillBinding{}
	for i := 0; i < 7; i++ {
		skillsKB[i] = data.SkillBinding{
			SkillID: skill.ID(binary.LittleEndian.Uint32(blobSkills[i*0x1c : i*0x1c+4])),
			KeyBinding: data.KeyBinding{
				Key1: [2]byte{blob[0x118+(i*0x14)], blob[0x119+(i*0x14)]},
				Key2: [2]byte{blob[0x122+(i*0x14)], blob[0x123+(i*0x14)]},
			},
		}
	}
	for i := 0; i < 9; i++ {
		skillIdx := i + 7
		skillsKB[skillIdx] = data.SkillBinding{
			SkillID: skill.ID(binary.LittleEndian.Uint32(blobSkills[skillIdx*0x1c : skillIdx*0x1c+4])),
			KeyBinding: data.KeyBinding{
				Key1: [2]byte{blob[0x384+(i*0x14)], blob[0x385+(i*0x14)]},
				Key2: [2]byte{blob[0x38e+(i*0x14)], blob[0x38f+(i*0x14)]},
			},
		}
	}

	belt := [4]data.KeyBinding{}
	for i := 0; i < 4; i++ {
		belt[i] = data.KeyBinding{
			Key1: [2]byte{blob[0x1b8+(i*0x14)], blob[0x1b9+(i*0x14)]},
			Key2: [2]byte{blob[0x1c2+(i*0x14)], blob[0x1c3+(i*0x14)]},
		}
	}

	return data.KeyBindings{
		CharacterScreen: data.KeyBinding{
			Key1: [2]byte{blob[0x00], blob[0x01]},
			Key2: [2]byte{blob[0xa], blob[0xb]},
		},
		Inventory: data.KeyBinding{
			Key1: [2]byte{blob[0x14], blob[0x15]},
			Key2: [2]byte{blob[0x1e], blob[0x1f]},
		},
		HoradricCube: data.KeyBinding{
			Key1: [2]byte{blob[0x4b0], blob[0x4b1]},
			Key2: [2]byte{blob[0x4ba], blob[0x4bb]},
		},
		PartyScreen: data.KeyBinding{
			Key1: [2]byte{blob[0x28], blob[0x29]},
			Key2: [2]byte{blob[0x32], blob[0x33]},
		},
		MercenaryScreen: data.KeyBinding{
			Key1: [2]byte{blob[0x438], blob[0x439]},
			Key2: [2]byte{blob[0x442], blob[0x443]},
		},
		MessageLog: data.KeyBinding{
			Key1: [2]byte{blob[0x3c], blob[0x3d]},
			Key2: [2]byte{blob[0x46], blob[0x47]},
		},
		QuestLog: data.KeyBinding{
			Key1: [2]byte{blob[0x50], blob[0x51]},
			Key2: [2]byte{blob[0x5a], blob[0x5b]},
		},
		HelpScreen: data.KeyBinding{
			Key1: [2]byte{blob[0x78], blob[0x79]},
			Key2: [2]byte{blob[0x82], blob[0x83]},
		},
		SkillTree: data.KeyBinding{
			Key1: [2]byte{blob[0xf0], blob[0xf1]},
			Key2: [2]byte{blob[0xfa], blob[0xfb]},
		},
		SkillSpeedBar: data.KeyBinding{
			Key1: [2]byte{blob[0x104], blob[0x105]},
			Key2: [2]byte{blob[0x10e], blob[0x10f]},
		},
		Skills: skillsKB,
		SelectPreviousSkill: data.KeyBinding{
			Key1: [2]byte{blob[0x2f8], blob[0x2f9]},
			Key2: [2]byte{blob[0x302], blob[0x303]},
		},
		SelectNextSkill: data.KeyBinding{
			Key1: [2]byte{blob[0x30c], blob[0x30d]},
			Key2: [2]byte{blob[0x316], blob[0x317]},
		},
		ShowBelt: data.KeyBinding{
			Key1: [2]byte{blob[0x1a4], blob[0x1a5]},
			Key2: [2]byte{blob[0x1ae], blob[0x1af]},
		},
		UseBelt: belt,
		SwapWeapons: data.KeyBinding{
			Key1: [2]byte{blob[0x35c], blob[0x35d]},
			Key2: [2]byte{blob[0x366], blob[0x367]},
		},
		Chat: data.KeyBinding{
			Key1: [2]byte{blob[0x64], blob[0x65]},
			Key2: [2]byte{blob[0x6e], blob[0x6f]},
		},
		Run: data.KeyBinding{
			Key1: [2]byte{blob[0x294], blob[0x295]},
			Key2: [2]byte{blob[0x29e], blob[0x29f]},
		},
		ToggleRunWalk: data.KeyBinding{
			Key1: [2]byte{blob[0x2a8], blob[0x2a9]},
			Key2: [2]byte{blob[0x2b2], blob[0x2b3]},
		},
		StandStill: data.KeyBinding{
			Key1: [2]byte{blob[0x2bc], blob[0x2bd]},
			Key2: [2]byte{blob[0x2c6], blob[0x2c7]},
		},
		ForceMove: data.KeyBinding{
			Key1: [2]byte{blob[0x49c], blob[0x49d]},
			Key2: [2]byte{blob[0x4a6], blob[0x4a7]},
		},
		ShowItems: data.KeyBinding{
			Key1: [2]byte{blob[0x2d0], blob[0x2d1]},
			Key2: [2]byte{blob[0x2da], blob[0x2db]},
		},
		ShowPortraits: data.KeyBinding{
			Key1: [2]byte{blob[0x348], blob[0x349]},
			Key2: [2]byte{blob[0x352], blob[0x353]},
		},
		Automap: data.KeyBinding{
			Key1: [2]byte{blob[0x8c], blob[0x8d]},
			Key2: [2]byte{blob[0x96], blob[0x97]},
		},
		CenterAutomap: data.KeyBinding{
			Key1: [2]byte{blob[0xa0], blob[0xa1]},
			Key2: [2]byte{blob[0xaa], blob[0xab]},
		},
		FadeAutomap: data.KeyBinding{
			Key1: [2]byte{blob[0xb4], blob[0xb5]},
			Key2: [2]byte{blob[0xbe], blob[0xbf]},
		},
		PartyOnAutomap: data.KeyBinding{
			Key1: [2]byte{blob[0xc8], blob[0xc9]},
			Key2: [2]byte{blob[0xd2], blob[0xd3]},
		},
		NamesOnAutomap: data.KeyBinding{
			Key1: [2]byte{blob[0xdc], blob[0xdd]},
			Key2: [2]byte{blob[0xe6], blob[0xe7]},
		},
		ToggleMiniMap: data.KeyBinding{
			Key1: [2]byte{blob[0x370], blob[0x371]},
			Key2: [2]byte{blob[0x37a], blob[0x37b]},
		},
		SayHelp: data.KeyBinding{
			Key1: [2]byte{blob[0x208], blob[0x209]},
			Key2: [2]byte{blob[0x212], blob[0x213]},
		},
		SayFollowMe: data.KeyBinding{
			Key1: [2]byte{blob[0x21c], blob[0x21d]},
			Key2: [2]byte{blob[0x226], blob[0x227]},
		},
		SayThisIsForYou: data.KeyBinding{
			Key1: [2]byte{blob[0x230], blob[0x231]},
			Key2: [2]byte{blob[0x23a], blob[0x23b]},
		},
		SayThanks: data.KeyBinding{
			Key1: [2]byte{blob[0x244], blob[0x245]},
			Key2: [2]byte{blob[0x24e], blob[0x24f]},
		},
		SaySorry: data.KeyBinding{
			Key1: [2]byte{blob[0x258], blob[0x259]},
			Key2: [2]byte{blob[0x262], blob[0x263]},
		},
		SayBye: data.KeyBinding{
			Key1: [2]byte{blob[0x26c], blob[0x26d]},
			Key2: [2]byte{blob[0x276], blob[0x277]},
		},
		SayNowYouDie: data.KeyBinding{
			Key1: [2]byte{blob[0x280], blob[0x281]},
			Key2: [2]byte{blob[0x28a], blob[0x28b]},
		},
		SayRetreat: data.KeyBinding{
			Key1: [2]byte{blob[0x44c], blob[0x44d]},
			Key2: [2]byte{blob[0x456], blob[0x457]},
		},
		ClearScreen: data.KeyBinding{
			Key1: [2]byte{blob[0x2e4], blob[0x2e5]},
			Key2: [2]byte{blob[0x2ee], blob[0x2ef]},
		},
		ClearMessages: data.KeyBinding{
			Key1: [2]byte{blob[0x320], blob[0x321]},
			Key2: [2]byte{blob[0x32a], blob[0x32b]},
		},
		Zoom: data.KeyBinding{
			Key1: [2]byte{blob[0x474], blob[0x475]},
			Key2: [2]byte{blob[0x47e], blob[0x47f]},
		},
		LegacyToggle: data.KeyBinding{
			Key1: [2]byte{blob[0x488], blob[0x489]},
			Key2: [2]byte{blob[0x492], blob[0x493]},
		},
	}
}

// readKeyBindingBlobs finds and reads the keybinding data blobs.
// First tries hardcoded offsets, then scans memory to find them.
func (gd *GameReader) readKeyBindingBlobs() (blob []byte, blobSkills []byte) {
	initD2goLog()

	// Try hardcoded offsets first
	blobAddr := gd.moduleBaseAddressPtr + 0x1DFFAF4
	blobSkillsAddr := gd.moduleBaseAddressPtr + 0x2228030

	// If we previously found the correct offsets via scanning, use those
	if cachedBlobOffset != 0 {
		blobAddr = gd.moduleBaseAddressPtr + cachedBlobOffset
		blobSkillsAddr = gd.moduleBaseAddressPtr + cachedBlobSkillOffset
	}

	blob = gd.ReadBytesFromMemory(blobAddr, 0x500)
	blobSkills = gd.ReadBytesFromMemory(blobSkillsAddr, 0x500)

	// Check if blob has any non-zero data
	allZero := true
	for _, b := range blob[:64] {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		// Try in-process read at current addresses
		if inBlob, err := gd.Process.readMemoryViaRemoteThread(blobAddr, 0x500); err == nil {
			hasData := false
			for _, b := range inBlob[:64] {
				if b != 0 {
					hasData = true
					break
				}
			}
			if hasData {
				blob = inBlob
				allZero = false
			}
		}
		if !allZero {
			if inSkills, err := gd.Process.readMemoryViaRemoteThread(blobSkillsAddr, 0x500); err == nil {
				blobSkills = inSkills
			}
		}
	}

	// If still all zeros, try scanning for the keybinding blob
	if allZero && !kbScanDone {
		kbScanDone = true
		log.Printf("[d2go] KeyBindings: scanning memory for keybinding blob...")
		if foundOffset := gd.scanForKeyBindingBlob(); foundOffset != 0 {
			cachedBlobOffset = foundOffset
			// blobSkills is typically 0x42D53C bytes after blob in the data section
			// Original: blobSkillsAddr - blobAddr = 0x2228030 - 0x1DFFAF4 = 0x42853C
			cachedBlobSkillOffset = foundOffset + 0x42853C
			blobAddr = gd.moduleBaseAddressPtr + cachedBlobOffset
			blobSkillsAddr = gd.moduleBaseAddressPtr + cachedBlobSkillOffset
			log.Printf("[d2go] KeyBindings: found blob at offset 0x%X, skills at offset 0x%X", cachedBlobOffset, cachedBlobSkillOffset)

			blob = gd.ReadBytesFromMemory(blobAddr, 0x500)
			blobSkills = gd.ReadBytesFromMemory(blobSkillsAddr, 0x500)

			// Try in-process if external fails
			isZero := true
			for _, b := range blob[:64] {
				if b != 0 {
					isZero = false
					break
				}
			}
			if isZero {
				if inBlob, err := gd.Process.readMemoryViaRemoteThread(blobAddr, 0x500); err == nil {
					blob = inBlob
				}
				if inSkills, err := gd.Process.readMemoryViaRemoteThread(blobSkillsAddr, 0x500); err == nil {
					blobSkills = inSkills
				}
			}
			log.Printf("[d2go] KeyBindings: after scan, first 32 bytes: %02X", blob[:32])
		} else {
			log.Printf("[d2go] KeyBindings: scan found nothing, using defaults")
			blob = gd.buildDefaultKeyBindingBlob()
			blobSkills = make([]byte, 0x500) // No skill bindings
		}
	} else if allZero && kbScanDone && cachedBlobOffset == 0 {
		// Already scanned and failed, use defaults
		blob = gd.buildDefaultKeyBindingBlob()
		blobSkills = make([]byte, 0x500)
	}

	// Debug: log skill IDs (first time only)
	if cachedBlobOffset != 0 || !allZero {
		for i := 0; i < 16; i++ {
			if i*0x1c+4 > len(blobSkills) {
				break
			}
			sid := binary.LittleEndian.Uint32(blobSkills[i*0x1c : i*0x1c+4])
			if sid != 0 && sid != 0xFFFFFFFF {
				log.Printf("[d2go] KeyBinding slot %d: skillID=%d", i, sid)
			}
		}
	}

	return blob, blobSkills
}

// scanForKeyBindingBlob scans the D2R module memory to find the keybinding data blob.
// It looks for a region where belt keys (default 1,2,3,4) appear at the expected
// offsets with 0x14-byte stride, which is a distinctive pattern.
func (gd *GameReader) scanForKeyBindingBlob() uintptr {
	// Belt keys are at blob+0x1B8, with stride 0x14 (20 bytes) for keys 1-4 (0x31-0x34)
	// We scan the data section of the module for this pattern
	const blobSize = 0x500
	const beltOffset = 0x1B8
	const stride = 0x14

	// Scan range: the data section is typically in the second half of the module
	scanStart := uintptr(0x1800000)
	scanEnd := uintptr(gd.Process.moduleBaseSize) - uintptr(blobSize)
	if scanEnd < scanStart {
		scanEnd = uintptr(gd.Process.moduleBaseSize) - uintptr(blobSize)
		scanStart = 0
	}

	// Read memory page by page and scan
	pageSize := uintptr(4096)
	for offset := scanStart; offset < scanEnd; offset += pageSize {
		readSize := pageSize + uintptr(blobSize) // read extra to cover blob spanning pages
		if offset+readSize > uintptr(gd.Process.moduleBaseSize) {
			readSize = uintptr(gd.Process.moduleBaseSize) - offset
		}

		addr := gd.moduleBaseAddressPtr + offset
		data := gd.ReadBytesFromMemory(addr, uint(readSize))
		if len(data) < blobSize {
			continue
		}

		// Scan this page for the belt key pattern
		limit := len(data) - blobSize
		for i := 0; i < limit; i++ {
			// Check belt keys at expected offsets: 1,2,3,4 (0x31-0x34)
			if data[i+beltOffset] == 0x31 &&
				data[i+beltOffset+stride] == 0x32 &&
				data[i+beltOffset+2*stride] == 0x33 &&
				data[i+beltOffset+3*stride] == 0x34 {

				// Additional validation: check other well-known default keybindings
				// StandStill at 0x2BC should be Shift (0x10)
				// Run at 0x294 should be 'R' (0x52) or Ctrl...
				// Chat at 0x64 should be Enter (0x0D)
				chatKey := data[i+0x64]
				standStill := data[i+0x2BC]

				// At least one more match for confirmation
				if chatKey == 0x0D || standStill == 0x10 {
					foundOffset := offset + uintptr(i)
					log.Printf("[d2go] KeyBindings scan: found candidate at module+0x%X (belt=1234, chat=0x%02X, standStill=0x%02X)",
						foundOffset, chatKey, standStill)
					return foundOffset
				}
			}
		}
	}

	// Fallback: try in-process scan
	log.Printf("[d2go] KeyBindings scan: external scan failed, trying in-process...")
	// Try reading via remote thread at various offsets around the old address
	for delta := int(-0x200000); delta <= 0x200000; delta += 0x1000 {
		testOffset := uintptr(int(0x1DFFAF4) + delta)
		if testOffset >= uintptr(gd.Process.moduleBaseSize) {
			continue
		}
		addr := gd.moduleBaseAddressPtr + testOffset
		testData, err := gd.Process.readMemoryViaRemoteThread(addr, 0x500)
		if err != nil {
			continue
		}

		// Check belt keys
		if len(testData) >= blobSize &&
			testData[beltOffset] == 0x31 &&
			testData[beltOffset+stride] == 0x32 &&
			testData[beltOffset+2*stride] == 0x33 &&
			testData[beltOffset+3*stride] == 0x34 {

			log.Printf("[d2go] KeyBindings scan: found via in-process at module+0x%X", testOffset)
			return testOffset
		}
	}

	return 0
}

// buildDefaultKeyBindingBlob creates a keybinding blob with D2R default keybindings.
// This is used as a fallback when the actual keybinding data cannot be found in memory.
func (gd *GameReader) buildDefaultKeyBindingBlob() []byte {
	blob := make([]byte, 0x500)

	// Set default keybindings (D2R defaults)
	// Each entry is 20 (0x14) bytes: Key1[2] + padding[8] + Key2[2] + padding[8]
	setKey := func(offset int, key byte) {
		if offset < len(blob) {
			blob[offset] = key
		}
	}

	setKey(0x00, 0x43)  // CharacterScreen: C
	setKey(0x14, 0x49)  // Inventory: I
	setKey(0x28, 0x50)  // PartyScreen: P
	setKey(0x3C, 0x4D)  // MessageLog: M  (not standard but common)
	setKey(0x50, 0x51)  // QuestLog: Q
	setKey(0x64, 0x0D)  // Chat: Enter
	setKey(0x78, 0x48)  // HelpScreen: H
	setKey(0x8C, 0x09)  // Automap: Tab
	setKey(0xF0, 0x54)  // SkillTree: T
	setKey(0x1B8, 0x31) // Belt1: 1
	setKey(0x1CC, 0x32) // Belt2: 2
	setKey(0x1E0, 0x33) // Belt3: 3
	setKey(0x1F4, 0x34) // Belt4: 4
	setKey(0x294, 0x52) // Run: R
	setKey(0x2BC, 0x10) // StandStill: Shift
	setKey(0x2D0, 0x57) // ShowItems: W  (Alt in classic, W in D2R)
	setKey(0x49C, 0x00) // ForceMove: unset by default

	log.Printf("[d2go] KeyBindings: using DEFAULT keybindings (belt=1234, chat=Enter, standStill=Shift)")

	return blob
}
