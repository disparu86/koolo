package memory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const moduleName = "d2r.exe"

var debugPrivilegeEnabled bool

// enableDebugPrivilege enables SeDebugPrivilege for the current process.
// This allows reading protected process memory even with anti-cheat.
func enableDebugPrivilege() error {
	if debugPrivilegeEnabled {
		return nil
	}

	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	seDebug, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	err = windows.LookupPrivilegeValue(nil, seDebug, &luid)
	if err != nil {
		return fmt.Errorf("LookupPrivilegeValue: %w", err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	tp.Privileges[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}

	err = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	if err != nil {
		return fmt.Errorf("AdjustTokenPrivileges: %w", err)
	}

	debugPrivilegeEnabled = true
	log.Printf("[d2go] SeDebugPrivilege enabled successfully")
	return nil
}

type Process struct {
	handler              windows.Handle
	pid                  uint32
	moduleBaseAddressPtr uintptr
	moduleBaseSize       uint32
}

const (
	Int8  = 1 // signed 8-bit integer
	Int16 = 2 // signed 16-bit integer
	Int32 = 4 // signed 32-bit integer
	Int64 = 8 // signed 64-bit integer
)

func NewProcess() (Process, error) {
	enableDebugPrivilege() // Best-effort, ignore error

	module, err := getGameModule()
	if err != nil {
		return Process{}, err
	}

	// Use PROCESS_ALL_ACCESS (0x1F0FFF) for full access to protected memory pages
	h, err := windows.OpenProcess(0x1F0FFF, false, module.ProcessID)
	if err != nil {
		return Process{}, err
	}

	return Process{
		handler:              h,
		pid:                  module.ProcessID,
		moduleBaseAddressPtr: module.ModuleBaseAddress,
		moduleBaseSize:       module.ModuleBaseSize,
	}, nil
}

func NewProcessForPID(pid uint32) (Process, error) {
	enableDebugPrivilege() // Best-effort, ignore error

	module, found := getMainModule(pid)
	if !found {
		return Process{}, errors.New("no module found for the specified PID")
	}

	// Use PROCESS_ALL_ACCESS (0x1F0FFF) for full access to protected memory pages
	h, err := windows.OpenProcess(0x1F0FFF, false, module.ProcessID)
	if err != nil {
		return Process{}, err
	}

	return Process{
		handler:              h,
		pid:                  module.ProcessID,
		moduleBaseAddressPtr: module.ModuleBaseAddress,
		moduleBaseSize:       module.ModuleBaseSize,
	}, nil
}

func (p Process) Close() error {
	return windows.CloseHandle(p.handler)
}

func getGameModule() (ModuleInfo, error) {
	processes := make([]uint32, 2048)
	length := uint32(0)
	err := windows.EnumProcesses(processes, &length)
	if err != nil {
		return ModuleInfo{}, err
	}

	for _, process := range processes {
		module, found := getMainModule(process)
		if found {
			return module, nil
		}
	}

	return ModuleInfo{}, err
}

func getMainModule(pid uint32) (ModuleInfo, bool) {
	mi, err := GetProcessModules(pid)
	if err != nil {
		return ModuleInfo{}, false
	}
	for _, m := range mi {
		if strings.Contains(strings.ToLower(m.ModuleName), moduleName) {
			return m, true
		}
	}

	return ModuleInfo{}, false
}


// D2RExePath is kept for compatibility but D2R.exe is encrypted on disk.
var D2RExePath string

var (
	procVirtualAllocEx    = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualAllocEx")
	procVirtualFreeEx     = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualFreeEx")
	procCreateRemoteThread = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateRemoteThread")
)

func (p Process) getProcessMemory() ([]byte, error) {
	totalSize := uintptr(p.moduleBaseSize)
	data := make([]byte, totalSize)

	// Strategy 1: Try reading the entire module at once (fast path).
	err := windows.ReadProcessMemory(p.handler, p.moduleBaseAddressPtr, &data[0], totalSize, nil)
	if err == nil {
		return data, nil
	}

	// Strategy 2: Try to unprotect pages via remote thread calling VirtualProtect
	// from within D2R's process. kernel32.dll is at the same address in all processes.
	p.tryUnprotectPages()

	// Strategy 3: Page-by-page brute force read.
	const pageSize = uintptr(4096)
	pagesOK := 0
	pagesFailed := 0
	for offset := uintptr(0); offset < totalSize; offset += pageSize {
		readSize := pageSize
		if offset+readSize > totalSize {
			readSize = totalSize - offset
		}
		if windows.ReadProcessMemory(p.handler, p.moduleBaseAddressPtr+offset, &data[offset], readSize, nil) == nil {
			pagesOK++
		} else {
			pagesFailed++
		}
	}
	totalPages := pagesOK + pagesFailed
	log.Printf("[d2go] Page-by-page read: ok=%d, failed=%d, total=%d (%.1f%% readable)",
		pagesOK, pagesFailed, totalPages, float64(pagesOK)/float64(totalPages)*100)

	return data, nil
}

// tryUnprotectPages uses a remote thread to call VirtualProtect on each page
// of D2R's module from within the D2R process. This may allow reading pages
// that are protected against external ReadProcessMemory.
func (p Process) tryUnprotectPages() {
	// Get VirtualProtect address from our own kernel32.dll.
	// kernel32.dll is loaded at the same base address in all processes.
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		log.Printf("[d2go] Failed to load kernel32.dll: %v", err)
		return
	}
	vpProc, err := kernel32.FindProc("VirtualProtect")
	if err != nil {
		log.Printf("[d2go] Failed to find VirtualProtect: %v", err)
		return
	}
	vpAddr := vpProc.Addr()
	log.Printf("[d2go] VirtualProtect address: 0x%X", vpAddr)

	totalSize := uintptr(p.moduleBaseSize)

	// Shellcode: loop through pages, call VirtualProtect(page, 4096, PAGE_EXECUTE_READWRITE, &oldProtect)
	// RCX = pointer to params struct:
	//   [0]  baseAddr (uint64)
	//   [8]  totalSize (uint64)
	//   [16] vpAddr (uint64)
	//   [24] oldProtect (uint32) - scratch space
	shellcode := []byte{
		0x53,                                           // push rbx
		0x41, 0x54,                                     // push r12
		0x41, 0x55,                                     // push r13
		0x41, 0x56,                                     // push r14
		0x41, 0x57,                                     // push r15
		0x48, 0x83, 0xEC, 0x30,                         // sub rsp, 0x30
		0x4C, 0x8B, 0x21,                               // mov r12, [rcx]       ; baseAddr
		0x4C, 0x8B, 0x69, 0x08,                         // mov r13, [rcx+8]     ; totalSize
		0x4C, 0x8B, 0x71, 0x10,                         // mov r14, [rcx+16]    ; VirtualProtect addr
		0x4C, 0x8D, 0x79, 0x18,                         // lea r15, [rcx+24]    ; &oldProtect
		0x31, 0xDB,                                     // xor ebx, ebx         ; offset = 0
		// .loop:
		0x49, 0x3B, 0xDD,                               // cmp rbx, r13
		0x7D, 0x1E,                                     // jge .done (+30)
		0x49, 0x8D, 0x0C, 0x1C,                         // lea rcx, [r12+rbx]   ; lpAddress
		0xBA, 0x00, 0x10, 0x00, 0x00,                   // mov edx, 0x1000      ; dwSize = 4096
		0x41, 0xB8, 0x40, 0x00, 0x00, 0x00,             // mov r8d, 0x40        ; PAGE_EXECUTE_READWRITE
		0x4D, 0x89, 0xF9,                               // mov r9, r15          ; lpflOldProtect
		0x41, 0xFF, 0xD6,                               // call r14             ; VirtualProtect
		0x48, 0x81, 0xC3, 0x00, 0x10, 0x00, 0x00,       // add rbx, 0x1000
		0xEB, 0xDD,                                     // jmp .loop (-35)
		// .done:
		0x48, 0x83, 0xC4, 0x30,                         // add rsp, 0x30
		0x41, 0x5F,                                     // pop r15
		0x41, 0x5E,                                     // pop r14
		0x41, 0x5D,                                     // pop r13
		0x41, 0x5C,                                     // pop r12
		0x5B,                                           // pop rbx
		0x31, 0xC0,                                     // xor eax, eax
		0xC3,                                           // ret
	}

	// Layout: [shellcode][padding][params]
	const scOffset = uintptr(0)
	const paramOffset = uintptr(0x60) // align params after shellcode
	allocSize := paramOffset + 32      // 32 bytes for params struct

	remoteAddr, _, allocErr := procVirtualAllocEx.Call(
		uintptr(p.handler), 0, allocSize, 0x3000, 0x40, // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
	)
	if remoteAddr == 0 {
		log.Printf("[d2go] VirtualAllocEx for unprotect failed: %v", allocErr)
		return
	}
	defer procVirtualFreeEx.Call(uintptr(p.handler), remoteAddr, 0, 0x8000)

	// Write shellcode
	if err := windows.WriteProcessMemory(p.handler, remoteAddr+scOffset, &shellcode[0], uintptr(len(shellcode)), nil); err != nil {
		log.Printf("[d2go] WriteProcessMemory (shellcode): %v", err)
		return
	}

	// Write params: {baseAddr, totalSize, vpAddr, oldProtect(scratch)}
	params := make([]byte, 32)
	binary.LittleEndian.PutUint64(params[0:8], uint64(p.moduleBaseAddressPtr))
	binary.LittleEndian.PutUint64(params[8:16], uint64(totalSize))
	binary.LittleEndian.PutUint64(params[16:24], uint64(vpAddr))
	// params[24:28] = oldProtect scratch, leave as 0

	if err := windows.WriteProcessMemory(p.handler, remoteAddr+paramOffset, &params[0], uintptr(len(params)), nil); err != nil {
		log.Printf("[d2go] WriteProcessMemory (params): %v", err)
		return
	}

	// Execute shellcode via remote thread
	threadHandle, _, threadErr := procCreateRemoteThread.Call(
		uintptr(p.handler), 0, 0,
		remoteAddr+scOffset,    // start address
		remoteAddr+paramOffset, // parameter (RCX)
		0, 0,
	)
	if threadHandle == 0 {
		log.Printf("[d2go] CreateRemoteThread for unprotect failed: %v", threadErr)
		return
	}
	defer windows.CloseHandle(windows.Handle(threadHandle))

	// Wait up to 30 seconds
	event, waitErr := windows.WaitForSingleObject(windows.Handle(threadHandle), 30000)
	if event != 0 || waitErr != nil {
		log.Printf("[d2go] Unprotect thread wait failed: event=%d err=%v", event, waitErr)
		return
	}

	// Check exit code
	var exitCode uint32
	procGetExitCodeThread := syscall.NewLazyDLL("kernel32.dll").NewProc("GetExitCodeThread")
	procGetExitCodeThread.Call(threadHandle, uintptr(unsafe.Pointer(&exitCode)))
	log.Printf("[d2go] Unprotect thread completed, exit code: %d", exitCode)
}


// searchPatternViaRemoteThread searches for a byte pattern inside D2R's process
// memory by injecting shellcode that runs within the process itself. This bypasses
// anti-cheat that blocks external ReadProcessMemory on certain code pages.
// pattern: the bytes to search for (up to 16 bytes)
// mask: 0xFF = must match, 0x00 = wildcard (must be same length as pattern)
// valueReadOffset: signed offset from pattern start to read a 4-byte value
// Returns: offset from module base, the 4-byte value, and whether the pattern was found.
func (p Process) searchPatternViaRemoteThread(pattern []byte, mask []byte, valueReadOffset int) (foundOffset uintptr, value uint32, found bool) {
	if len(pattern) == 0 || len(pattern) > 16 || len(pattern) != len(mask) {
		return 0, 0, false
	}

	// x64 shellcode: searches through module memory for a pattern with mask support.
	// RCX = pointer to params struct (see layout below).
	// Compares each byte position against pattern, skipping wildcards (mask==0).
	// When found, writes the offset and reads a 4-byte value at pattern+valueReadOffset.
	shellcode := []byte{
		// Prologue: save non-volatile registers
		0x53,             // push rbx
		0x55,             // push rbp
		0x56,             // push rsi
		0x57,             // push rdi
		0x41, 0x54,       // push r12
		0x41, 0x55,       // push r13
		0x41, 0x56,       // push r14
		0x41, 0x57,       // push r15
		0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28  (shadow space, 16-byte aligned)

		// Load params from RCX
		0x4C, 0x8B, 0x21,             // mov r12, [rcx]       ; baseAddr
		0x4C, 0x8B, 0x69, 0x08,       // mov r13, [rcx+8]     ; totalSize
		0x4C, 0x8B, 0x71, 0x10,       // mov r14, [rcx+16]    ; patternLen
		0x48, 0x8D, 0x71, 0x18,       // lea rsi, [rcx+24]    ; pattern data
		0x48, 0x8D, 0x79, 0x28,       // lea rdi, [rcx+40]    ; mask data
		0x48, 0x8B, 0x69, 0x38,       // mov rbp, [rcx+56]    ; valueReadOffset (signed)
		0x4C, 0x8D, 0x79, 0x40,       // lea r15, [rcx+64]    ; &output

		// Initialize output: foundOffset = -1
		0x49, 0xC7, 0x07, 0xFF, 0xFF, 0xFF, 0xFF, // mov qword [r15], -1
		// Initialize output: value = 0
		0x41, 0xC7, 0x47, 0x08, 0x00, 0x00, 0x00, 0x00, // mov dword [r15+8], 0

		// maxOffset = totalSize - patternLen
		0x4D, 0x29, 0xF5, // sub r13, r14

		// offset = 0
		0x31, 0xDB, // xor ebx, ebx

		// .loop:
		0x49, 0x3B, 0xDD,       // cmp rbx, r13
		0x7D, 0x36,             // jge .done  (offset calculated below)

		// lea rax, [r12+rbx]   ; current memory position
		0x49, 0x8D, 0x04, 0x1C, // lea rax, [r12+rbx]
		// xor ecx, ecx         ; pattern index = 0
		0x31, 0xC9,

		// .inner:
		0x49, 0x3B, 0xCE,       // cmp rcx, r14
		0x7D, 0x14,             // jge .found

		// Check mask: if mask[idx]==0, skip comparison (wildcard)
		0x8A, 0x14, 0x0F,       // mov dl, [rdi+rcx]
		0x84, 0xD2,             // test dl, dl
		0x74, 0x08,             // jz .skip_match

		// Compare memory byte with pattern byte
		0x8A, 0x14, 0x08,       // mov dl, [rax+rcx]
		0x3A, 0x14, 0x0E,       // cmp dl, [rsi+rcx]
		0x75, 0x17,             // jne .next_offset

		// .skip_match:
		0x48, 0xFF, 0xC1,       // inc rcx
		0xEB, 0xE7,             // jmp .inner

		// .found: pattern matched at offset rbx
		0x49, 0x89, 0x1F,             // mov [r15], rbx          ; foundOffset
		0x49, 0x8D, 0x04, 0x1C,       // lea rax, [r12+rbx]
		0x48, 0x01, 0xE8,             // add rax, rbp            ; + valueReadOffset
		0x8B, 0x00,                   // mov eax, [rax]          ; read 4 bytes
		0x41, 0x89, 0x47, 0x08,       // mov [r15+8], eax        ; store value
		0xEB, 0x05,                   // jmp .done

		// .next_offset:
		0x48, 0xFF, 0xC3, // inc rbx
		0xEB, 0xC5,       // jmp .loop

		// .done: epilogue
		0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
		0x41, 0x5F,             // pop r15
		0x41, 0x5E,             // pop r14
		0x41, 0x5D,             // pop r13
		0x41, 0x5C,             // pop r12
		0x5F,                   // pop rdi
		0x5E,                   // pop rsi
		0x5D,                   // pop rbp
		0x5B,                   // pop rbx
		0x31, 0xC0,             // xor eax, eax
		0xC3,                   // ret
	}

	// Layout in remote memory: [shellcode @ 0x00] [params @ 0xA0]
	const scOffset = uintptr(0)
	const paramOffset = uintptr(0xA0) // 160, well past shellcode
	// Params layout (80 bytes):
	//   [0]  baseAddr         uint64
	//   [8]  totalSize        uint64
	//   [16] patternLen       uint64
	//   [24] pattern[16]      [16]byte
	//   [40] mask[16]         [16]byte
	//   [56] valueReadOffset  int64  (signed)
	//   [64] foundOffset      int64  (output, -1 = not found)
	//   [72] value            uint32 (output)
	//   [76] padding          4 bytes
	const paramsSize = uintptr(80)
	allocSize := paramOffset + paramsSize

	remoteAddr, _, allocErr := procVirtualAllocEx.Call(
		uintptr(p.handler), 0, allocSize, 0x3000, 0x40, // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
	)
	if remoteAddr == 0 {
		log.Printf("[d2go] searchPattern: VirtualAllocEx failed: %v", allocErr)
		return 0, 0, false
	}
	defer procVirtualFreeEx.Call(uintptr(p.handler), remoteAddr, 0, 0x8000)

	// Write shellcode
	if err := windows.WriteProcessMemory(p.handler, remoteAddr+scOffset, &shellcode[0], uintptr(len(shellcode)), nil); err != nil {
		log.Printf("[d2go] searchPattern: WriteProcessMemory (shellcode): %v", err)
		return 0, 0, false
	}

	// Build and write params
	params := make([]byte, paramsSize)
	binary.LittleEndian.PutUint64(params[0:8], uint64(p.moduleBaseAddressPtr))
	binary.LittleEndian.PutUint64(params[8:16], uint64(p.moduleBaseSize))
	binary.LittleEndian.PutUint64(params[16:24], uint64(len(pattern)))
	copy(params[24:24+len(pattern)], pattern)
	copy(params[40:40+len(mask)], mask)
	binary.LittleEndian.PutUint64(params[56:64], uint64(int64(valueReadOffset))) // signed
	// Initialize foundOffset to -1
	binary.LittleEndian.PutUint64(params[64:72], 0xFFFFFFFFFFFFFFFF)

	if err := windows.WriteProcessMemory(p.handler, remoteAddr+paramOffset, &params[0], paramsSize, nil); err != nil {
		log.Printf("[d2go] searchPattern: WriteProcessMemory (params): %v", err)
		return 0, 0, false
	}

	// Execute via remote thread
	threadHandle, _, threadErr := procCreateRemoteThread.Call(
		uintptr(p.handler), 0, 0,
		remoteAddr+scOffset,     // start address
		remoteAddr+paramOffset,  // parameter (RCX)
		0, 0,
	)
	if threadHandle == 0 {
		log.Printf("[d2go] searchPattern: CreateRemoteThread failed: %v", threadErr)
		return 0, 0, false
	}
	defer windows.CloseHandle(windows.Handle(threadHandle))

	// Wait up to 60 seconds (scanning ~41MB byte-by-byte)
	event, waitErr := windows.WaitForSingleObject(windows.Handle(threadHandle), 60000)
	if event != 0 || waitErr != nil {
		log.Printf("[d2go] searchPattern: thread wait failed: event=%d err=%v", event, waitErr)
		return 0, 0, false
	}

	// Check exit code
	var exitCode uint32
	procGetExitCodeThread := syscall.NewLazyDLL("kernel32.dll").NewProc("GetExitCodeThread")
	procGetExitCodeThread.Call(threadHandle, uintptr(unsafe.Pointer(&exitCode)))
	log.Printf("[d2go] searchPattern: thread completed, exit code: %d", exitCode)

	// Read back results
	resultBuf := make([]byte, 12) // 8 bytes foundOffset + 4 bytes value
	if err := windows.ReadProcessMemory(p.handler, remoteAddr+paramOffset+64, &resultBuf[0], 12, nil); err != nil {
		log.Printf("[d2go] searchPattern: ReadProcessMemory (results): %v", err)
		return 0, 0, false
	}

	resultOffset := int64(binary.LittleEndian.Uint64(resultBuf[0:8]))
	resultValue := binary.LittleEndian.Uint32(resultBuf[8:12])

	if resultOffset == -1 {
		log.Printf("[d2go] searchPattern: pattern not found in process memory")
		return 0, 0, false
	}

	log.Printf("[d2go] searchPattern: FOUND at offset 0x%X, value=0x%X", resultOffset, resultValue)
	return uintptr(resultOffset), resultValue, true
}

// buildMaskFromString converts a mask string like "xxx????xxx" to byte mask
// where 'x' = 0xFF (must match) and '?' = 0x00 (wildcard).
func buildMaskFromString(maskStr string) []byte {
	mask := make([]byte, len(maskStr))
	for i, c := range maskStr {
		if c == 'x' {
			mask[i] = 0xFF
		}
		// '?' stays 0x00
	}
	return mask
}

// readMemoryViaRemoteThread reads memory from inside the target process using
// CreateRemoteThread. This bypasses ReadProcessMemory protections (anti-cheat)
// by executing a simple memcpy shellcode inside the game process.
// srcAddr is the absolute address to read from. size is the number of bytes to read (max 4096).
func (p Process) readMemoryViaRemoteThread(srcAddr uintptr, size int) ([]byte, error) {
	if size <= 0 || size > 4096 {
		return nil, fmt.Errorf("invalid size %d (must be 1-4096)", size)
	}

	// x64 shellcode: copies 'size' bytes from srcAddr to outputBuf.
	// RCX = pointer to params struct.
	// Params layout:
	//   [0]  srcAddr    uint64
	//   [8]  size       uint64
	//   [16] outputBuf  [size]byte (output)
	shellcode := []byte{
		// Prologue
		0x56,                         // push rsi
		0x57,                         // push rdi
		0x48, 0x83, 0xEC, 0x28,       // sub rsp, 0x28

		// Load params
		0x48, 0x8B, 0x31,             // mov rsi, [rcx]       ; srcAddr
		0x48, 0x8B, 0x49, 0x08,       // mov rcx_val, [rcx+8] ; size -> we'll use it
		0x48, 0x8D, 0x79, 0x10,       // lea rdi, [rcx+16]    ; outputBuf

		// Save size in rcx for rep movsb
		// rcx already has [rcx+8] but we need the params ptr first
		// Let me redo this more carefully:
	}

	// Actually, let me write cleaner shellcode
	shellcode = []byte{
		// Prologue
		0x53,                         // push rbx
		0x56,                         // push rsi
		0x57,                         // push rdi
		0x48, 0x83, 0xEC, 0x20,       // sub rsp, 0x20

		// RCX = params ptr
		0x48, 0x8B, 0xD9,             // mov rbx, rcx         ; save params ptr
		0x48, 0x8B, 0x73, 0x00,       // mov rsi, [rbx]       ; srcAddr
		0x48, 0x8B, 0x4B, 0x08,       // mov rcx, [rbx+8]     ; size (count for rep movsb)
		0x48, 0x8D, 0x7B, 0x10,       // lea rdi, [rbx+16]    ; outputBuf

		// rep movsb: copies rcx bytes from [rsi] to [rdi]
		0xF3, 0xA4,                   // rep movsb

		// Epilogue
		0x48, 0x83, 0xC4, 0x20,       // add rsp, 0x20
		0x5F,                         // pop rdi
		0x5E,                         // pop rsi
		0x5B,                         // pop rbx
		0x31, 0xC0,                   // xor eax, eax
		0xC3,                         // ret
	}

	// Layout: [shellcode @ 0x00] [params @ 0x40]
	const scOffset = uintptr(0)
	const paramOffset = uintptr(0x40)
	paramsSize := uintptr(16 + size) // srcAddr(8) + size(8) + outputBuf(size)
	allocSize := paramOffset + paramsSize

	remoteAddr, _, allocErr := procVirtualAllocEx.Call(
		uintptr(p.handler), 0, allocSize, 0x3000, 0x40,
	)
	if remoteAddr == 0 {
		return nil, fmt.Errorf("VirtualAllocEx failed: %v", allocErr)
	}
	defer procVirtualFreeEx.Call(uintptr(p.handler), remoteAddr, 0, 0x8000)

	// Write shellcode
	if err := windows.WriteProcessMemory(p.handler, remoteAddr+scOffset, &shellcode[0], uintptr(len(shellcode)), nil); err != nil {
		return nil, fmt.Errorf("WriteProcessMemory (shellcode): %v", err)
	}

	// Build and write params (just srcAddr and size, output area is zeroed by VirtualAlloc)
	params := make([]byte, 16)
	binary.LittleEndian.PutUint64(params[0:8], uint64(srcAddr))
	binary.LittleEndian.PutUint64(params[8:16], uint64(size))

	if err := windows.WriteProcessMemory(p.handler, remoteAddr+paramOffset, &params[0], 16, nil); err != nil {
		return nil, fmt.Errorf("WriteProcessMemory (params): %v", err)
	}

	// Execute via remote thread
	threadHandle, _, threadErr := procCreateRemoteThread.Call(
		uintptr(p.handler), 0, 0,
		remoteAddr+scOffset,
		remoteAddr+paramOffset,
		0, 0,
	)
	if threadHandle == 0 {
		return nil, fmt.Errorf("CreateRemoteThread failed: %v", threadErr)
	}
	defer windows.CloseHandle(windows.Handle(threadHandle))

	event, waitErr := windows.WaitForSingleObject(windows.Handle(threadHandle), 5000)
	if event != 0 || waitErr != nil {
		return nil, fmt.Errorf("thread wait failed: event=%d err=%v", event, waitErr)
	}

	// Read back the output buffer
	result := make([]byte, size)
	if err := windows.ReadProcessMemory(p.handler, remoteAddr+paramOffset+16, &result[0], uintptr(size), nil); err != nil {
		return nil, fmt.Errorf("ReadProcessMemory (result): %v", err)
	}

	return result, nil
}

func (p Process) ReadBytesFromMemory(address uintptr, size uint) []byte {
	var data = make([]byte, size)
	windows.ReadProcessMemory(p.handler, address, &data[0], uintptr(size), nil)

	return data
}

type IntType uint

const (
	Uint8  = 1
	Uint16 = 2
	Uint32 = 4
	Uint64 = 8
)

func (p Process) ReadUInt(address uintptr, size IntType) uint {
	bytes := p.ReadBytesFromMemory(address, uint(size))

	return bytesToUint(bytes, size)
}

func ReadUIntFromBuffer(bytes []byte, offset uint, size IntType) uint {
	return bytesToUint(bytes[offset:offset+uint(size)], size)
}

func bytesToUint(bytes []byte, size IntType) uint {
	switch size {
	case Uint8:
		return uint(bytes[0])
	case Uint16:
		return uint(binary.LittleEndian.Uint16(bytes))
	case Uint32:
		return uint(binary.LittleEndian.Uint32(bytes))
	case Uint64:
		return uint(binary.LittleEndian.Uint64(bytes))
	}

	return 0
}
func ReadIntFromBuffer(bytes []byte, offset uint, size IntType) int {
	return bytesToInt(bytes[offset:offset+uint(size)], size)
}
func bytesToInt(bytes []byte, size IntType) int {
	switch size {
	case Int8:
		return int(int8(bytes[0]))
	case Int16:
		return int(int16(binary.LittleEndian.Uint16(bytes)))
	case Int32:
		return int(int32(binary.LittleEndian.Uint32(bytes)))
	case Int64:
		return int(int64(binary.LittleEndian.Uint64(bytes)))
	}
	return 0
}

func (p Process) ReadStringFromMemory(address uintptr, size uint) string {
	if size == 0 {
		for i := 1; true; i++ {
			data := p.ReadBytesFromMemory(address, uint(i))
			if data[i-1] == 0 {
				return string(bytes.Trim(data, "\x00"))
			}
		}
	}

	return string(bytes.Trim(p.ReadBytesFromMemory(address, size), "\x00"))
}

func (p Process) findPattern(memory []byte, pattern, mask string) int {
	patternLength := len(pattern)
	for i := 0; i < int(p.moduleBaseSize)-patternLength; i++ {
		found := true
		for j := 0; j < patternLength; j++ {
			if string(mask[j]) != "?" && string(pattern[j]) != string(memory[i+j]) {
				found = false
				break
			}
		}

		if found {
			return i
		}
	}

	return 0
}

func (p Process) FindPattern(memory []byte, pattern, mask string) uintptr {
	if offset := p.findPattern(memory, pattern, mask); offset != 0 {
		return p.moduleBaseAddressPtr + uintptr(offset)
	}

	return 0
}

func (p Process) FindPatternByOperand(memory []byte, pattern, mask string) uintptr {
	if offset := p.findPattern(memory, pattern, mask); offset != 0 {
		// Adjust the address based on the operand value
		operandAddress := p.moduleBaseAddressPtr + uintptr(offset)
		operandValue := binary.LittleEndian.Uint32(memory[offset+3 : offset+7])
		finalAddress := operandAddress + uintptr(operandValue) + 7 // 7 is the length of the instruction
		return finalAddress
	}

	return 0
}

func (p Process) GetPID() uint32 {
	return p.pid
}

type ModuleInfo struct {
	ProcessID         uint32
	ModuleBaseAddress uintptr
	ModuleBaseSize    uint32
	ModuleHandle      syscall.Handle
	ModuleName        string
}

func GetProcessModules(processID uint32) ([]ModuleInfo, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(hProcess)

	var modules [1024]windows.Handle
	var needed uint32
	if err := windows.EnumProcessModules(hProcess, &modules[0], uint32(unsafe.Sizeof(modules[0]))*1024, &needed); err != nil {
		return nil, err
	}
	count := needed / uint32(unsafe.Sizeof(modules[0]))

	var moduleInfos []ModuleInfo
	for i := uint32(0); i < count; i++ {
		var mi windows.ModuleInfo
		if err := windows.GetModuleInformation(hProcess, modules[i], &mi, uint32(unsafe.Sizeof(mi))); err != nil {
			return nil, err
		}

		var moduleName [windows.MAX_PATH]uint16
		if err := windows.GetModuleFileNameEx(hProcess, modules[i], &moduleName[0], windows.MAX_PATH); err != nil {
			return nil, err
		}

		moduleInfos = append(moduleInfos, ModuleInfo{
			ProcessID:         processID,
			ModuleBaseAddress: mi.BaseOfDll,
			ModuleBaseSize:    mi.SizeOfImage,
			ModuleHandle:      syscall.Handle(modules[i]),
			ModuleName:        syscall.UTF16ToString(moduleName[:]),
		})
	}

	return moduleInfos, nil
}

// ReadPointer reads a pointer from the specified memory address.
func (p *Process) ReadPointer(address uintptr, size int) (uintptr, error) {
	buffer := p.ReadBytesFromMemory(address, uint(size))
	if len(buffer) == 0 {
		return 0, errors.New("failed to read memory")
	}

	return uintptr(*(*uint64)(unsafe.Pointer(&buffer[0]))), nil
}

func (p Process) ReadIntoBuffer(address uintptr, buffer []byte) error {
	return windows.ReadProcessMemory(p.handler, address, &buffer[0], uintptr(len(buffer)), nil)
}

// ReadWidgetContainer reads the WidgetContainer structure.
func (p *Process) ReadWidgetContainer(address uintptr, full bool) (map[string]interface{}, error) {
	widgetPtr, err := p.ReadPointer(address+0x8, 8)
	if err != nil {
		return nil, err
	}

	widgetNameLength := p.ReadUInt(address+0x10, 4)

	widgetName := p.ReadStringFromMemory(widgetPtr, uint(widgetNameLength))
	if widgetName == "" {
		return nil, errors.New("failed to read widget name")
	}

	widget_visible := p.ReadUInt(address+0x51, 1) == 1
	widget_active := p.ReadUInt(address+0x50, 1) == 1

	result := map[string]interface{}{
		"WidgetNameString": widgetName,
		"WidgetNameLength": widgetNameLength,
		"WidgetVisible":    widget_visible,
		"WidgetActive":     widget_active,
	}

	if full {
		childWidgetsListPtr, err := p.ReadPointer(widgetPtr+0x38, 8)
		if err != nil {
			return nil, err
		}

		childWidgetSize := p.ReadUInt(widgetPtr+0x40, 4)

		widgetListPtr, err := p.ReadPointer(widgetPtr+0x68, 8)
		if err != nil {
			return nil, err
		}

		widgetListSize := p.ReadUInt(widgetPtr+0x78, 4)

		widgetList2Ptr, err := p.ReadPointer(widgetPtr+0x80, 8)
		if err != nil {
			return nil, err
		}

		widgetList2Size := p.ReadUInt(widgetPtr+0x90, 4)

		result["ChildWidgetsListPointer"] = childWidgetsListPtr
		result["ChildWidgetSize"] = childWidgetSize
		result["WidgetListPointer"] = widgetListPtr
		result["WidgetListSize"] = widgetListSize
		result["WidgetList2Pointer"] = widgetList2Ptr
		result["WidgetList2Size"] = widgetList2Size
	}

	return result, nil
}

// ReadWidgetList iterates through a list of widgets given a pointer to the list and its size.
func (p *Process) ReadWidgetList(listPointer uintptr, listSize int) (map[string]map[string]interface{}, error) {
	widgetMap := make(map[string]map[string]interface{})
	widgetSize := int(unsafe.Sizeof(uintptr(0)))

	for i := 0; i < listSize; i++ {
		widgetAddr, err := p.ReadPointer(listPointer+uintptr(i*widgetSize), 8)
		if err != nil {
			return nil, err
		}

		widgetContainer, err := p.ReadWidgetContainer(widgetAddr, false)
		if err != nil {
			return nil, err
		}

		widgetName, ok := widgetContainer["WidgetNameString"].(string)
		if !ok {
			return nil, errors.New("failed to read widget name")
		}

		widgetMap[widgetName] = widgetContainer
	}

	return widgetMap, nil
}
