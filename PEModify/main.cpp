//#include <winnt.h> // struct descirption at "Image Format"
#include <windows.h>
#include <iostream>
#include "FileMapping.h"
#include "PE.h"
#include <stdio.h>

#define MAGIC_CODE_MARKER 0x12345678

#define GetProcAddressAddress 0x743150B0
#define LoadLibraryAddress 0x74315980
#define GteModuleHandleAAddress 0x74314FB0

__declspec(naked) void injectionCode()
{
	__asm
	{
		push MAGIC_CODE_MARKER
		
		sub esp, 34
		mov ebp, esp

		mov byte ptr[ebp + 0], 'u'
		mov byte ptr[ebp + 1], 's'
		mov byte ptr[ebp + 2], 'e'
		mov byte ptr[ebp + 3], 'r'
		mov byte ptr[ebp + 4], '3'
		mov byte ptr[ebp + 5], '2'
		mov byte ptr[ebp + 6], '.'
		mov byte ptr[ebp + 7], 'd'
		mov byte ptr[ebp + 8], 'l'
		mov byte ptr[ebp + 9], 'l'
		mov byte ptr[ebp + 10], 0

		push ebp
		mov ecx, LoadLibraryAddress // call LoadLibrary
		call ecx

		mov dword ptr [ebp + 24], eax // user32.dll handle

		mov ecx, GteModuleHandleAAddress
		push 0
		call ecx			// call GetProcAddress

		mov dword ptr [ebp + 28], eax // GetModuleHandle return value

		mov byte ptr[ebp + 0], 'C'
		mov byte ptr[ebp + 1], 'r'
		mov byte ptr[ebp + 2], 'e'
		mov byte ptr[ebp + 3], 'a'
		mov byte ptr[ebp + 4], 't'
		mov byte ptr[ebp + 5], 'e'
		mov byte ptr[ebp + 6], 'W'
		mov byte ptr[ebp + 7], 'i'
		mov byte ptr[ebp + 8], 'n'
		mov byte ptr[ebp + 9], 'd'
		mov byte ptr[ebp + 10], 'o'
		mov byte ptr[ebp + 11], 'w'
		mov byte ptr[ebp + 12], 'E'
		mov byte ptr[ebp + 13], 'x'
		mov byte ptr[ebp + 14], 'A'
		mov byte ptr[ebp + 15], 0

		mov byte ptr[ebp + 17], 'b'
		mov byte ptr[ebp + 18], 'u'
		mov byte ptr[ebp + 19], 't'
		mov byte ptr[ebp + 20], 't'
		mov byte ptr[ebp + 21], 'o'
		mov byte ptr[ebp + 22], 'n'
		mov byte ptr[ebp + 23],  0

		push ebp            // function name
		push dword ptr[ebp + 24]  // dllHandle from LoadLibrary
		mov ecx, GetProcAddressAddress
		call ecx			// call GetProcAddress

		push 0
		push dword ptr[ebp + 28]
		push 0
		push 0
		push 0x80000000
		push 0x80000000
		push 0x80000000
		push 0x80000000
		push 0x8160000
		lea ebx, [ebp+17]
		push ebx
		push ebx
		push 0

		call eax
		mov dword ptr[ebp + 32], eax // window handle

		mov byte ptr[ebp + 0], 'S'
		mov byte ptr[ebp + 1], 'h'
		mov byte ptr[ebp + 2], 'o'
		mov byte ptr[ebp + 3], 'w'
		mov byte ptr[ebp + 4], 'W'
		mov byte ptr[ebp + 5], 'i'
		mov byte ptr[ebp + 6], 'n'
		mov byte ptr[ebp + 7], 'd'
		mov byte ptr[ebp + 8], 'o'
		mov byte ptr[ebp + 9], 'w'
		mov byte ptr[ebp + 10], 0

		push ebp            // function name
		push dword ptr[ebp + 24]  // dllHandle from LoadLibrary
		mov ecx, GetProcAddressAddress
		call ecx			// call GetProcAddress

		push SW_SHOWDEFAULT
		push dword ptr[ebp + 32]
		call eax

		add esp, 34

		push MAGIC_CODE_MARKER
	}
}

// calculate function physical location when using incremental linking
uintptr_t functionAddressIncremental(void* funcPointer)
{
	char* funcPointerChar = (char*) funcPointer;

	// AAA is the real address of a function
	// [funcPointer] -> jmp AAA ---- E9 AA AA AA AA

	// omit instruction bytecode, calculate address (sum of jmp argument and instruction address)
	// and add instruction size
	return *((uintptr_t*)(funcPointerChar + 1)) + (uintptr_t)funcPointerChar + 5;;
}

void injectCode(PE& pe, void* injectionCode)
{
	auto* codeSection = pe.findSection(".text");
	auto codePhysicalAddress = pe.offsetToPhysical(codeSection->PointerToRawData);

	auto freeSpace = codeSection->SizeOfRawData - codeSection->Misc.VirtualSize;

	auto codeDestinationPhysical = codePhysicalAddress + codeSection->Misc.VirtualSize;
	auto codeDestinationRVA = codeSection->VirtualAddress + codeSection->Misc.VirtualSize;

	auto codeStart = (uintptr_t) injectionCode;

	while (*((int*) codeStart) != MAGIC_CODE_MARKER)
		codeStart++;

	codeStart += sizeof(MAGIC_CODE_MARKER);

	auto codeEnd = codeStart + 1;
	while (*((int*) codeEnd) != MAGIC_CODE_MARKER)
		codeEnd++;

	codeEnd -= 1; // push instruction size

	auto codeSize = codeEnd - codeStart;

	char jmpBackInstruction[] = "\xE9\x00\x00\x00\x00";
	int* jmpBackAddress = (int*)(jmpBackInstruction + 1);
	auto jmpBackInstructionSize = 5;

	// relative offset to addressOfEntryPoint
	*jmpBackAddress = pe.nt_header->OptionalHeader.AddressOfEntryPoint - 
		(codeDestinationRVA + codeSize + jmpBackInstructionSize);

	if ((codeSize + jmpBackInstructionSize) > freeSpace)
	{
		std::cout << "error: no space\n";
		return;
	}

	memcpy((void*) codeDestinationPhysical, (void*) codeStart, codeSize);
	memcpy((void*) (codeDestinationPhysical + codeSize), jmpBackInstruction,
		jmpBackInstructionSize);

	codeSection->Misc.VirtualSize += codeSize + jmpBackInstructionSize;
	pe.nt_header->OptionalHeader.AddressOfEntryPoint = codeDestinationRVA;
}

int main()
{

	std::string name;

	std::cin >> name;

	FileMapping mapping(name);
	auto base_ptr = mapping.ptr();

	PE pe(base_ptr);

	pe.printImports();
	pe.printSections();

	injectCode(pe, &injectionCode);




	//HWND window = CreateWindowEx(0, "button", "title",
	//	WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
	//	CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, GetModuleHandle(0), 0);
	//if (window)
	//{
	//	ShowWindow(window, SW_SHOWDEFAULT);
	//}
	
}