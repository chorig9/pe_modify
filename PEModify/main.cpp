//#include <winnt.h> // struct descirption at "Image Format"
#include <windows.h>
#include <iostream>
#include "FileMapping.h"
#include "PE.h"
#include <stdio.h>

#define MAGIC_CODE_MARKER 0x12345678

__declspec(naked) void injectionCode()
{
	__asm
	{
		push MAGIC_CODE_MARKER
		
		sub esp, 16
		mov byte ptr[esp + 0], 'u'
		mov byte ptr[esp + 1], 's'
		mov byte ptr[esp + 2], 'e'
		mov byte ptr[esp + 3], 'r'
		mov byte ptr[esp + 4], '3'
		mov byte ptr[esp + 5], '2'
		mov byte ptr[esp + 6], '.'
		mov byte ptr[esp + 7], 'd'
		mov byte ptr[esp + 8], 'l'
		mov byte ptr[esp + 9], 'l'
		mov byte ptr[esp + 10], 0

		mov ebx, esp

		push ebx

		mov ecx, 0x74315980 // call LoadLibrary
		call ecx

		mov byte ptr[esp + 0], 'M'
		mov byte ptr[esp + 1], 'e'
		mov byte ptr[esp + 2], 's'
		mov byte ptr[esp + 3], 's'
		mov byte ptr[esp + 4], 'a'
		mov byte ptr[esp + 5], 'g'
		mov byte ptr[esp + 6], 'e'
		mov byte ptr[esp + 7], 'B'
		mov byte ptr[esp + 8], 'o'
		mov byte ptr[esp + 9], 'x'
		mov byte ptr[esp + 10],'A'
		mov byte ptr[esp + 11], 0

		mov ebx, esp
		push ebx            // function name

		push eax            // dllHandle from LoadLibrary

		mov ecx, 0x743150B0
		call ecx			// call GetProcAddress

		push 0
		push ebx
		push ebx
		push 0

		call eax

		add esp, 16

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
	
}