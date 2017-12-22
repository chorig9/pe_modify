//#include <winnt.h> // struct descirption at "Image Format"
#include <windows.h>
#include <iostream>
#include "FileMapping.h"
#include "PE.h"
#include <stdio.h>

#define MAGIC_CODE_MARKER 0x12345678

#define Kernel32DllBaseAddress 0x75710000

#define GetProcAddressOffset 0x000150B0
#define LoadLibraryOffset 0x00015980
#define GetModuleHandleAOffset 0x00014FB0

#define GetProcAddressAddress 0x757250B0
#define LoadLibraryAddress 0x75725980
#define GetModuleHandleAAddress 0x75724FB0

static_assert(GetProcAddressAddress == GetProcAddressOffset + Kernel32DllBaseAddress,
	"GetProcAddress");
static_assert(LoadLibraryAddress == LoadLibraryOffset + Kernel32DllBaseAddress,
	"LoadLibraryAddress");
static_assert(GetModuleHandleAAddress == GetModuleHandleAOffset + Kernel32DllBaseAddress,
	"GetModuleHandleAAddress");

#define dd _asm __emit

#define user32dll dd 'u' dd 's' dd 'e' dd 'r' dd '3' dd '2' dd '.' dd 'd' dd 'l' dd 'l' dd 0
#define CreateWindowExA dd 'C' dd 'r' dd 'e' dd 'a' dd 't' dd 'e' dd 'W' dd 'i' dd 'n' dd 'd' dd 'o' dd 'w' dd 'E' dd 'x' dd 'A' dd 0
#define ShowWindow dd 'S' dd 'h' dd 'o' dd 'w' dd 'W' dd 'i' dd 'n' dd 'd' dd 'o' dd 'w' dd 0
#define windowName dd 'e' dd 'd' dd 'i' dd 't' dd 0
#define GetMessageA dd 'G' dd 'e' dd 't' dd 'M' dd 'e' dd 's' dd 's' dd 'a' dd 'g' dd 'e' dd 'A' dd 0
#define DispatchMessageA dd 'D' dd 'i' dd 's' dd 'p' dd 'a' dd 't' dd 'c' dd 'h' dd 'M' dd 'e' dd 's' dd 's' dd 'a' dd 'g' dd 'e' dd 'A' dd 0
#define TranslateMessage dd 'T' dd 'r' dd 'a' dd 'n' dd 's' dd 'l' dd 'a' dd 't' dd 'e' dd 'M' dd 'e' dd 's' dd 's' dd 'a' dd 'g' dd 'e' dd 0

#define user32dllSize 11
#define CreateWindowExASize 16
#define ShowWindowSize 11
#define windowNameSize 5
#define GetMessageASize 12
#define DispatchMessageASize 17

__declspec(naked) void injectionCodeWindow()
{
	__asm
	{
		push MAGIC_CODE_MARKER

		get_eip:
		mov eax, [esp]
		ret

		get_data_offset:
		call get_eip
		lea eax, [eax + 4]
		ret

		user32dll
		CreateWindowExA
		ShowWindow
		windowName
		GetMessageA
		DispatchMessageA
		TranslateMessage

		push MAGIC_CODE_MARKER

		push ebp

		sub esp, 80
		mov ebp, esp

		call get_data_offset
		mov [ebp], eax     // "user32.dll"
		add eax, user32dllSize
		mov [ebp + 4], eax // "CreateWindowExA"
		add eax, CreateWindowExASize
		mov [ebp + 8], eax // "ShowWindow"
		add eax, ShowWindowSize
		mov [ebp + 12], eax // window class name
		add eax, windowNameSize
		mov [ebp + 16], eax // "GetMessage"
		add eax, GetMessageASize
		mov [ebp + 20], eax // "DispatchMessage"
		add eax, DispatchMessageASize
		mov [ebp + 70], eax // "TransalteMessage"

		push dword ptr [ebp]
		mov ecx, LoadLibraryAddress // call LoadLibrary
		call ecx

		mov dword ptr[ebp + 24], eax // user32.dll handle

		push 0
		 mov ecx, GetModuleHandleAAddress
		 push 0
		 call ecx			// call GetProcAddress
		push eax
		push 0
		push 0
		push 0x80000000
		push 0x80000000
		push 0x80000000
		push 0x80000000
		push 0x8160000
		push dword ptr [ebp + 12]
		push dword ptr [ebp + 12]
		push 0

		push [ebp + 4]            // function name
		push dword ptr[ebp + 24]  // dllHandle from LoadLibrary
		mov ecx, GetProcAddressAddress
		call ecx			// call GetProcAddress
		call eax
		mov dword ptr[ebp + 32], eax // window handle

		push [ebp + 8]            // function name
		push dword ptr[ebp + 24]  // dllHandle from LoadLibrary
		mov ecx, GetProcAddressAddress
		call ecx			// call GetProcAddress

		push SW_SHOWDEFAULT
		push dword ptr[ebp + 32]
		call eax

			get_message:
		
		push[ebp + 16]            // function name
		push dword ptr[ebp + 24]  // dllHandle from LoadLibrary
		mov ecx, GetProcAddressAddress
		call ecx

		push 0
		push 0
		push 0
		lea edi, [ebp + 40]
		push edi
		call eax
		
		cmp eax, 0
		jz end

		push[ebp + 70]            // function name
		push dword ptr[ebp + 24]  // dllHandle from LoadLibrary
		mov ecx, GetProcAddressAddress
		call ecx

		lea edi, [ebp + 40]
		push edi
		call eax

		push[ebp + 20]            // function name
		push dword ptr[ebp + 24]  // dllHandle from LoadLibrary
		mov ecx, GetProcAddressAddress
		call ecx

		lea edi, [ebp + 40]
		push edi
		call eax

		jmp get_message

		end:
		add esp, 80

		pop ebp

		push MAGIC_CODE_MARKER
	}
}

#define MessageBoxA dd 'M' dd 'e' dd 's' dd 's' dd 'a' dd 'g' dd 'e' dd 'B' dd 'o' dd 'x' dd 'A' dd 0

__declspec(naked) void injectionCodeMessageBox()
{
	__asm
	{
		push MAGIC_CODE_MARKER

		get_eip :
		mov eax, [esp]
		ret

		get_data_offset :
		call get_eip
		lea eax, [eax + 4]
		ret

		user32dll
		MessageBoxA

		push MAGIC_CODE_MARKER

		push ebp
		mov ebp, esp

		call get_data_offset
		push eax     // "user32.dll"
		add eax, user32dllSize
		push eax	 // "MessageBoxA"

		push [ebp - 4]
		mov ecx, LoadLibraryAddress // call LoadLibrary
		call ecx

		push [ebp - 8]            // function name
		push eax  // dllHandle from LoadLibrary
		mov ecx, GetProcAddressAddress
		call ecx			// call GetProcAddress

		push 0
		push[ebp - 8]
		push[ebp - 8]
		push 0

		call eax

		pop ebp

		push MAGIC_CODE_MARKER
	}
}

// calculate function physical location when using incremental linking
uintptr_t functionAddressIncremental(void* funcPointer)
{
	char* funcPointerChar = (char*)funcPointer;

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

	auto codeStart = (uintptr_t)injectionCode;

	while (*((int*)codeStart) != MAGIC_CODE_MARKER)
		codeStart++;

	codeStart += sizeof(MAGIC_CODE_MARKER);

	auto codeEntryPoint = codeStart + 1;
	while (*((int*)codeEntryPoint) != MAGIC_CODE_MARKER)
		codeEntryPoint++;

	codeEntryPoint += sizeof(MAGIC_CODE_MARKER);

	auto codeEnd = codeEntryPoint + 1;
	while (*((int*)codeEnd) != MAGIC_CODE_MARKER)
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

	memcpy((void*)codeDestinationPhysical, (void*)codeStart, codeSize);
	memcpy((void*)(codeDestinationPhysical + codeSize), jmpBackInstruction,
		jmpBackInstructionSize);

	codeSection->Misc.VirtualSize += codeSize + jmpBackInstructionSize;
	pe.nt_header->OptionalHeader.AddressOfEntryPoint = codeDestinationRVA + codeEntryPoint - codeStart;
}

int main()
{
	std::string name;
	int mode;

	std::cout << "Enter filename\n";
	std::cin >> name;
	
	std::cout << "Enter mode (0 - show Edit window, 1 - show MessageBox)\n";
	std::cin >> mode;

	FileMapping mapping(name);
	auto base_ptr = mapping.ptr();

	PE pe(base_ptr);

	//pe.printImports();
	//pe.printSections();

	if (mode == 0)
		injectCode(pe, &injectionCodeWindow);
	else
		injectCode(pe, &injectionCodeMessageBox);

	getchar();
	
}