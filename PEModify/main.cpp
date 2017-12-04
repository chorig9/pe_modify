//#include <winnt.h> // struct descirption at "Image Format"
#include <windows.h>
#include <iostream>
#include "FileMapping.h"
#include <vector>
#include <stdio.h>
#include <winternl.h>

struct PE
{
	PE(uintptr_t base_ptr)
	{
		base = base_ptr;
		dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base_ptr);
		nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(base_ptr + dos_header->e_lfanew);
		sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(uintptr_t(nt_header) + sizeof(*nt_header));
	}

	uintptr_t rva_to_offset(uintptr_t rva) const
	{
		for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
		{
			if (rva > sections[i].VirtualAddress &&
				rva <= sections[i].VirtualAddress + sections[i].SizeOfRawData)
			{
				return sections[i].PointerToRawData + rva - sections[i].VirtualAddress;
			}
		}

		return 0;
	}

	uintptr_t rva_to_physical(uintptr_t rva) const
	{
		return rva_to_offset(rva) + base;
	}

	uintptr_t offset_to_physical(uintptr_t offset) const
	{
		return offset + base;
	}

	template<class T>
	T* rva_to_type(uintptr_t rva) const
	{
		return reinterpret_cast<T*> (rva_to_physical(rva));
	}

	IMAGE_SECTION_HEADER* findSection(std::string sectionName)
	{
		for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
		{
			char buffer[9] = { 0 };
			memcpy(buffer, sections[i].Name, 8);
			
			if (strcmp(buffer, sectionName.c_str()) == 0)
				return &sections[i];
		}

		return nullptr;
	}

	uintptr_t base;
	IMAGE_DOS_HEADER* dos_header;
	IMAGE_NT_HEADERS* nt_header;
	IMAGE_SECTION_HEADER* sections;
};

template<class T>
struct ARRAY
{
	T entry[];
};


void print_sections(std::string name)
{
	FileMapping mapping(name);
	auto base_ptr = mapping.ptr();

	PE pe(base_ptr);

	for (int i = 0; i < pe.nt_header->FileHeader.NumberOfSections; i++)
	{
		printf("%.8s\n", (char*)pe.sections[i].Name);
	}

	auto import_table = pe.rva_to_type<IMAGE_IMPORT_DESCRIPTOR>(pe.nt_header->OptionalHeader.DataDirectory[1].VirtualAddress);

	auto name_im = pe.rva_to_type<char>(import_table->Name);

	std::cout << import_table->Name << " " << name_im;

}

#define MAGIC_CODE_MARKER 0x12345678

__declspec(naked) void callMessageBox()
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

		push 0
		push ebx
		push ebx
		push 0

		mov ecx, 0x07419F8B0
		call ecx

		add esp, 16

		push MAGIC_CODE_MARKER
	}
}

__declspec(naked) void callLoadLibrary()
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

void x(std::string name)
{
	FileMapping mapping(name);
	auto base_ptr = mapping.ptr();

	PE pe(base_ptr);

	auto* codeSection = pe.findSection(".text");
	auto codePhysicalAddress = pe.offset_to_physical(codeSection->PointerToRawData);

	auto freeSpace = codeSection->SizeOfRawData - codeSection->Misc.VirtualSize;

	auto codeDestinationPhysical = codePhysicalAddress + codeSection->Misc.VirtualSize;
	auto codeDestinationRVA = codeSection->VirtualAddress + codeSection->Misc.VirtualSize;

	uintptr_t codeStart = (uintptr_t) &callLoadLibrary;

	while (*((int*) codeStart) != MAGIC_CODE_MARKER)
		codeStart++;

	codeStart += sizeof(MAGIC_CODE_MARKER);

	auto codeEnd = codeStart + 1;
	while (*((int*) codeEnd) != MAGIC_CODE_MARKER)
		codeEnd++;

	codeEnd -= 1; // push opcode

	auto codeSize = codeEnd - codeStart;

	char jmpBackInstruction[] = "\xE9\x00\x00\x00\x00";
	int* jmpBackAddress = (int*)(jmpBackInstruction + 1);

	// relative offset to addressOfEntryPoint
	*jmpBackAddress = pe.nt_header->OptionalHeader.AddressOfEntryPoint - (codeDestinationRVA + codeSize + 5);

	if ((codeSize + sizeof(jmpBackInstruction)) > freeSpace)
	{
		printf("error: no space\n");
	}

	memcpy((void*) codeDestinationPhysical, (void*) codeStart, codeSize);
	memcpy((void*) (codeDestinationPhysical + codeSize), jmpBackInstruction, sizeof(jmpBackInstruction));

	codeSection->Misc.VirtualSize += codeSize + sizeof(jmpBackInstruction);
	pe.nt_header->OptionalHeader.AddressOfEntryPoint = codeDestinationRVA;
}

void parse_import(PE *pe)
{
	struct IMPORT_DESCRIPTOR_ARRAY
	{
		IMAGE_IMPORT_DESCRIPTOR entries[];
	};

	struct THUNK_DATA_ARRAY
	{
		IMAGE_THUNK_DATA thunks[];
	};

	// XXX ARRAY<IMAGE_IMPORT_DESCRIPTOR>
	auto import_table = pe->rva_to_type<IMPORT_DESCRIPTOR_ARRAY>(pe->nt_header->OptionalHeader.DataDirectory[1].VirtualAddress);

	int j = 0;
	while (import_table->entries[j].OriginalFirstThunk != 0)
	{
		auto iat = pe->rva_to_type<THUNK_DATA_ARRAY>(import_table->entries[j].OriginalFirstThunk);
		auto dllName = pe->rva_to_type<char>(import_table->entries[j].Name);

		printf("     %s\n", dllName);

		int i = 0;
		while (iat->thunks[i].u1.AddressOfData != 0)
		{
			auto import = pe->rva_to_type<IMAGE_IMPORT_BY_NAME>(iat->thunks[i].u1.AddressOfData);
			printf("%s\n", (char*) import->Name);

			i++;
		}

		j++;
	}
}

void parse_export_in_memory(PE* pe)
{
	struct THUNK_DATA_ARRAY
	{
		IMAGE_THUNK_DATA thunks[];
	};

	auto export_directory = (IMAGE_EXPORT_DIRECTORY*) (pe->nt_header->OptionalHeader.DataDirectory[0].VirtualAddress + pe->base);

	struct NAMES_ARRAY
	{
		DWORD ptr[];
	};
	
	struct ADDRESSES_TABLE
	{
		DWORD address[];
	};

	auto names = (NAMES_ARRAY*) (export_directory->AddressOfNames + pe->base);
	auto addresses = (ADDRESSES_TABLE*)(export_directory->AddressOfFunctions + pe->base);

	for (int i = 0; i < export_directory->NumberOfNames; i++)
	{
		printf("%s %d\n", (char*)(names->ptr[i] + pe->base), addresses->address[i]);
	}
	
	
}

#include <windows.h>
#include <winternl.h>
#include <iostream>

HRESULT UnicodeToAnsi(LPCOLESTR pszW, LPSTR* ppszA) {
	ULONG cbAnsi, cCharacters;
	DWORD dwError;
	// If input is null then just return the same.    
	if (pszW == NULL)
	{
		*ppszA = NULL;
		return NOERROR;
	}
	cCharacters = wcslen(pszW) + 1;
	cbAnsi = cCharacters * 2;

	*ppszA = (LPSTR)CoTaskMemAlloc(cbAnsi);
	if (NULL == *ppszA)
		return E_OUTOFMEMORY;

	if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA, cbAnsi, NULL, NULL))
	{
		dwError = GetLastError();
		CoTaskMemFree(*ppszA);
		*ppszA = NULL;
		return HRESULT_FROM_WIN32(dwError);
	}
	return NOERROR;
}

PTEB getTeb()
{
	__asm
	{
		mov eax, fs:18h
	}
}

void readPEB()
{
	PTEB tebPtr = getTeb();
	PPEB pebPtr = tebPtr->ProcessEnvironmentBlock;
	PPEB_LDR_DATA pebLdr = pebPtr->Ldr;

	PLIST_ENTRY le = (PLIST_ENTRY)pebLdr->InMemoryOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY mainModule = CONTAINING_RECORD(le, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

	PLDR_DATA_TABLE_ENTRY module = nullptr;

	while (module != mainModule)
	{
		le = le->Flink;
		module = CONTAINING_RECORD(le, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		LPSTR name;
		UnicodeToAnsi(module->FullDllName.Buffer, &name);
		std::cout << name << " " << module->DllBase << " " << std::endl;
	}
}

int main()
{


	x("notepad.exe");
	
}