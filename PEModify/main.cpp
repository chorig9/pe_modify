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

void asm_code()
{
	__asm
	{
		nop
		mov ecx, 07419F8B0h
		push 0
		push 0
		push 0
		push 0
		call ecx
		nop
	}
}

uintptr_t functionAddress(void* funcPointer)
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

	auto codeStart = functionAddress(asm_code);
	while (*((unsigned char*) codeStart) != 0x90)
		codeStart++;

	auto codeEnd = codeStart + 1;
	while (*((unsigned char*) codeEnd) != 0x90)
		codeEnd++;

	auto codeSize = codeEnd - codeStart;

	// TODO 5 = jmpInstructionLength
	if ((codeSize + 5) > freeSpace)
	{
		printf("error: no space\n");
	}

	memcpy((void*) codeDestinationPhysical, (void*) codeStart, codeSize);

	char jmpBackInstruction[] = "\xE9\x00\x00\x00\x00";
	int* jmpBackAddress = (int*)(jmpBackInstruction + 1);

	// relative offset to addressOfEntryPoint
	*jmpBackAddress = pe.nt_header->OptionalHeader.AddressOfEntryPoint - (codeDestinationRVA + codeSize + 5);

	memcpy((void*)(codeDestinationPhysical + codeSize), jmpBackInstruction, 5);

	codeSection->Misc.VirtualSize += codeSize + 5;
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

void parse_export(PE* pe)
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

void readPEB()
{
	PTEB tebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
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

	//original_return = 0x741476E0;
	//test();

	

	/*FileMapping mapping("printf-rel.exe");
	auto base_ptr = mapping.ptr();

	PE pe(base_ptr);
	parse_import(&pe);*/

	//__asm
	//{
	//	push 0
	//	push 0
	//		push 0
	//		push 0
	//		mov ecx, 07419F8B0h
	//	call ecx
	//}


	//print_sections("printf-rel.exe");

	//entry_point = (int) &test;
	//code();

	//asm_code();



	x("Project1x.exe");

	//parse_import("printf-rel.exe");

	// 0x741476E0

	//PE pe(0x74130000);

	//auto* codeSection = pe.findSection(".text");
	
	//parse_export(&pe);
	

	//printf("%lu\n", pe.nt_header->OptionalHeader.ImageBase);

	//auto *x = pe.findSection(".text");

	//auto baseOfCode = pe.nt_header->OptionalHeader.BaseOfCode;

	//auto codePhysicalAddress = pe.offset_to_physical(x->PointerToRawData);
	//auto baseOfCodePhysical = pe.rva_to_physical(baseOfCode);
	//
	//auto entryPoint = pe.nt_header->OptionalHeader.AddressOfEntryPoint;
	//auto size = x->SizeOfRawData;

	//asm_code();

	//getchar();
	
}