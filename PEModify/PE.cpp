#include "PE.h"
#include <iostream>

PE::PE(uintptr_t base_ptr)
{
	base = base_ptr;
	dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base_ptr);
	nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(base_ptr + dos_header->e_lfanew);
	sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(uintptr_t(nt_header) + sizeof(*nt_header));
}

uintptr_t PE::rvaToOffset(uintptr_t rva) const
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

uintptr_t PE::rvaToPhysical(uintptr_t rva) const
{
	return rvaToOffset(rva) + base;
}

uintptr_t PE::offsetToPhysical(uintptr_t offset) const
{
	return offset + base;
}

IMAGE_SECTION_HEADER* PE::findSection(std::string sectionName)
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

void PE::printSections()
{
	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
	{
		printf("%.8s\n", (char*) sections[i].Name);
	}

	auto import_table = rvaToType<IMAGE_IMPORT_DESCRIPTOR>(nt_header->OptionalHeader.DataDirectory[1].VirtualAddress);

	auto name_im = rvaToType<char>(import_table->Name);

	std::cout << import_table->Name << " " << name_im;

}

void PE::printImports()
{
	using ImportDescriptorArray = ARRAY<IMAGE_IMPORT_DESCRIPTOR>;
	using ThunkDataArray = ARRAY<IMAGE_THUNK_DATA>;

	auto import_table = rvaToType<ImportDescriptorArray>(nt_header->OptionalHeader.DataDirectory[1].VirtualAddress);

	int j = 0;
	while (import_table->entry[j].OriginalFirstThunk != 0)
	{
		auto iat = rvaToType<ThunkDataArray>(import_table->entry[j].OriginalFirstThunk);
		auto dllName = rvaToType<char>(import_table->entry[j].Name);

		std::cout << dllName << std::endl;

		int i = 0;
		while (iat->entry[i].u1.AddressOfData != 0)
		{
			auto import = rvaToType<IMAGE_IMPORT_BY_NAME>(iat->entry[i].u1.AddressOfData);
			std::cout << (char*)import->Name;

			i++;
		}

		j++;
	}
}