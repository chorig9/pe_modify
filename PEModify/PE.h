#pragma once
#include <windows.h>
#include <string>

class PE
{
public:
	PE(uintptr_t base_ptr);

	uintptr_t rvaToOffset(uintptr_t rva) const;

	uintptr_t rvaToPhysical(uintptr_t rva) const;

	uintptr_t offsetToPhysical(uintptr_t offset) const;

	template<class T>
	T* rvaToType(uintptr_t rva) const
	{
		return reinterpret_cast<T*> (rvaToPhysical(rva));
	}

	IMAGE_SECTION_HEADER* findSection(std::string sectionName);

	void printSections();

	void printImports();

	IMAGE_DOS_HEADER* dos_header;
	IMAGE_NT_HEADERS* nt_header;
	IMAGE_SECTION_HEADER* sections;

private:
	uintptr_t base;

};

template<class T>
struct ARRAY
{
	T entry[];
};