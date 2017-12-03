#pragma once
#include <string>
#include <windows.h>

class FileMapping
{
public:
	FileMapping(std::string name) :
		name(name)
	{
		file = CreateFile(
			name.c_str(),					// name
			GENERIC_READ | GENERIC_WRITE,   // access rights
			0,								// shared mode
			nullptr,						// security
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);						// template file

		fileMapping = CreateFileMapping(
			file,				// file handle
			nullptr,            // security attributes
			PAGE_READWRITE,     // protect flag
			0,                  // size
			0,
			nullptr);           // name

		view = MapViewOfFile(
			fileMapping,
			FILE_MAP_WRITE,
			0,					// start offset
			0,
			0);					// end offset - 0 = end of file

	}

	uintptr_t ptr() const
	{
		return reinterpret_cast<uintptr_t>(view);
	}

	~FileMapping()
	{
		FlushViewOfFile(view, 0);
		UnmapViewOfFile(view);
		CloseHandle(fileMapping);
		CloseHandle(file);
	}

private:
	std::string name;

	LPVOID view;

	HANDLE fileMapping;

	HANDLE file;
};
