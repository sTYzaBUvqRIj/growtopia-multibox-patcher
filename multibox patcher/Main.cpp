
#define WIN32_LEAN_AND_MEAN
#include <Windows.h> // PE

#include <fstream>
#include <iostream>

#include <sys/stat.h> // check file
#include <conio.h> // _getch

inline bool CheckFile(const char* dir) noexcept
{
	struct stat st;
	if (stat(dir, &st))
		return false;
	return true;
}

uintptr_t BASE = 0;
PIMAGE_NT_HEADERS NT_HEADERS = nullptr;
uintptr_t START = 0;
uintptr_t END = 0;

inline void InitializeAddress(const uintptr_t base) noexcept
{
	BASE = base;
	NT_HEADERS = PIMAGE_NT_HEADERS(uintptr_t(BASE) + PIMAGE_DOS_HEADER(BASE)->e_lfanew);
	START = uintptr_t(BASE) + NT_HEADERS->OptionalHeader.BaseOfCode;
	END = NT_HEADERS->OptionalHeader.SizeOfCode;
}

// Pattern: int array
inline uintptr_t FindPattern(const int* data, const int size, const int offset = 0) noexcept
{
	bool found = false;

	if (!START || !END || size < 1)
		return 0;
	for (size_t i = START; i <= START + END; ++i) {
		for (size_t j = 0; j < size; ++j) {
			if (*((PBYTE)i + j) == data[j] || data[j] == -1)
				found = true;
			else {
				found = false;
				break;
			}
		}
		if (found)
			return uintptr_t(i) + offset;
	}

	return 0x0;
}

// Pattern: char array
inline uintptr_t FindPattern(const char* data, const int size, const int offset = 0) noexcept
{
	bool found = false;

	if (!START || !END || size < 1)
		return 0;
	for (size_t i = START; i <= START + END; ++i) {
		for (int j = 0; j < size; ++j) {
			if (*((char*)i + j) == data[j])
				found = true;
			else {
				found = false;
				break;
			}
		}
		if (found)
			return uintptr_t(i) + offset;
	}
	return 0x0;
}

int main()
{
	std::cout << "Input growtopia path: ";
	std::string gtDir;
	std::cin >> gtDir;

	std::cout << "Input output directory: ";
	std::string outDir;
	std::cin >> outDir;

	if (!gtDir.empty() && CheckFile(gtDir.c_str())) {
		std::fstream input(gtDir, std::ios::in | std::ios::binary);

		input.seekg(0, std::ios::end);
		const std::streamsize size = input.tellg();

		if (size == -1) {
			std::cout << "Couldn't open " << gtDir << std::endl;
			Sleep(4000);
			return -1;
		}

		std::cout << "File size is " << size << " bytes" << std::endl;
		char* data = new char[size];
		if (!data) {
			std::cout << "Something went wrong when allocating" << size << " bytes" << std::endl;
			Sleep(4000);
			return -1;
		}

		input.seekg(0, std::ios::beg);
		if (!input.read(data, size)) {
			std::cout << "Something went wrong" << std::endl;
			Sleep(4000);
			return -1;
		}

		std::cout << "Starting patch..." << std::endl;
		// Here we patching stuff
		InitializeAddress((uintptr_t)data);

		bool patched = false;

		const uintptr_t mutex1 = FindPattern("\xC9\x48\x85\xC0\x0F\x85", 6, 4);
		if (mutex1) {
			std::cout << "Mutex check found: " << (mutex1 - (uintptr_t)data) << std::endl;
			const char* nop5 = "\x90\x90\x90\x90\x90\x90";
			memcpy((void*)mutex1, nop5, 6);
			std::cout << "Success writing to memory" << std::endl;
			patched = true;
		}

		const int patterns[7] = { 0x0, 0x3B, 0xC1, 0x75, -1, 0x85, 0xC9 };
		const uintptr_t bypass1 = FindPattern((int*)patterns, 7, 3);
		if (bypass1) {
			std::cout << "Ban bypass found: " << (bypass1 - (uintptr_t)data) << std::endl;
			const char* nop2 = "\x90\x90";
			memcpy((void*)bypass1, nop2, 2);
			std::cout << "Success patch ban bypass" << std::endl;
		}

		if (patched) {
			std::cout << "Writing output file: " << outDir << "\\Growtopia_patched.exe" << std::endl;
			std::fstream out(outDir + "\\Growtopia_patched.exe", std::ios::binary | std::ios::out);
			out.write(data, size);
			out.close();
		}
		else
			std::cout << "Nothing to patch!" << std::endl;

		delete[] data;
		input.close();
		Sleep(1000);
		std::cout << "Press anywhere to exit..." << std::endl;
		return _getch();
	}
	else {
		std::cout << "Couldn't find file " << gtDir << ". Make sure to input Growtopia path correctly" << std::endl;
		Sleep(4000);
		return -1;
	}
}