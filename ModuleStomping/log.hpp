#pragma once
#include <Windows.h>
#include <cstdio>

void log(const char* format, ...) {
	auto last_error = GetLastError();
	va_list args;
	va_start(args, format);
	char msg_buffer[512];
	int length = vsnprintf(msg_buffer, sizeof(msg_buffer), format, args);

	if (length < 0) {
		msg_buffer[sizeof(msg_buffer) - 1] = '\0';
	}
	va_end(args);

	if (last_error) {
		LPSTR error_buffer = nullptr;
		auto size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr, last_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&error_buffer, 0, nullptr);
		if (size) {
			printf("[!] %s. Error: %s\n", msg_buffer, error_buffer);
		}
		else {
			printf("[!] %s. Error: %d.\n", msg_buffer, last_error);
		}
		LocalFree(error_buffer);
	}
	else {
		printf("[+] %s.\n", msg_buffer);
	}
}
