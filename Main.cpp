#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <intrin.h>
#include "detours.h"
#include <stdint.h>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>


#pragma comment(lib,"detours")
#pragma comment(lib,"ntdll")
#pragma comment(lib, "Ws2_32.lib")

HMODULE Gepard_Module = 0;
DWORD fake_Variable_Send = 0, fake_Variable_Recv = 0;
BYTE LdrLoadDll_Bytes[5], LoadLibW_Bytes[5], LoadLibA_Bytes[5], KiUserExceptionDispatcher_Bytes[8], DbgUiRemoteBreakin_Bytes[5], RtlUnhandledExceptionFilter2_Bytes[8];
LPVOID GameModule = 0, FakeGameModule = 0, CRC_1Back = 0;

SOCKET sg = 0;

DWORD WINAPI SendFunc(
	SOCKET     s,
	const char* buf,
	int        len,
	int        flags)
{
	typedef DWORD(WINAPI * p_Send)(SOCKET s, char* buf, int len, int flags);
	p_Send o_Send = reinterpret_cast<p_Send>(fake_Variable_Send);
	if (buf && len > 6 && buf[0] == 0x04 && buf[1] == 0x02)
		return o_Send(s, const_cast<char*>(buf), len, flags);
	sg = s;
	return send(s, buf, len, flags);
}

DWORD WINAPI RecvFunc(
	SOCKET     s,
	char* buf,
	int        len,
	int        flags)
{
	typedef DWORD(WINAPI * p_Recv)(SOCKET s, char* buf, int len, int flags);
	p_Recv o_Recv = reinterpret_cast<p_Recv>(fake_Variable_Recv);
	return o_Recv(s, buf, len, flags);
}

BOOL __fastcall  LoadFile(void* T, void* EDX, char* a1, DWORD a2, DWORD a3, DWORD a4)
{
	typedef INT(__thiscall * p_file)(void* T, char* File, DWORD a2, DWORD a3, DWORD a4);
	p_file o_f = reinterpret_cast<p_file>(reinterpret_cast<DWORD>(Gepard_Module) + 0x14980);
	BOOL Data = o_f(T, a1, a2, a3, a4);
	return 1;
}

__declspec(naked) void CRC_Hook1()
{

	__asm
	{
		cmp eax,0x00400A04
		je FAKE
		cmp eax, 0x00400A05
		je FAKE2
		cmp eax, 0x00400A06
		je FAKE3
		cmp eax, 0x00400A07
		je FAKE4

		cmp eax, 0x00400A00
		je FAKE5
		cmp eax, 0x00400A01
		je FAKE6
		cmp eax, 0x00400A02
		je FAKE7
		cmp eax, 0x00400A03
		je FAKE8


		lea edi, [edi + 0x00000002]
		jmp CRC_1Back
	FAKE:
		lea eax, fake_Variable_Send
		lea edi, [edi + 0x00000002]
		mov dx,[eax]
		jmp CRC_1Back
	FAKE2:
		lea eax, fake_Variable_Send
		add eax,1
		lea edi, [edi + 0x00000002]
		mov dx, [eax]
		jmp CRC_1Back
	FAKE3 :
		lea eax, fake_Variable_Send
		add eax,2
		lea edi, [edi + 0x00000002]
		mov dx, [eax]
		jmp CRC_1Back
	FAKE4 :
		lea eax, fake_Variable_Send
		add eax,3
		lea edi, [edi + 0x00000002]
		mov dx, [eax]
		jmp CRC_1Back
	FAKE5 :
		lea eax, fake_Variable_Recv
		lea edi, [edi + 0x00000002]
		mov dx, [eax]
		jmp CRC_1Back
	FAKE6 :
		lea eax, fake_Variable_Recv
		add eax, 1
		lea edi, [edi + 0x00000002]
		mov dx, [eax]
		jmp CRC_1Back
	FAKE7 :
		lea eax, fake_Variable_Recv
		add eax, 2
		lea edi, [edi + 0x00000002]
		mov dx, [eax]
		jmp CRC_1Back
	FAKE8 :
		lea eax, fake_Variable_Recv
		add eax, 3
		lea edi, [edi + 0x00000002]
		mov dx, [eax]
		jmp CRC_1Back

	}
}


bool Hook_FindFirstFileW(bool detourStatus);
bool Hook_OpenProcess(bool detourStatus);
bool Hook_CRC(bool detourStatus);

bool PrepareBypass()
{


	static auto MakePageWriteable = [](LPVOID Addr)->DWORD
	{
		DWORD Old = 0;
		_MEMORY_BASIC_INFORMATION mbi = { 0,0,0,0,0,0,0 };
		if (!VirtualQuery(Addr, &mbi, sizeof(mbi)))
			return 0;
		if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &Old))
			return 0;
		return 1;
	};
	

	ZeroMemory(LdrLoadDll_Bytes, 5);
	ZeroMemory(LoadLibW_Bytes, 5);
	ZeroMemory(LoadLibA_Bytes, 5);

	/* Safe bytes before anti-cheat overwrites these functions */
	
	GameModule = GetModuleHandle(0);
	HMODULE Ntdll = GetModuleHandle("ntdll.dll");
	HMODULE Kernel32 = GetModuleHandle("Kernel32.dll");
	HMODULE Win32U = GetModuleHandle("Win32u.dll");
	if (Ntdll == 0 || Kernel32 == 0) return false;

	LPVOID LdrLoadDll_Addy = GetProcAddress(Ntdll, "LdrLoadDll");
	LPVOID KiUserExceptionDispatcher_Addy = GetProcAddress(Ntdll, "KiUserExceptionDispatcher");
	LPVOID DbgUiRemoteBreakin_Addy = GetProcAddress(Ntdll, "DbgUiRemoteBreakin");
	LPVOID RtlUnhandledExceptionFilter2_Addy = GetProcAddress(Ntdll, "RtlUnhandledExceptionFilter2");
	LPVOID LoadLibW_Addy = GetProcAddress(Kernel32, "LoadLibraryW");
	LPVOID LoadLibA_Addy = GetProcAddress(Kernel32, "LoadLibraryA");

	if (!LdrLoadDll_Addy) return false;
	memcpy(LdrLoadDll_Bytes, LdrLoadDll_Addy, 5);
	if (!LoadLibW_Addy) return false;
	memcpy(LoadLibW_Bytes, LoadLibW_Addy, 5);
	if (!LoadLibA_Addy) return false;
	memcpy(LoadLibA_Bytes, LoadLibA_Addy, 5);
	if (!KiUserExceptionDispatcher_Addy) return false;
	memcpy(KiUserExceptionDispatcher_Bytes, KiUserExceptionDispatcher_Addy, 8);
	if (!DbgUiRemoteBreakin_Addy) return false;
	memcpy(DbgUiRemoteBreakin_Bytes, DbgUiRemoteBreakin_Addy, 5);
	if (!RtlUnhandledExceptionFilter2_Addy) return false;
	memcpy(RtlUnhandledExceptionFilter2_Bytes, RtlUnhandledExceptionFilter2_Addy, 8);

	Hook_FindFirstFileW(true);
	Hook_OpenProcess(true);

	char DllPath[MAX_PATH];
	ZeroMemory(DllPath, MAX_PATH);

	

	/* Load Gepard */
	GetFullPathNameA("gepard_o.dll", MAX_PATH, DllPath, 0);
	Gepard_Module = LoadLibraryA(DllPath);
	if (!Gepard_Module) return 0;

	

	PIMAGE_DOS_HEADER DosHeader_Dll = reinterpret_cast<PIMAGE_DOS_HEADER>(Gepard_Module);
	PIMAGE_DOS_HEADER DosHeader_Game = reinterpret_cast<PIMAGE_DOS_HEADER>(GameModule);
	PIMAGE_NT_HEADERS NtHeader_Dll = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(Gepard_Module) + DosHeader_Dll->e_lfanew);
	PIMAGE_NT_HEADERS NtHeader_Game = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(GameModule) + DosHeader_Game->e_lfanew);

	LPVOID FakeModule = VirtualAlloc(0, NtHeader_Dll->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!FakeModule)
		return 0;

	FakeGameModule = VirtualAlloc(0, NtHeader_Game->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!FakeGameModule)
		return 0;

	memcpy(FakeModule, Gepard_Module, NtHeader_Dll->OptionalHeader.SizeOfImage);
	memcpy(FakeGameModule, reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(GameModule)), NtHeader_Game->OptionalHeader.SizeOfImage);


	/* DLL CRC */
	if (!MakePageWriteable(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x71314)) ||
		!MakePageWriteable(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x71478)) ||
		!MakePageWriteable(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x9BF3C)) ||
		!MakePageWriteable(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x68DC0)))
		return 0;

	*reinterpret_cast<DWORD*>(reinterpret_cast<DWORD>(Gepard_Module) + 0x68DC0) = reinterpret_cast<DWORD>(FakeModule) + 0x1000;
	*reinterpret_cast<DWORD*>(reinterpret_cast<DWORD>(Gepard_Module) + 0x71314) = reinterpret_cast<DWORD>(FakeModule);
	*reinterpret_cast<DWORD*>(reinterpret_cast<DWORD>(Gepard_Module) + 0x71478) = reinterpret_cast<DWORD>(FakeModule);
	*reinterpret_cast<DWORD*>(reinterpret_cast<DWORD>(Gepard_Module) + 0x9BF3C) = reinterpret_cast<DWORD>(FakeModule);

	/* Game CRC */

	if (!MakePageWriteable(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x2E09C)) ||
		!MakePageWriteable(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x7F9304)) ||
		!MakePageWriteable(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x7F92F8)))
		return 0;

	*reinterpret_cast<DWORD*>(reinterpret_cast<DWORD>(Gepard_Module) + 0x2E09C) = reinterpret_cast<DWORD>(FakeGameModule) + 0x1000;
	*reinterpret_cast<DWORD*>(reinterpret_cast<DWORD>(Gepard_Module) + 0x7F9304) = reinterpret_cast<DWORD>(FakeGameModule) + 0x1000;
	*reinterpret_cast<DWORD*>(reinterpret_cast<DWORD>(Gepard_Module) + 0x7F92F8) = reinterpret_cast<DWORD>(FakeGameModule);

	if (!MakePageWriteable(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x715A0)))
		return 0;

	if (!MakePageWriteable(reinterpret_cast<LPVOID>(0x00400A10)))
		return 0;

	fake_Variable_Send = reinterpret_cast<DWORD>(Gepard_Module) + 0x1D940;
	fake_Variable_Recv = reinterpret_cast<DWORD>(Gepard_Module) + 0x1E840;
	Hook_CRC(true);
	

	/* Inject bypass */

	if (!MakePageWriteable(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x1F7FC2)))
		return 0;

	memcpy(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x1F7FC2), "\x90\x90", 2);

	CreateThread(0, 0, [](LPVOID Arg)->DWORD
	{

		HMODULE Ntdll = GetModuleHandle("ntdll.dll");
		HMODULE Kernel32 = GetModuleHandle("Kernel32.dll");
		if (Ntdll == 0 || Kernel32 == 0) return 0;

		LPVOID LdrLoadDll_Addy = GetProcAddress(Ntdll, "LdrLoadDll");
		LPVOID LoadLibW_Addy = GetProcAddress(Kernel32, "LoadLibraryW");
		LPVOID LoadLibA_Addy = GetProcAddress(Kernel32, "LoadLibraryA");
		LPVOID KiUserExceptionDispatcher_Addy = GetProcAddress(Ntdll, "KiUserExceptionDispatcher");
		LPVOID DbgUiRemoteBreakin_Addy = GetProcAddress(Ntdll, "DbgUiRemoteBreakin");
		LPVOID RtlUnhandledExceptionFilter2_Addy = GetProcAddress(Ntdll, "RtlUnhandledExceptionFilter2");



		if (!MakePageWriteable(LdrLoadDll_Addy) ||
			!MakePageWriteable(LoadLibW_Addy) ||
			!MakePageWriteable(LoadLibA_Addy) ||
			!MakePageWriteable(KiUserExceptionDispatcher_Addy) ||
			!MakePageWriteable(DbgUiRemoteBreakin_Addy) ||
			!MakePageWriteable(RtlUnhandledExceptionFilter2_Addy))
			return false;

		while (*reinterpret_cast<BYTE*>(LdrLoadDll_Addy) != 0xE9)
			Sleep(100);
		memcpy(LdrLoadDll_Addy, LdrLoadDll_Bytes, 5);
		while (*reinterpret_cast<BYTE*>(LoadLibW_Addy) != 0xE9)
			Sleep(100);
		memcpy(LoadLibW_Addy, LoadLibW_Bytes, 5);
		while (*reinterpret_cast<BYTE*>(LoadLibA_Addy) != 0xE9)
			Sleep(100);
		memcpy(LoadLibA_Addy, LoadLibA_Bytes, 5);
		while (*reinterpret_cast<BYTE*>(KiUserExceptionDispatcher_Addy) != 0xE9)
			Sleep(100);
		memcpy(KiUserExceptionDispatcher_Addy, KiUserExceptionDispatcher_Bytes, 8);
		while (*reinterpret_cast<BYTE*>(DbgUiRemoteBreakin_Addy) != 0xE9)
			Sleep(100);
		memcpy(DbgUiRemoteBreakin_Addy, DbgUiRemoteBreakin_Bytes, 5);
		while (*reinterpret_cast<BYTE*>(RtlUnhandledExceptionFilter2_Addy) != 0xE9)
			Sleep(100);
		memcpy(RtlUnhandledExceptionFilter2_Addy, RtlUnhandledExceptionFilter2_Bytes, 8);


		while (true)
		{
			Sleep(120);
			if (*reinterpret_cast<DWORD*>(reinterpret_cast<DWORD>(Gepard_Module) + 0x715A0) != (reinterpret_cast<DWORD>(GameModule) + 0x1000))
				* reinterpret_cast<DWORD*>(reinterpret_cast<DWORD>(Gepard_Module) + 0x715A0) = reinterpret_cast<DWORD>(GameModule) + 0x1000;
			*reinterpret_cast<DWORD*>(0x00400A04) = reinterpret_cast<DWORD>(SendFunc);
			*reinterpret_cast<DWORD*>(0x00400A00) = reinterpret_cast<DWORD>(RecvFunc);
			*reinterpret_cast<DWORD*>(0x00400A10) = reinterpret_cast<DWORD>(LoadFile);
		}
		return 1;
	}, 0, 0, 0);
	
	return true;
}

extern "C" _declspec(dllexport) int get_gepard_version()
{
	if (Gepard_Module) return 0;
	LPVOID Function = GetProcAddress(Gepard_Module, "get_gepard_version");
	if (!Function) return 0;
	return reinterpret_cast<int(*)()>(Function)();
}

BOOL WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		PrepareBypass();
		return TRUE;
	}
	return TRUE;
}

bool Hook_FindFirstFileW(bool detourStatus)
{
	typedef HANDLE(WINAPI * p_FindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW Data);
	static p_FindFirstFileW o_FindFirstFileW = reinterpret_cast<p_FindFirstFileW>(GetProcAddress(GetModuleHandle("Kernel32.dll"), "FindNextFileW"));

	p_FindFirstFileW FindFirstFileW_Hook = [](LPCWSTR lpFileName, LPWIN32_FIND_DATAW Data)->HANDLE
	{
		DWORD_PTR dwStartAddress = 0;
		HMODULE hModule = 0;
		DWORD Old = 0;
		NTSTATUS Status = -1;
		if (NT_SUCCESS(NtQueryInformationThread(GetCurrentThread(), static_cast<THREADINFOCLASS>(9), &dwStartAddress, sizeof(DWORD_PTR), NULL)) &&
			GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<char*>(dwStartAddress), &hModule) && hModule == Gepard_Module ||
			GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<char*>(_ReturnAddress()), &hModule) && hModule == Gepard_Module)
		{
			return 0;
		}
		
		return o_FindFirstFileW(lpFileName, Data);
	};

	if (DetourTransactionBegin() != NO_ERROR ||
		DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
		(detourStatus ? DetourAttach : DetourDetach)(&(PVOID&)o_FindFirstFileW, FindFirstFileW_Hook) != NO_ERROR ||
		DetourTransactionCommit() != NO_ERROR)
		return false;
	return true;
}

bool Hook_CRC(bool detourStatus)
{
	LPVOID CRC_One = 0;
	if (!CRC_One)
	{
		CRC_One = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(Gepard_Module) + 0x34F13);
		CRC_1Back = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(CRC_One) + 0x6);
	}
	if (DetourTransactionBegin() != NO_ERROR ||
		DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
		(detourStatus ? DetourAttach : DetourDetach)(&(PVOID&)CRC_One, CRC_Hook1) != NO_ERROR ||
		DetourTransactionCommit() != NO_ERROR)
		return false;
	return true;
}

bool Hook_OpenProcess(bool detourStatus)
{
	typedef HANDLE(WINAPI * p_OpenProcess)(DWORD dwDesiredAccess,BOOL  bInheritHandle,DWORD dwProcessId);
	static p_OpenProcess o_OpenProcess = reinterpret_cast<p_OpenProcess>(GetProcAddress(GetModuleHandle("KERNELBASE"), "OpenProcess"));

	p_OpenProcess OpenProcess_Hook = [](DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId)->HANDLE
	{
		DWORD_PTR dwStartAddress = 0;
		HMODULE hModule = 0;
		DWORD Old = 0;
		NTSTATUS Status = -1;
		if (NT_SUCCESS(NtQueryInformationThread(GetCurrentThread(), static_cast<THREADINFOCLASS>(9), &dwStartAddress, sizeof(DWORD_PTR), NULL)) &&
			GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<char*>(dwStartAddress), &hModule) && hModule == Gepard_Module ||
			GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<char*>(_ReturnAddress()), &hModule) && hModule == Gepard_Module)
		{
			dwProcessId = GetCurrentProcessId();
		}
		return o_OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	};

	if (DetourTransactionBegin() != NO_ERROR ||
		DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
		(detourStatus ? DetourAttach : DetourDetach)(&(PVOID&)o_OpenProcess, OpenProcess_Hook) != NO_ERROR ||
		DetourTransactionCommit() != NO_ERROR)
		return false;
	return true;
}