#include <Windows.h>
#include <injector\injector.hpp>
#include <IniReader.h>

// Timebug fixing stuff
DWORD GlobalTimerAddress = 0x009885D8;
DWORD TimerAddress = 0x009142DC;
float PreviousRaceTime = 0.0f;
bool TimebugFixEnabled = 0;
bool StabilityPatchesEnabled = 0;
bool ShouldAddPurecallHandler = 0;
bool PreventPurecalls = 0;

void FixMemory()
{
	// Disable memory checks 
	injector::WriteMemory<int>(0x00464EE6, 0x9090C031, true);
	injector::WriteMemory<int>(0x00464F47, 0x9090C031, true);
}

void FixPurecall()
{
	if (!PreventPurecalls)
		return;

	/*
	 *		Pathc idea: the edx contains a ptr to class vtbl
	 *		since we know that, we can determine the failing class (vtbl @ 0x00890970)
	 *		if we catch this failing class, exit the function with 0 immideatly,
	 *		otherwise continue as normal.
	 *
	 *		Pseudocode:
	 *
	 *		cmp edx, 00890970h		; if edx != 0x00890970
	 *		jne normal_operation	; continue normal operation
	 *		xor eax, eax			; else eax = 0 (result = 0)
	 *		jmp return				; exit the function
	 *	normal_operation:
	 *		call dword ptr[edx+80h] ; call the virtual function if it exists
	 *		jmp continue			; continue normal operation
	 */

	char callFix[] = { 0xE9, 0x0B, 0xFD, 0xFF, 0xFF, 		// jmp 0043DD15h
					   0x90 };								// nop

	char fixDD15[] = { 0x81, 0xFA, 0x70, 0x09, 0x89, 0x00,	// cmp edx, 00890970h
					   0x75, 0xD8,							// jne 0043DCF5h
					   0xEb, 0xC6 };						// jmp 0043DCE5h

	char fixDCF5[] = { 0xFF, 0x92, 0x80, 0x00, 0x00, 0x00,	// call dword ptr[edx+ACh]
					   0xE9, 0x0B, 0x03, 0x00, 0x00 };		// jmp  0043E00Bh

	char fixDCE5[] = { 0x31, 0xC0, 							// xor eax, eax
					   0xE9, 0x20, 0x05, 0x00, 0x00 };		// jmp 0043E20Ch

	injector::WriteMemoryRaw(0x0043E005, callFix, sizeof(callFix), true);	// patch call
	injector::WriteMemoryRaw(0x0043DD15, fixDD15, sizeof(fixDD15), true);
	injector::WriteMemoryRaw(0x0043DCF5, fixDCF5, sizeof(fixDCF5), true);
	injector::WriteMemoryRaw(0x0043DCE5, fixDCE5, sizeof(fixDCE5), true);

}

void AddPurecallHandler()
{
	if (!ShouldAddPurecallHandler)
		return;
	char handler[] = { 0x31, 0xC0, 0x8B, 0x00, 0xC3 };
	char replaceHandler[] = { 0x68, 0xB0, 0X56, 0x7C, 0x00, 0xE8, 0x61, 0xFB, 0xFF, 0xFF, 0x83, 0xC4, 0x04, 0xC3 };
	char callPatch[] = { 0xE8, 0x7B, 0x19, 0x16, 0x00 };

	injector::WriteMemoryRaw(0x007C56B0, handler, sizeof(handler), true);
	injector::WriteMemoryRaw(0x007C56B5, replaceHandler, sizeof(replaceHandler), true);
	injector::WriteMemoryRaw(0x00663D35, callPatch, sizeof(callPatch), true);
}

void FixTimebug()
{
	if (!TimebugFixEnabled)
		return;
	float tmpTime = injector::ReadMemory<float>(TimerAddress);
	if (tmpTime < PreviousRaceTime)
	{
		injector::WriteMemory<float>(GlobalTimerAddress, 0.0f);
	}
	PreviousRaceTime = tmpTime;
}

void FixStringToLower()
{
	char newInstructions[] = { 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00, 0x31, 0xC0, 0xC3 };

	// Fixes Attrib::StringToLowerCaseKey
	injector::WriteMemory<short>(0x004549BF, 0xE0EB, true);

	injector::WriteMemory<int>(0x004549A1, 0x0775FF85, true);
	injector::WriteMemory<int>(0x004549A5, 0xB9EB5E5F, true);
	injector::WriteMemory<int>(0x004549AC, 0x11EB078A, true);

	injector::WriteMemoryRaw(0x00454962, newInstructions, sizeof(newInstructions), true);
}

void ReadConfig()
{
	CIniReader iniReader("MWFixes.ini");

	TimebugFixEnabled = iniReader.ReadInteger("Fixes", "TimebugFix", 0) == 1;
	StabilityPatchesEnabled = iniReader.ReadInteger("Fixes", "StabilityFixes", 0) == 1;
	ShouldAddPurecallHandler = iniReader.ReadInteger("Fixes", "AddPurecallHandler", 0) == 1;
	PreventPurecalls = iniReader.ReadInteger("Fixes", "PreventPurecall", 0) == 1;
}

void Init()
{
	ReadConfig();
	AddPurecallHandler();
	FixPurecall();
	if (!StabilityPatchesEnabled)
		return;
	FixMemory();
	FixStringToLower();
}

DWORD WINAPI Background(LPVOID unused)
{
	while (true)
	{
		FixTimebug();
		Sleep(1);
	}
}

int WINAPI DllMain(HMODULE hInstance, DWORD reason, LPVOID lpReserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
		IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)(base);
		IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);


		// Copy-paste from MWExtraOptions
		if ((base + nt->OptionalHeader.AddressOfEntryPoint + (0x400000 - base)) == 0x7C4040) // Check if .exe file is compatible - Thanks to thelink2012 and MWisBest
		{
			Init();
			CreateThread(0, 0, Background, NULL, 0, NULL);
		}
		else
		{
			MessageBoxA(NULL, "This .exe is not supported.\nPlease use v1.3 English speed.exe (5,75 MB (6.029.312 bytes)).", "MWFixes", MB_ICONERROR);
			return FALSE;
		}
	}
	return TRUE;
}