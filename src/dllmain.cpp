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

void FixMemory()
{
	// Disable memory checks 
	injector::WriteMemory<int>(0x00464EE6, 0x9090C031, true);
	injector::WriteMemory<int>(0x00464F47, 0x9090C031, true);
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
}

void Init()
{
	ReadConfig();
	AddPurecallHandler();
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