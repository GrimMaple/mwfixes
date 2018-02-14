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


/*
 *	Patch note	00464EE6
 *				00464F47 mov	eax, [esp+20h+use_best_fit]
 *
 *	Changed that to 
 *	xor eax, eax
 *	
 *	to manually fail the "use_best_fit" test
*/
void FixMemory()
{
	// Disable memory checks 
	injector::WriteMemory<int>(0x00464EE6, 0x9090C031, true);	// xor eax, eax
																// nop
																// nop

	injector::WriteMemory<int>(0x00464F47, 0x9090C031, true);	// xor eax, eax
																// nop
																// nop
}

/*
 *	Patch note: 0057D105 mov edx, [ecx] ; possible null-pointer.
 *
 *	Can sometimes happen when unloading cops (? or roadblocks ?)
 *
 *	Added sanity checks to not dereference null
 */
void FixSub_0057D0F0()
{
	char fix[] = { 0x85, 0xC9, 		// test ecx, ecx
				   0x74, 0xFA, 		// je 057d11f
				   0x8B, 0x11, 		// mov edx, [ecx]
				   0xEB, 0xDE, };	// jmp 0057D107

	char call[] = { 0xEB, 0x1A };	// jmp 0057D121

	injector::WriteMemoryRaw(0x0057D121, fix, sizeof(fix), true);
	injector::WriteMemoryRaw(0x0057D105, call, sizeof(call), true);
}

void FixPurecall()
{
	if (!PreventPurecalls)
		return;

	/*
	 *		Patch idea: the edx contains a ptr to class vtbl
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
	 *
	 *		Sliced in parts because of space limitations
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

/*
 *	Patch note: replace default _purecall handler to generate dumps
 *
 *	Replaces a call to a random nullsub
 */
void AddPurecallHandler()
{
	if (!ShouldAddPurecallHandler)
		return;
	char handler[] = { 0x31, 0xC0,							// xor eax, eax
					   0x8B, 0x00,							// mov eax, [eax]	; crashes immediately 
					   0xC3 };								// ret				; just in case

	char replaceHandler[] = { 0x68, 0xB0, 0X56, 0x7C, 0x00, // push 007C56B0	; new purecall handler address
							  0xE8, 0x61, 0xFB, 0xFF, 0xFF, // call 007C5220	; _set_purecall_handler
							  0x83, 0xC4, 0x04,				// add  esp, 04h	; restore stack (__cdecl)
							  0xC3 };						// ret

	char callPatch[] = { 0xE8, 0x7B, 0x19, 0x16, 0x00 };	// call 007C56B5

	injector::WriteMemoryRaw(0x007C56B0, handler, sizeof(handler), true);
	injector::WriteMemoryRaw(0x007C56B5, replaceHandler, sizeof(replaceHandler), true);

	// replaces a call to a nullsub
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


/*
 *	Patch note: 004549BF mov al, [edi]	; potentional dereferencing a null pointer
 *
 *	Attrib::StringToLowerCaseKey(const char* str) -- Happened if str was null
 */
void FixStringToLower()
{
	char newInstructions[] = { 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00,	// add esp, 100h	; restore esp
							   0x31, 0xC0,							// xor eax, eax		; return 0
							   0xC3 };								// ret

	// Fixes Attrib::StringToLowerCaseKey
	injector::WriteMemory<short>(0x004549BF, 0xE0EB, true);			// jump to patched code

	injector::WriteMemory<int>(0x004549A1, 0x0775FF85, true);		// test edi, edi
																	// jne	004549AC

	injector::WriteMemory<int>(0x004549A5, 0xB9EB5E5F, true);		// pop edi
																	// pop esi
																	// jmp 00454962

	injector::WriteMemory<int>(0x004549AC, 0x11EB078A, true);		// mov al,[edi]
																	// jmp 004549C1		; return to normal operation

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
	FixSub_0057D0F0();
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