#pragma once

#define HMODULE PVOID
#define PTR_OFFSET(_p, _offset) (PVOID)(((PBYTE)_p) + (_offset))
#define RVATOVA(base,offset) ((DWORD)((DWORD)(base)+(DWORD)(offset)))
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0

typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef BYTE                *PBYTE;
typedef WORD                *PWORD;
typedef DWORD               *PDWORD;

typedef struct
{
	PVOID *ServiceTable;
	ULONG LowCall;
	ULONG HiCall;
	PBYTE ArgTable;
} SRVTABLE, *PSRVTABLE;

typedef struct _IMAGE_DATA_DIRECTORY
{
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER
{
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

//
// Optional header format.
//

typedef struct _IMAGE_OPTIONAL_HEADER
{
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	//
	// NT additional fields.
	//

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Reserved1;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS
{
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	PDWORD  *AddressOfFunctions;
	PDWORD  *AddressOfNames;
	PWORD   *AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,                 // 0 Y N
	SystemProcessorInformation,             // 1 Y N
	SystemPerformanceInformation,           // 2 Y N
	SystemTimeOfDayInformation,             // 3 Y N
	SystemNotImplemented1,                  // 4 Y N
	SystemProcessesAndThreadsInformation,   // 5 Y N
	SystemCallCounts,                       // 6 Y N
	SystemConfigurationInformation,         // 7 Y N
	SystemProcessorTimes,                   // 8 Y N
	SystemGlobalFlag,                       // 9 Y Y
	SystemNotImplemented2,                  // 10 Y N
	SystemModuleInformation,                // 11 Y N
	SystemLockInformation,                  // 12 Y N
	SystemNotImplemented3,                  // 13 Y N
	SystemNotImplemented4,                  // 14 Y N
	SystemNotImplemented5,                  // 15 Y N
	SystemHandleInformation,                // 16 Y N
	SystemObjectInformation,                // 17 Y N
	SystemPagefileInformation,              // 18 Y N
	SystemInstructionEmulationCounts,       // 19 Y N
	SystemInvalidInfoClass1,                // 20
	SystemCacheInformation,                 // 21 Y Y
	SystemPoolTagInformation,               // 22 Y N
	SystemProcessorStatistics,              // 23 Y N
	SystemDpcInformation,                   // 24 Y Y
	SystemNotImplemented6,                  // 25 Y N
	SystemLoadImage,                        // 26 N Y
	SystemUnloadImage,                      // 27 N Y
	SystemTimeAdjustment,                   // 28 Y Y
	SystemNotImplemented7,                  // 29 Y N
	SystemNotImplemented8,                  // 30 Y N
	SystemNotImplemented9,                  // 31 Y N
	SystemCrashDumpInformation,             // 32 Y N
	SystemExceptionInformation,             // 33 Y N
	SystemCrashDumpStateInformation,        // 34 Y Y/N
	SystemKernelDebuggerInformation,        // 35 Y N
	SystemContextSwitchInformation,         // 36 Y N
	SystemRegistryQuotaInformation,         // 37 Y Y
	SystemLoadAndCallImage,                 // 38 N Y
	SystemPrioritySeparation,               // 39 N Y
	SystemNotImplemented10,                 // 40 Y N
	SystemNotImplemented11,                 // 41 Y N
	SystemInvalidInfoClass2,                // 42
	SystemInvalidInfoClass3,                // 43
	SystemTimeZoneInformation,              // 44 Y N
	SystemLookasideInformation,             // 45 Y N
	SystemSetTimeSlipEvent,                 // 46 N Y
	SystemCreateSession,                    // 47 N Y
	SystemDeleteSession,                    // 48 N Y
	SystemInvalidInfoClass4,                // 49
	SystemRangeStartInformation,            // 50 Y N
	SystemVerifierInformation,              // 51 Y Y
	SystemAddVerifier,                      // 52 N Y
	SystemSessionProcessesInformation       // 53 Y N
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION
{ // Information Class 11

	/*000*/ ULONG Reserved[2];
	// The base address of the module.
	/*008*/ PVOID Base;
	// The size of the module.
	/*00ñ*/ ULONG Size;
	// A bit array of flags describing the state of the module.
	/*010*/ ULONG Flags;
	// The index of the module in the array of modules.
	/*014*/ USHORT Index;
	// Normally contains zero; interpretation unknown.
	/*016*/ USHORT Unknown;
	// The number of references to the module.
	/*018*/ USHORT LoadCount;
	// The offset to the final filename component of the image name.
	/*01a*/ USHORT ModuleNameOffset;
	// The filepath of the module.
	/*01c*/ CHAR ImageName[256];
	/*11c*/
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);