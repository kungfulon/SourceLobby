#include <tier1/tier1.h>
#include <tier1/utlhashtable.h>
#include <capstone/capstone.h>

#include "detour.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// memdbgon must be the last include file in a .cpp file!!!
#include <tier0/memdbgon.h>

class Detour : public IDetour
{
public:
    bool Initialize();
    void Shutdown();
    void* CreateHook(void* addr, void* hookFunc);
    bool EnableHook(void* hook);
    bool DisableHook(void* hook);
    void DestroyHook(void* hook);

private:
    struct PatchInfo
    {
        void* addr;
        uint8 original[5];
        uint8 patched[5];
    };

    csh cs;
    CUtlHashtable<void*, PatchInfo> hooks;

    uint8* trampolineBase;
    uint8* trampolineCur;
};

static Detour detourSingleton;
IDetour* detour = (IDetour *)&detourSingleton;

static void memcpyRWX(void* dst, void* src, size_t size)
{
    DWORD oldProtect;
    VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(dst, src, size);
    VirtualProtect(dst, size, oldProtect, &oldProtect);
}

static void generateJMP(void* fn, void* target, uint8* out)
{
    out[0] = 0xE9u;
    *(uint32*)(out + 1) = (uint32)target - (uint32)fn - 5;
}

bool Detour::Initialize()
{
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs) != CS_ERR_OK)
        return false;

    auto mem = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mem == NULL)
        return false;

    trampolineBase = trampolineCur = (uint8*)mem;
    return true;
}

void Detour::Shutdown()
{
    FOR_EACH_HASHTABLE(hooks, i)
        DisableHook(hooks.Key(i));

    hooks.Purge();
    VirtualFree(trampolineBase, 0, MEM_RELEASE);
    cs_close(&cs);
}

void* Detour::CreateHook(void* addr, void* hookFunc)
{
    PatchInfo pi;
    pi.addr = addr;
    memcpy(pi.original, addr, sizeof(pi.original));
    generateJMP(addr, hookFunc, pi.patched);
    
    const uint8* code = (uint8*)addr;
    size_t size = 32;
    uint64 address = (uint64)addr;
    cs_insn* ins = cs_malloc(cs);
    uint8* trampoline = trampolineCur;
    
    while (size > 27)
    {
        cs_disasm_iter(cs, &code, &size, &address, ins);
        
        switch (ins->bytes[0])
        {
        case 0xE8u:
        case 0xE9u:
            generateJMP(trampolineCur, (void*)(code + *(uint32*)(ins->bytes + 1)), trampolineCur);
            trampolineCur[0] = ins->bytes[0];
            trampolineCur += 5;
            break;
        case 0xEBu:
            generateJMP(trampolineCur, (void*)(code + ins->bytes[1]), trampolineCur);
            trampolineCur += 5;
            break;
        default:
            memcpy(trampolineCur, ins->bytes, ins->size);
            trampolineCur += ins->size;
        }
    }

    generateJMP(trampolineCur, (void*)code, trampolineCur);
    trampolineCur += 5;

    cs_free(ins, 1);
    hooks.Insert(trampoline, pi);
    return trampoline;
}

bool Detour::EnableHook(void* hook)
{
    auto i = hooks.Find(hook);
    if (i == hooks.InvalidHandle())
        return false;

    const auto& pi = hooks[i];
    memcpyRWX(pi.addr, (void*)pi.patched, sizeof(pi.patched));
    return true;
}

bool Detour::DisableHook(void* hook)
{
    auto i = hooks.Find(hook);
    if (i == hooks.InvalidHandle())
        return false;

    const auto& pi = hooks[i];
    memcpyRWX(pi.addr, (void*)pi.original, sizeof(pi.original));
    return true;
}

void Detour::DestroyHook(void* hook)
{
    DisableHook(hook);
    hooks.Remove(hook);
}

bool HookIAT(CSysModule* module, const char* importModule, uint16 ordinal, void* hookFunc)
{
    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((uint8*)module + dosHeader->e_lfanew);
    auto importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDirectory.Size == 0)
        return false;

    for (auto importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((uint8*)module + importDirectory.VirtualAddress);
        importDescriptor->OriginalFirstThunk != NULL;
        ++importDescriptor)
    {
        const char* moduleName = (const char*)((uint8*)module + importDescriptor->Name);
        if (V_stricmp(importModule, moduleName))
            continue;

        auto ilt = (PIMAGE_THUNK_DATA)((uint8*)module + importDescriptor->OriginalFirstThunk);
        auto iat = (PIMAGE_THUNK_DATA)((uint8*)module + importDescriptor->FirstThunk);
        for (; ilt->u1.AddressOfData != NULL; ++ilt, ++iat)
        {
            if ((ilt->u1.Ordinal & IMAGE_ORDINAL_FLAG) && IMAGE_ORDINAL(ilt->u1.Ordinal) == ordinal)
            {
                memcpyRWX(&iat->u1.Function, &hookFunc, sizeof(iat->u1.Function));
                return true;
            }
        }
    }

    return false;
}
