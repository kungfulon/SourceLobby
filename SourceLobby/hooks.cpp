#include "hooks.h"

#include <tier1/tier1.h>
#include <tier1/netadr.h>

#include <winsock2.h>

#include "detour.h"
#include "SourceLobby.h"

// memdbgon must be the last include file in a .cpp file!!!
#include "tier0/memdbgon.h"

static constexpr uint16 P2P_PORT = 1;

static constexpr uint16 SENDTO_ORDINAL = 20;

static constexpr const uint8 NET_StringToAdrPattern[] =
{ 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00, 0x8D, 0x85, 0xCC, 0xCC, 0xCC, 0xCC, 0x68, 0x80, 0x00, 0x00, 0x00, 0xFF, 0x75, 0xCC, 0x50, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x6A, 0x0A, 0x8D, 0x85 };

static constexpr const uint8 CheckIPRestrictionsPattern[] = 
{ 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0xCC, 0x8B, 0xCE, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x84, 0xC0, 0x75, 0xCC, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x83, 0xB8, 0xCC, 0x00, 0x00, 0x00, 0x01, 0x75, 0xCC, 0x68 };

typedef int (*trecvfrom)(int s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
static trecvfrom _recvfrom;

int RecvFrom(int s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
    SteamNetworkingMessage_t* msg;
    if (steam.SteamNetworkingMessages()->ReceiveMessagesOnChannel(0, &msg, 1) == 0)
        return _recvfrom(s, buf, len, flags, from, fromlen);

    int msgLen = (int)msg->GetSize();

    if (len < msgLen)
    {
        msg->Release();
        WSASetLastError(WSAEMSGSIZE);
        return SOCKET_ERROR;
    }

    auto* addr = (sockaddr_in*)from;
    addr->sin_family = AF_INET;
    addr->sin_addr.S_un.S_addr = msg->m_identityPeer.GetSteamID().GetAccountID();
    addr->sin_port = htons(P2P_PORT);
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));
    memcpy(buf, msg->GetData(), msgLen);
    msg->Release();

    WSASetLastError(0);
    return msgLen;
}

int WSAAPI SendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    auto* addr = (const sockaddr_in*)to;
    if (addr->sin_port != htons(P2P_PORT))
        return sendto(s, buf, len, flags, to, tolen);

    // Only support individual for now.
    CSteamID remote;
    remote.Set(addr->sin_addr.S_un.S_addr, k_EUniversePublic, k_EAccountTypeIndividual);

    SteamNetworkingIdentity identity;
    identity.SetSteamID(remote);
    auto result = steam.SteamNetworkingMessages()->SendMessageToUser(identity, buf, len, k_nSteamNetworkingSend_Unreliable | k_nSteamNetworkingSend_AutoRestartBrokenSession, 0);
    if (result != k_EResultOK)
    {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }

    WSASetLastError(0);
    return len;
}

typedef bool (*tNET_StringToAdr)(const char* s, netadr_t* a);
static tNET_StringToAdr _NET_StringToAdr;

bool NET_StringToAdr(const char* s, netadr_t* a)
{
    if (strncmp(s, "STEAM_", 6))
        return _NET_StringToAdr(s, a);

    EUniverse universe;
    uint32 authServer;
    uint32 accountNumber;
    sscanf(s, "STEAM_%u:%u:%u", &universe, &authServer, &accountNumber);

    // Only support individual for now.
    CSteamID steamID;
    steamID.Set((accountNumber << 1) | authServer, k_EUniversePublic, k_EAccountTypeIndividual);
    *(uint32*)a->ip = steamID.GetAccountID();
    a->port = htons(P2P_PORT);
    a->type = NA_IP;
    
    return true;
}

typedef bool(__fastcall* tCheckIPRestrictions)(class CBaseServer* _this, uint32 _edx, const netadr_t& adr, int nAuthProtocol);
static tCheckIPRestrictions _CheckIPRestrictions;

bool __fastcall CheckIPRestrictions(class CBaseServer* _this, uint32 _edx, const netadr_t& adr, int nAuthProtocol)
{
    if (adr.GetPort() == P2P_PORT)
        return true;

    return _CheckIPRestrictions(_this, _edx, adr, nAuthProtocol);
}

static uint8* ScanPattern(uint8* start, int size, const uint8* pattern, int patternLen)
{
    auto comp = [](uint8* i, const uint8* pattern, int patternLen)
    {
        for (auto j = 0; j < patternLen; ++j)
        {
            if (pattern[j] == 0xCC)
                continue;
            if (i[j] != pattern[j])
                return false;
        }
        return true;
    };
    for (auto* i = start; i + patternLen <= start + size; ++i)
    {
        if (comp(i, pattern, patternLen))
            return i;
    }
    return nullptr;
}

static uint8* ScanPattern(CSysModule* module, const uint8* pattern, int patternLen)
{
    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((uint8*)module + dosHeader->e_lfanew);
    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader)
    {
        if (!(sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) ||
            !(sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        auto* p = ScanPattern((uint8*)module + sectionHeader->VirtualAddress, sectionHeader->Misc.VirtualSize, pattern, patternLen);
        if (p != nullptr)
            return p;
    }
    return nullptr;
}

bool InitializeHooks()
{
    if (!detour->Initialize())
        return false;

    _recvfrom = g_pVCR->Hook_recvfrom;
    g_pVCR->Hook_recvfrom = RecvFrom;

    auto engineModule = Sys_LoadModule("engine" DLL_EXT_STRING);

    HookIAT(engineModule, "wsock32.dll", SENDTO_ORDINAL, SendTo);

    auto NET_StringToAdrAddr = ScanPattern(engineModule, NET_StringToAdrPattern, sizeof(NET_StringToAdrPattern));
    if (NET_StringToAdrAddr != nullptr)
    {
        _NET_StringToAdr = (tNET_StringToAdr)detour->CreateHook(NET_StringToAdrAddr, NET_StringToAdr);
        detour->EnableHook(_NET_StringToAdr);
    }

    auto CheckIPRestrictionsAddr = ScanPattern(engineModule, CheckIPRestrictionsPattern, sizeof(CheckIPRestrictionsPattern));
    if (CheckIPRestrictionsAddr != nullptr)
    {
        _CheckIPRestrictions = (tCheckIPRestrictions)detour->CreateHook(CheckIPRestrictionsAddr, CheckIPRestrictions);
        detour->EnableHook(_CheckIPRestrictions);
    }

    return true;
}

void ShutdownHooks()
{
    auto engineModule = Sys_LoadModule("engine" DLL_EXT_STRING);
    HookIAT(engineModule, "wsock32.dll", SENDTO_ORDINAL, sendto);
    g_pVCR->Hook_recvfrom = _recvfrom;
    detour->Shutdown();
}
