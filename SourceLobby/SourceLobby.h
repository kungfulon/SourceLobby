#ifndef SOURCELOBBY_H
#define SOURCELOBBY_H
#pragma once

#include <steam/steam_api.h>
#include "steam/isteamnetworkingmessages.h"
#include "steam/isteamnetworkingutils.h"

class SteamAPIContext : public CSteamAPIContext
{
public:
    bool Init()
    {
        if (!CSteamAPIContext::Init())
            return false;

        if (!SteamClient())
            return false;

        HSteamUser hSteamUser = SteamAPI_GetHSteamUser();
        HSteamPipe hSteamPipe = SteamAPI_GetHSteamPipe();

        m_pSteamNetworkingMessages = (ISteamNetworkingMessages*)SteamClient()->GetISteamGenericInterface(hSteamUser, hSteamPipe, STEAMNETWORKINGMESSAGES_INTERFACE_VERSION);
        if (m_pSteamNetworkingMessages == nullptr)
            return false;

        m_pSteamNetworkingUtils = (ISteamNetworkingUtils*)SteamClient()->GetISteamGenericInterface(hSteamUser, hSteamPipe, STEAMNETWORKINGUTILS_INTERFACE_VERSION);
        if (m_pSteamNetworkingUtils == nullptr)
            return false;

        return true;
    }

    void Clear()
    {
        CSteamAPIContext::Clear();

        m_pSteamNetworkingMessages = nullptr;
        m_pSteamNetworkingUtils = nullptr;
    }

    ISteamNetworkingMessages* SteamNetworkingMessages() { return m_pSteamNetworkingMessages; }
    ISteamNetworkingUtils* SteamNetworkingUtils() { return m_pSteamNetworkingUtils; }

private:
    ISteamNetworkingMessages* m_pSteamNetworkingMessages;
    ISteamNetworkingUtils* m_pSteamNetworkingUtils;
};

extern SteamAPIContext steam;

#endif // SOURCELOBBY_H
