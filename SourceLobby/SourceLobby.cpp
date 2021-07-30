#include "hooks.h"

#include <engine/iserverplugin.h>
#include <tier1/tier1.h>

#include "SourceLobby.h"

// memdbgon must be the last include file in a .cpp file!!!
#include "tier0/memdbgon.h"

class SourceLobby : public IServerPluginCallbacks
{
public:
	bool Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory);
	void Unload();
	void Pause();
	void UnPause();
	const char* GetPluginDescription();
	void LevelInit(char const* pMapName);
	void ServerActivate(edict_t* pEdictList, int edictCount, int clientMax);
	void GameFrame(bool simulating);
	void LevelShutdown(void);
	void ClientActive(edict_t* pEntity);
	void ClientDisconnect(edict_t* pEntity);
	void ClientPutInServer(edict_t* pEntity, char const* playername);
	void SetCommandClient(int index);
	void ClientSettingsChanged(edict_t* pEdict);
	PLUGIN_RESULT ClientConnect(bool* bAllowConnect, edict_t* pEntity, const char* pszName, const char* pszAddress, char* reject, int maxrejectlen);
	PLUGIN_RESULT ClientCommand(edict_t* pEntity, const CCommand& args);
	PLUGIN_RESULT NetworkIDValidated(const char* pszUserName, const char* pszNetworkID);
	void OnQueryCvarValueFinished(QueryCvarCookie_t iCookie, edict_t* pPlayerEntity, EQueryCvarValueStatus eStatus, const char* pCvarName, const char* pCvarValue);
	void OnEdictAllocated(edict_t* edict);
	void OnEdictFreed(const edict_t* edict);

	STEAM_CALLBACK(SourceLobby, OnSteamNetworkingMessagesSessionRequest, SteamNetworkingMessagesSessionRequest_t);
};

SteamAPIContext steam;
SourceLobby sourceLobby;
EXPOSE_SINGLE_INTERFACE_GLOBALVAR(SourceLobby, IServerPluginCallbacks, INTERFACEVERSION_ISERVERPLUGINCALLBACKS, sourceLobby);

bool SourceLobby::Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory)
{
	if (!steam.Init())
		return false;

	if (!InitializeHooks())
		return false;

	ConnectTier1Libraries(&interfaceFactory, 1);
	ConVar_Register();

	return true;
}

void SourceLobby::Unload()
{
	ConVar_Unregister();
	DisconnectTier1Libraries();

	ShutdownHooks();

	steam.Clear();
}

void SourceLobby::Pause()
{
}

void SourceLobby::UnPause()
{
}

const char* SourceLobby::GetPluginDescription()
{
	return "SourceLobby";
}

void SourceLobby::LevelInit(char const* pMapName)
{
}

void SourceLobby::ServerActivate(edict_t* pEdictList, int edictCount, int clientMax)
{
	auto accountID = steam.SteamUser()->GetSteamID().GetAccountID();
	char connectString[256];
	V_snprintf(connectString, sizeof(connectString), "+connect STEAM_%u:%u:%u", k_EUniversePublic, accountID & 1, accountID >> 1);
	steam.SteamFriends()->SetRichPresence("connect", connectString);
}

void SourceLobby::GameFrame(bool simulating)
{
}

void SourceLobby::LevelShutdown(void)
{
	steam.SteamFriends()->SetRichPresence("connect", nullptr);
}

void SourceLobby::ClientActive(edict_t* pEntity)
{
}

void SourceLobby::ClientDisconnect(edict_t* pEntity)
{
}

void SourceLobby::ClientPutInServer(edict_t* pEntity, char const* playername)
{
}

void SourceLobby::SetCommandClient(int index)
{
}

void SourceLobby::ClientSettingsChanged(edict_t* pEdict)
{
}

PLUGIN_RESULT SourceLobby::ClientConnect(bool* bAllowConnect, edict_t* pEntity, const char* pszName, const char* pszAddress, char* reject, int maxrejectlen)
{
	return PLUGIN_CONTINUE;
}

PLUGIN_RESULT SourceLobby::ClientCommand(edict_t* pEntity, const CCommand& args)
{
	return PLUGIN_CONTINUE;
}

PLUGIN_RESULT SourceLobby::NetworkIDValidated(const char* pszUserName, const char* pszNetworkID)
{
	return PLUGIN_CONTINUE;
}

void SourceLobby::OnQueryCvarValueFinished(QueryCvarCookie_t iCookie, edict_t* pPlayerEntity, EQueryCvarValueStatus eStatus, const char* pCvarName, const char* pCvarValue)
{
}

void SourceLobby::OnEdictAllocated(edict_t* edict)
{
}

void SourceLobby::OnEdictFreed(const edict_t* edict)
{
}

void SourceLobby::OnSteamNetworkingMessagesSessionRequest(SteamNetworkingMessagesSessionRequest_t* params)
{
	steam.SteamNetworkingMessages()->AcceptSessionWithUser(params->m_identityRemote);
}
