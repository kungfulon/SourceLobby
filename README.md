# SourceLobby

P2P networking support for Source Engine games, mainly for Source 2013 branch.

## Building

Use Visual Studio 2015 build tools to build the project.

Make sure to clone submodules.

## Installation

Install `SourceLobby.dll` as a plugin. General plugin installation available here: https://developer.valvesoftware.com/wiki/Server_plugins.

Since the DLL is unsigned, the game must be run in `insecure` mode in order to load the library.

Use `connect <STEAMID>`, for example `connect STEAM_0:0:1111110` to connect to other player's listen server.

Also after a player has hosted the game, other players can use `Join Game` button in Steam friend list.

Note that you cannot connect to other players that are not using this library.

## License

This project is licensed under MIT License.

This project used Source SDK 2013. The license is available at https://github.com/ValveSoftware/source-sdk-2013/blob/master/LICENSE.

This project uses Steamworks SDK. The license is available at https://partner.steamgames.com/documentation/sdk_access_agreement. 

This project uses Capstone Disassembly Engine. The license is available at https://github.com/aquynh/capstone/blob/master/LICENSE.TXT.
