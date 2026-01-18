#pragma once

#include "main.h"
#include "memory.h"
#include "secure.h"

SAMPFramework* pSAMP;

namespace fs = std::filesystem;

static stSAMP* samp = NULL;

stTextdraw* CreateTextDraw(int nId, stTextDrawTransmit* pTransmit, const char* szText)
{
	struct stSAMP* g_SAMP;
	g_SAMP = *(stSAMP**)(pSAMP->g_dwSAMP_Addr + SAMP_INFO_OFFSET);
	return ((stTextdraw * (__thiscall*)(stTextdrawPool*, int, stTextDrawTransmit*, const char*))(pSAMP->g_dwSAMP_Addr + 0x1AE20))(g_SAMP->pPools->pTextdraw, nId, pTransmit, szText);
}

bool SAMPFramework::tryInit(void)
{
	g_SAMP = *(stSAMP**)(g_dwSAMP_Addr + SAMP_INFO_OFFSET);

	if (g_SAMP == nullptr)
		return false;

	g_Chat = *(stChatInfo**)(g_dwSAMP_Addr + SAMP_CHAT_INFO_OFFSET);

	if (g_Chat == nullptr)
		return false;

	g_Input = *(stInputInfo**)(g_dwSAMP_Addr + SAMP_CHAT_INPUT_INFO_OFFSET);

	if (g_Input == nullptr)
		return false;

	if (g_SAMP->pRakClientInterface == nullptr)
		return false;

	g_RakClient = (RakClientInterface*)g_SAMP->pRakClientInterface;

	g_Vehicles = g_SAMP->pPools->pVehicle;
	g_Players = g_SAMP->pPools->pPlayer;

	stTextDrawTransmit ts;
	ts.fX = 6.0f;
	ts.fY = 435.0f;
	ts.byteStyle = 1;
	ts.fLetterWidth = 0.120f;
	ts.fLetterHeight = 0.8f;
	ts.fBoxWidth = 398.0f;
	ts.fBoxHeight = 17.0f;
	ts.byteOutline = 1;
	ts.byteShadow = 0;
	ts.dwLetterColor = -76;
	ts.dwBackgroundColor = 0x4D4D4D50;
	ts.dwBoxColor = 50;
	ts.byteFlags = 1;

	CreateTextDraw(1337, &ts, "wraithclient v1.0.3");

	isInited = true;

	return true;
};

void SAMPFramework::addMessageToChat(D3DCOLOR cColor, char *szMsg, ...)
{
	if (g_Chat == nullptr)
		return;

	void(__thiscall *AddToChatWindowBuffer) (const void *_this, int iType, char *szText, char *szPrefix, DWORD cColor, DWORD cPrefixColor) =
		(void(__thiscall *) (const void *, int, char *, char *, DWORD, DWORD)) (g_dwSAMP_Addr + SAMP_FUNC_ADDTOCHATWND);

	if (szMsg == NULL)
		return;

	va_list ap;
	char tmp[512];
	memset(tmp, 0, 512);
	va_start(ap, szMsg);
	vsnprintf(tmp, sizeof(tmp) - 1, szMsg, ap);
	va_end(ap);

	return AddToChatWindowBuffer((void *) g_Chat, 8, tmp, NULL, cColor, 0x00);
}

void SAMPFramework::addClientCommand(char *szCmd, CMDPROC pFunc)
{
	if (g_Input == nullptr)
		return;

	void(__thiscall *AddClientCommand) (const void *_this, char *szCommand, CMDPROC pFunc) =
		(void(__thiscall *) (const void *, char *, CMDPROC)) (g_dwSAMP_Addr + SAMP_FUNC_ADDCLIENTCMD);

	if (szCmd == NULL)
		return;

	return AddClientCommand(g_Input, szCmd, pFunc);
}

void addSayToChatWindow(char* msg)
{
	if (pSAMP == NULL || msg == NULL)
		return;

	if (msg[0] == '/')
		((void(__thiscall*) (void* _this, char* message)) (pSAMP->g_dwSAMP_Addr + 0x65C60))(pSAMP->getInput(), msg);
	else
		((void(__thiscall*) (void* _this, char* message)) (pSAMP->g_dwSAMP_Addr + 0x57F0)) (pSAMP->getPlayers()->pLocalPlayer, msg);
}

const char* SAMPFramework::getPlayerName(int iPlayerID)
{
	if (g_Players == NULL || iPlayerID < 0 || iPlayerID > SAMP_MAX_PLAYERS)
		return NULL;

	if (iPlayerID < 0 || iPlayerID > SAMP_MAX_PLAYERS)
		return NULL;

	if (iPlayerID == g_Players->sLocalPlayerID)
	{
		if (g_Players->iLocalPlayerNameAllocated <= 0xF)
			return g_Players->szLocalPlayerName;
		return g_Players->pszLocalPlayerName;
	}

	if (g_Players->pRemotePlayer[iPlayerID] == NULL)
		return NULL;

	if (g_Players->pRemotePlayer[iPlayerID]->iNameAllocated <= 0xF)
		return g_Players->pRemotePlayer[iPlayerID]->szPlayerName;

	return g_Players->pRemotePlayer[iPlayerID]->pszPlayerName;
}