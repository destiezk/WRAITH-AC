#include "main.h"
#include "secure.h"

CSecure* pSecure = new CSecure();

void CSecure::Add(DWORD dwAddress, BYTE byteSize)
{
	for (auto i = 0; i < byteSize; i++)
	{
		if (isAddressSecured(dwAddress + i) == -1)
		{
			g_Memory.dwAddress = dwAddress + i;
			g_Memory.origByte = *(BYTE*)(dwAddress + i);
			vecMemory.push_back(g_Memory);
		}
	}
}

int CSecure::isAddressSecured(DWORD dwAddress)
{
	for (size_t i = 0; i < vecMemory.size(); i++)
	{
		if (vecMemory[i].dwAddress == dwAddress)
			return i;
	}
	return -1;
}

void CSecure::SDetourAttach(PVOID* ppPointer, PVOID pDetour)
{
	Add(*(DWORD*)(ppPointer), 7);
	DetourAttach(ppPointer, pDetour);
}