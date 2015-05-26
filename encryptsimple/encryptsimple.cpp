// encryptsimple.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

enum unpack_type
{
	unpack_xor = 0,
	unpack_shl,
	unpack_shr,
	unpack_rol,
	unpack_ror
};

bool EncryptSimple(char* szFilename, unpack_type type, char* szKey, size_t KeyLength)
{
	bool fResult = false;
	size_t nKey = 0;

	HANDLE hFile = CreateFileA(szFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		if (dwFileSize > 0)
		{
			char szFileOut[MAX_PATH];

			wsprintfA(szFileOut, "encrypted_%u.bin", type);

			HANDLE hFile2 = CreateFileA(szFileOut, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
			if (hFile2 != INVALID_HANDLE_VALUE)
			{
				BYTE* pBuffer = new BYTE[dwFileSize];
				DWORD dwReadBytes = 0;

				ReadFile(hFile, pBuffer, dwFileSize, &dwReadBytes, NULL);
				if (dwReadBytes == dwFileSize)
				{
					unsigned char c;
					for (DWORD x = 0; x < dwFileSize; x++, nKey++)
					{

						//
						// rotate key
						//
						if (nKey >= KeyLength)
						{
							nKey = 0;
						}

						c = pBuffer[x];
						switch (type)
						{
						case unpack_xor:
							c ^= szKey[nKey];
							break;
						case unpack_shl:
							c = c << szKey[nKey];
							break;
						case unpack_shr:
							c = c >> szKey[nKey];
							break;
						case unpack_rol:
							c = ((c << szKey[nKey]) | (c >> (32 - szKey[nKey])));
							break;
						case unpack_ror:
							c = ((c >> szKey[nKey]) | (c << (32 - szKey[nKey])));
							break;
						}

						pBuffer[x] = c;

					}
				}
				WriteFile(hFile2, pBuffer, dwFileSize, &dwReadBytes, NULL);

				delete[] pBuffer;
				CloseHandle(hFile2);
				fResult = true;
				printf("created %s\n", szFileOut);
			}

		}
		CloseHandle(hFile);
	}

	return fResult;
}

int main(int argc, char* argv[])
{

	if (argc != 4)
	{
		printf("invalid parameters!\n\nusage:\nencrypt.exe filename type key\ntype: xor, shl, shr, ror, rol\nkey: 1 - 8 bytes");
		return 0;
	}

	
	unpack_type type;

	printf("arg1: %s\n", argv[1]);
	printf("arg2: %s\n", argv[2]);

	if (_stricmp((const char*)argv[2], "xor") == 0)
	{
		type = unpack_xor;
	}
	else if (_stricmp((const char*)argv[2], "shl") == 0)
	{
		type = unpack_shl;
	}
	else if (_stricmp((const char*)argv[2], "shr") == 0)
	{
		type = unpack_shr;
	}
	else if (_stricmp((const char*)argv[2], "rol") == 0)
	{
		type = unpack_rol;
	}
	else if (_stricmp((const char*)argv[2], "ror") == 0)
	{
		type = unpack_ror;
	}


	if (!EncryptSimple((char*)argv[1], type, (char*)argv[3], strlen((const char*)argv[3])))
	{
		printf("failed to encrypt file!\n");
	}

	return 0;
}

