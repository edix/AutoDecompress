//
//
// AutoDecompress by xedi
// IDA Pro Plugin to unpack data at given offset, unpack:
// aplib, rc4, xor, shift, rotate
//
// ida pro reference: http://www.openrce.org/reference_library/ida_sdk
//
// fyi: unfinished yet, still working on it - xedi, May 2015
// 
//

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <diskio.hpp>

#include "aplib/depacks.h"
#include "rc4/rc4.h"

static const uint32 g_uiMaxSize = 0x100000;

//
// global variables, so when we re-open the dialog the values will still exist in memory
//
char g_szKey[MAXSTR] = { 0 };
ushort g_rbSelection = 0;
sval_t g_FileLength = (sval_t)-1;



bool DumpBufferToFile(const char* szDumpType, const char* szFilename, uchar* pBuffer, size_t nBufferSize)
{
	FILE* pDump = ecreate(szFilename);
	if (pDump)
	{
		ewrite(pDump, pBuffer, nBufferSize);
		eclose(pDump);
		msg("AutoDecompress: %s: file dumped to in current directory: %s\n", szDumpType, szFilename);
		return true;
	}
	return false;
}

size_t GetLoadedFileSize()
{
	//
	// todo: is there an easier way to figure out how big the file is!?
	//

	size_t nResult = 0;
	ea_t address = get_screen_ea();
	if (address == BADADDR)
		return nResult;

	ea_t maxitem, maxitem2;
	maxitem = address;

	while (1)
	{
		maxitem2 = calc_max_item_end(maxitem);
		if (maxitem2 != BADADDR && maxitem2 != maxitem)
		{
			maxitem = maxitem2;
		}
		else
		{
			break;
		}
	}

	if (maxitem != BADADDR && maxitem2 != BADADDR)
	{
		nResult = maxitem - address;
	}
	
	return nResult;
}

bool UnpackAplibAtAddress(ea_t address)
{
	struct APLIB_HEADER
	{
		uint32 tag;
		uint32 header_size;
		uint32 packed_size;
		uint32 packed_crc;
		uint32 original_size;
		uint32 original_crc;
	};

	APLIB_HEADER header;
	uchar* pDestination = nullptr;
	uchar* pCompressed = nullptr;
	uint32 uiCompressedSize, uiDecompressedSize;
	uint uiOutputLength;
	bool fResult = false;

	if (get_many_bytes(address, &header, sizeof(header)))
	{
		if (header.tag == '23PA' && header.header_size == 24)
		{

			//
			// ok valid AP32
			// now get compressed buffer
			//
			uiCompressedSize = header.packed_size;
			uiDecompressedSize = header.original_size;

			//
			// only 1 MB for now
			//
			if (uiCompressedSize <= g_uiMaxSize && uiDecompressedSize <= g_uiMaxSize)
			{
				pCompressed = new uchar[uiCompressedSize];
				pDestination = new uchar[uiDecompressedSize];

				if (pCompressed && pDestination)
				{
					//
					// get compressed data
					//
					if (get_many_bytes(address + header.header_size, pCompressed, uiCompressedSize))
					{
						uiOutputLength = aP_depack_safe(pCompressed, uiCompressedSize, pDestination, uiDecompressedSize);
						if (uiOutputLength != (uint)-1 && uiOutputLength != 0)
						{
							//
							// ok, decompression is valid valid
							//
							msg("AutoDecompress: APLIB: decompressed %u bytes, compressed %u bytes\n", uiOutputLength, uiCompressedSize);

							//
							// check if output length is bigger than data, if so then please save it to a file because we can't add new bytes
							//
							msg("AutoDecompress: APLIB: I will unpack %u bytes (excluding header) in this file and store the whole binary in aplib_dump.bin\n", uiCompressedSize - header.header_size);

							//
							// undef
							//
							do_unknown_range(address, header.header_size + uiCompressedSize, DOUNK_SIMPLE);

							//
							// replace the header with zeros
							//
							for (size_t n = 0; n < header.header_size; n++)
							{
								set_cmt(address, "APLIB header found\n", true);
								patch_byte(address + n, 0x00);
							}

							patch_many_bytes(address + header.header_size, pDestination, uiCompressedSize - header.header_size);

							set_cmt(address + header.header_size, "APLIB data found", true);

							//
							// now save to file to the current directory
							//
							if (!DumpBufferToFile("APLIB", "aplib_dump.bin", pDestination, uiDecompressedSize))
							{
								msg("AutoDecompress: APLIB: failed to create file aplib_dump.bin\n");
							}

							fResult = true;
						}
					}
					else
					{
						msg("AutoDecompress: APLIB: can't read %u bytes at %a\n", uiCompressedSize, address);

					}
				}

				delete[] pDestination;
				delete[] pCompressed;
			}
			else
			{
				msg("AutoDecompress: APLIB: compress or decompress size is invalid (compress: %u bytes, decompress: %u bytes, max: %u bytes), aborting...\n", uiCompressedSize, uiDecompressedSize, g_uiMaxSize);
			}

		}
		else
		{
			msg("AutoDecompress: APLIB invalid header.\n");
		}
	}

	return fResult;
}


enum unpack_type
{
	unpack_xor = 0,
	unpack_shl,
	unpack_shr,
	unpack_rol,
	unpack_ror,
	unpack_rc4,
};

bool UnpackSimple(ea_t startaddress, size_t nSize, unpack_type type, char* szKey, size_t nKeyLength)
{
	bool fResult = true;
	size_t nKey = 0;

	//
	// undef
	//
	do_unknown_range(startaddress, nSize, DOUNK_SIMPLE);

	//
	// patch byte to byte
	//
	for (ea_t address = startaddress; address < startaddress + nSize; address++, nKey++)
	{
		uchar c = get_byte(address);


		//
		// rotate key
		//
		if (nKey >= nKeyLength)
		{
			nKey = 0;
		}
		
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
		default:
			msg("AutoDecompress: UNPACK UNKNOWN\n");
		}

	

		if (!patch_byte(address, c))
		{
			fResult = false;
			msg("AutoDecompress: unpack %u failed at address %a in patch_byte\n", type, address);
			break;

		}

	}

	return true;
}

bool UnpackRc4(ea_t startaddress, size_t nSize, char* szKey, size_t nKeyLength)
{
	if (nSize == 0 || nSize >= g_uiMaxSize)
	{
		msg("AutoDecompress: RC4: invalid size %u bytes\n", nSize);
		return false;
	}

	//
	// undef
	//
	do_unknown_range(startaddress, nSize, DOUNK_SIMPLE);

	uchar * pBuffer = new uchar[nSize];

	//
	// get data 
	//
	if (!pBuffer || !get_many_bytes(startaddress, pBuffer, nSize))
	{
		msg("AutoDecompress: RC4: get_many_bytes failed\n");
		delete[] pBuffer;
		return false;
	}

	//
	// decrypt and patch
	//

	rc4_key_t key;
	rc4_set_key((uchar*)szKey, nKeyLength, &key);
	rc4_crypt(pBuffer, nSize, &key);
	patch_many_bytes(startaddress, pBuffer, nSize);

	//
	// dump file to disk
	//
	if (!DumpBufferToFile("RC4", "rc4_dump.bin", pBuffer, nSize))
	{
		msg("AutoDecompress: RC4: failed to create file aplib_dump.bin\n");
	}

	delete[] pBuffer;
	
	msg("AutoDecompress: RC4: finished.\n");

	return true;
}


static int idaapi DialogCallback(int field_id, form_actions_t& fa)
{
	ushort val = 0;

	switch (field_id)
	{
	case CB_INIT:
		//
		// select the last element
		//
		if (g_rbSelection >= 0 )	// huehuehue
			DialogCallback(g_rbSelection + 3, fa);	
		break;
	case 1:		// key
	case 2:		// size
		break;

	case 3:		// aplib
		if (!fa.get_radiobutton_value(field_id, &val))
			INTERR(1337);
		fa.enable_field(1, !val);
		fa.enable_field(2, !val);
		break;

	case 4:		// rc4
	case 5:		// xor
	case 6:		// shl
	case 7:		// shr
	case 8:		// rol
	case 9:		// ror
		if (!fa.get_radiobutton_value(field_id, &val))
			INTERR(1337);
		fa.enable_field(1, true);
		fa.enable_field(2, true);
		
	
		break;
	default:
		msg("callback: %d\n", field_id);
		break;
	}


	return 1;
}

int idaapi init(void)
{
	return PLUGIN_OK;
}

void idaapi run(int)
{
	if (!autoIsOk() && askyn_c(ASKBTN_CANCEL, "HIDECANCEL\nThe autoanalysis has not finished yet.\nThe result might be incomplete. Do you want to continue?") < ASKBTN_NO)
	{
		return;
	}

	msg("AutoDecompress: started.\n");
	
	//
	// select dialog for unpacking type
	//
	//   <label:type:width:swidth:@hlp[]>

	char *szPreDialogForm =
		"STARTITEM 0\n"
		"AutoDecompress at 0x%08x\n\n"
		"%s\n"
		"<Enter decryption key   :A1:16:16::>\n"
		"<Enter size to decrypt  :D2::16::>\n\n"
		"<##Please select your decryption method##APLIB:R3>\n"
		"<RC4:R4>\n"
		"<XOR:R5>\n"
		"<Shift left:R6>\n"
		"<Shift right:R7>\n"
		"<Rotate left:R8>\n"
		"<Rotate right:R9>>\n";

	ea_t address;
	address = get_screen_ea();
	if (address == BADADDR)
	{
		msg("AutoDecompress: please select a valid address\n");
		return;
	}

	if (g_FileLength == (sval_t)-1)
		g_FileLength = GetLoadedFileSize();

	//
	// I wasnt able to figure out how to put a %a into the title of the dialog so this is a hack
	// 
	char szDialogForm[1024] = { 0 };
	qsnprintf(szDialogForm, sizeof(szDialogForm)/sizeof(szDialogForm[0]), szPreDialogForm, (uint32)address, "%/");

	if (AskUsingForm_c(szDialogForm, DialogCallback, g_szKey, &g_FileLength, &g_rbSelection) == 1)
	{
		//
		// and make sure again that the size is ok
		//
		if (g_FileLength == 0 || g_FileLength < 0)
		{
			g_FileLength = GetLoadedFileSize();
		}

		switch (g_rbSelection)
		{
		case 0:
			//
			// aplib
			//
			if (UnpackAplibAtAddress(address))
			{
				msg("AutoDecompress: unpacked data at address %a with aplib.\n", address);
			}
			else
			{
				msg("AutoDecompress: APLIB unpacking failed at %a\n.", address);
			}
			break;

		case 1:
			//
			// RC4
			//
			if (UnpackRc4(address, g_FileLength, g_szKey, (size_t)strlen(g_szKey)))
			{
				msg("AutoDecompress: RC4: decrypted\n");
			}
			else
			{
				msg("AutoDecompress: RC4: failed\n");
			}
			break;

		case 2:
			//
			// XOR
			//
			if (UnpackSimple(address, g_FileLength, unpack_xor, g_szKey, (size_t)strlen(g_szKey)))
			{
				msg("AutoDecompress: XOR: decrypted\n");
			}
			else
			{
				msg("AutoDecompress: XOR: failed\n");
			}
			break;

		case 3:	// shl
		case 4:	// shr
		case 5:	// rol
		case 6:	// ror

		default:
			msg("unknown selection: %u\n", g_rbSelection);
		}
	}
}


plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_FIX,           // plugin flags
	init,                 // initialize
	NULL,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	"Auto decompress data at given offset",                 // long comment about the plugin
	"Auto decompress",                 // multiline help about the plugin
	"AutoDecompress",        // the preferred short name of the plugin
	"ALT+F5"              // the preferred hotkey to run the plugin
};

