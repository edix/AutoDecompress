//
//
// AutoDecompress by xedi
// IDA Pro Plugin to unpack data at given offset, unpack:
// aplib, zip, xor, shift, ror, rot13
//
// ida pro reference: http://www.openrce.org/reference_library/ida_sdk
//
// fyi: unfinished yet, still working on it - xedi, Mai 2015
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

int idaapi init(void)
{
	return PLUGIN_OK;
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
	unsigned char* pDestination = nullptr;
	unsigned char* pCompressed = nullptr;
	uint32 uiCompressedSize, uiDecompressedSize;
	uint uiOutputLength;
	bool fResult = false;

	const uint32 uiMaxCompressionSize = 0x100000;

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
			if (uiCompressedSize <= uiMaxCompressionSize && uiDecompressedSize <= uiMaxCompressionSize)
			{
				pCompressed = new unsigned char[uiCompressedSize];
				pDestination = new unsigned char[uiDecompressedSize];

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

							patch_many_bytes(address + header.header_size, pDestination, uiCompressedSize - header.header_size);

							//
							// now save to file to the current directory
							//
							FILE* pDump = ecreate("aplib_dump.bin");
							if (pDump)
							{
								ewrite(pDump, pDestination, uiDecompressedSize);
								eclose(pDump);
								msg("AutoDecompress: APLIB: full decompressed file can be found in current directory: aplib_dump.bin\n");
							}
							else
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
				msg("AutoDecompress: APLIB: compress or decompress size is invalid (compress: %u bytes, decompress: %u bytes, max: %u bytes), aborting...\n", uiCompressedSize, uiDecompressedSize, uiMaxCompressionSize);
			}

		}
		else
		{
			msg("AutoDecompress: APLIB invalid header.\n");
		}
	}

	return fResult;
}


//void idaapi button_func(TView *fields[], int code)
//{
//	msg("The button was pressed!\n");
//}


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
	char *szDialogForm =
		"STARTITEM 0\n"
		"AutoDecompress\n\n"
		"<Enter decryption key:A:16:16::>\n"					// unused right now, should be a XOR key or something...
		"<##Please select your decryption method##APLIB:R>\n"
		"<Shift left:R>\n"
		"<Shift right:R>\n"
		"<XOR:R>>\n";


	char szKey[MAXSTR];
	ushort uiSelect = 0;
	qstrncpy(szKey, "", sizeof(szKey));

	if (AskUsingForm_c(szDialogForm, szKey, &uiSelect/*, button_func*/) == 1)
	{
		ea_t address;
		address = get_screen_ea();

		switch (uiSelect)
		{
		case 0:
			if (UnpackAplibAtAddress(address))
			{
				msg("AutoDecompress: unpacked data at address %a with aplib.\n", address);
			}
			else
			{
				msg("AutoDecompress: APLIB unpacking failed at %a\n.", address);
			}
			break;
		default:
			msg("unknown selection: %u\n", uiSelect);
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

