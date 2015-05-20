//
//
// AutoDecompress by xedi
// IDA Pro Plugin to unpack data at given offset, unpack:
// aplib, zip, xor, shift, ror, rot13
//
// ida pro reference: http://www.openrce.org/reference_library/ida_sdk
// 
//

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <bytes.hpp>
//#include <typeinf.hpp>
#include <funcs.hpp>

#include <algorithm>


int idaapi init(void)
{
	if (ph.id != PLFM_386)
	{
		return PLUGIN_SKIP;
	}

	return PLUGIN_OK;
}

std::string GetFunctionName(ea_t ea)
{
	qstring funcName;
	get_func_name2(&funcName, ea);
	return funcName.c_str();
}


void idaapi run(int)
{
	if (!autoIsOk() && askyn_c(ASKBTN_CANCEL, "HIDECANCEL\nThe autoanalysis has not finished yet.\nThe result might be incomplete. Do you want to continue?") < ASKBTN_NO)
	{
		return;
	}

	msg("AutoDecompress started.\n");

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

