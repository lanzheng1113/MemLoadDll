// RUNPCH.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <string>
#include <windows.h>
#include <shlwapi.h>
#include "module/zishiA/MemLoadDll.h"
#pragma comment(lib, "shlwapi.lib")
using namespace std;
#pragma warning(disable : 4996)

unsigned char *g_bMemory = NULL;

/**
 * \brief
 * 
 * \param
 * \return bytes read to memory.
 */
DWORD ReadDllFile(const string& DllPath)
{
	HANDLE FileHandle = CreateFileA(DllPath.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (0 == FileHandle)
	{
		return 0;
	}
	LARGE_INTEGER SizeOfFile;
	SizeOfFile.QuadPart = 0;
	if (!GetFileSizeEx(FileHandle, &SizeOfFile)
		|| SizeOfFile.QuadPart == 0)
	{
		return 0;
	}
	g_bMemory = new unsigned char[SizeOfFile.u.LowPart];
	if (!g_bMemory)
	{
		CloseHandle(FileHandle);
		return 0;
	}
	DWORD Readed = 0;
	if (!ReadFile(FileHandle, g_bMemory, SizeOfFile.u.LowPart, &Readed, NULL)
		|| Readed != SizeOfFile.u.LowPart)
	{
		delete[] g_bMemory;
		g_bMemory = NULL;
		CloseHandle(FileHandle);
		return 0;
	}
	CloseHandle(FileHandle);
	return Readed;
}

int _tmain(int argc, _TCHAR* argv[])
{
	//mark : After loading a function related to the memory will be released, that is, only one function can be loaded to perform
	WCHAR wcLocalPath[MAX_PATH * 2] = { 0 };
	GetModuleFileName(0, wcLocalPath, MAX_PATH);
	PathRemoveFileSpec(wcLocalPath);
	SetCurrentDirectory(wcLocalPath);

	DWORD dwFileLength = ReadDllFile("TestDll.dll");
	CMemLoadDll *clLoadClass = new CMemLoadDll();
	BOOL  bLoadDllResult  = clLoadClass->MemLoadLibrary(g_bMemory ,dwFileLength);	

	if(bLoadDllResult){
	    typedef VOID (*TYPEPRINTFMSE)(const string &strMessage);
	    TYPEPRINTFMSE _PrintfMse = (TYPEPRINTFMSE)clLoadClass->MemGetProcAddress("PrintfMse");
		if(_PrintfMse){
			_PrintfMse("Memory load function executed successfully!");
		}else{
			// getprocaddress error
		}
	}else{
		//loadlibrary error
	}

	delete clLoadClass;
	return 0;
}

