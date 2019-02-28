
#ifndef MEN_LOAD_DLL_H_
#define MEM_LOAD_DLL_H_

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef   BOOL (__stdcall *ProcDllMain)(HINSTANCE, DWORD, LPVOID);

class CMemLoadDll
{
public:
	CMemLoadDll();
	~CMemLoadDll();

public:
	BOOL    MemLoadLibrary(void* lpFileData, int nDataLength);	
	FARPROC    MemGetProcAddress(LPCSTR lpProcName);
	BOOL    IsLoadOk();
	void* GetLoadMoudleBase();
	DWORD GetImageSize();
    void CleanPeHead(void);

private:
	BOOL m_bIsLoadOk;
	BOOL CheckDataValide(void* lpFileData, int nDataLength);
	int  CalcTotalImageSize();
	void CopyDllDatas(void* pDest, void* pSrc);
	BOOL FillRavAddress(void* pImageBase);
	void DoRelocation(void* pNewBase);
	int  GetAlignedSize(int nOrigin, int nAlignment); 
	
private:
	ProcDllMain m_pDllMain;

private:
	void*                    m_pImageBase;
	PIMAGE_DOS_HEADER        m_pDosHeader;
	PIMAGE_NT_HEADERS        m_pNTHeader;
	PIMAGE_SECTION_HEADER    m_pSectionHeader;
	DWORD                    m_ImageSize;
};

#endif