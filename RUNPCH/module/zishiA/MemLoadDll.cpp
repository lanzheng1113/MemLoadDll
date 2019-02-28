
//#include "stdafx.h"
#include "MemLoadDll.h"

CMemLoadDll::CMemLoadDll()
{
    m_bIsLoadOk = FALSE;
    m_pImageBase = NULL;
    m_pDllMain = NULL;
}
 
CMemLoadDll::~CMemLoadDll()
{
    if(m_bIsLoadOk)
    {
    //    ASSERT(m_pImageBase != NULL);
    //    ASSERT(m_pDllMain   != NULL);
        m_pDllMain((HINSTANCE)m_pImageBase, DLL_PROCESS_DETACH, 0);
        VirtualFree(m_pImageBase, 0, MEM_RELEASE);
    }
}
 
/*
*函数名: MemLoadLibrary
*说明: 函数从内存缓冲区数据中加载一个dll到当前进程的地址空间
*参数1:存放待加载DLL的文件数据缓冲区
*参数2: 缓冲区长度
*返回值： 成功返回TRUE , 失败返回FALSE
*/

BOOL CMemLoadDll::MemLoadLibrary(void* lpFileData, int nDataLength)
{
    if (m_pImageBase != NULL)
    {
        return FALSE;  
    }

    //检查数据有效性，并初始化
    if (!CheckDataValide(lpFileData, nDataLength))
    {
        return FALSE;
    }

    //计算所需的加载空间
    int nImageSize = CalcTotalImageSize(); 
    if (nImageSize == 0)
    {
        return FALSE;
    }
    // 分配虚拟内存,这里分配虚拟内存可采用三段夹击的方法.后期可接管系统异常处理.来对抗杀软扫描.
	m_ImageSize = nImageSize;  //保存ImageSize
    void *pMemoryAddress = VirtualAlloc(NULL, nImageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
    if (NULL == pMemoryAddress)
    {
        return FALSE;
    }
    else
    {
        CopyDllDatas(pMemoryAddress, lpFileData); //复制dll数据，并对齐每个段
        //重定位信息
        if (m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0  &&  m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
        {
            DoRelocation(pMemoryAddress);
        }
        //填充导入表
        if (!FillRavAddress(pMemoryAddress))
        {
            VirtualFree(pMemoryAddress, 0, MEM_RELEASE);
            return FALSE;
        }
        //修改页属性。应该根据每个页的属性单独设置其对应内存页的属性。
        //统一设置成一个属性PAGE_EXECUTE_READWRITE
        unsigned long unOld; 
        VirtualProtect(pMemoryAddress, nImageSize, PAGE_EXECUTE_READWRITE, &unOld);
    }
    //修正基地址
    m_pNTHeader->OptionalHeader.ImageBase = (DWORD)pMemoryAddress;
/*
#ifdef WIN32
#else
    m_pNTHeader->OptionalHeader.ImageBase = (ULONGULONG)pMemoryAddress;
#endif
*/
	//接下来要调用一下dll的入口函数，做初始化工作。
    m_pDllMain = (ProcDllMain)(m_pNTHeader->OptionalHeader.AddressOfEntryPoint + (PBYTE)pMemoryAddress);
	//函数初始化,非MFC工程。
    BOOL InitResult = m_pDllMain((HINSTANCE)pMemoryAddress, DLL_PROCESS_ATTACH, 0); 
    if (!InitResult) //初始化失败
    {
        m_pDllMain((HINSTANCE)pMemoryAddress, DLL_PROCESS_DETACH, 0);
        VirtualFree(pMemoryAddress, 0, MEM_RELEASE);
        m_pDllMain = NULL;
        return FALSE;
    }
	m_bIsLoadOk = TRUE;
	m_pImageBase = pMemoryAddress;
    return TRUE;
}

DWORD CMemLoadDll::GetImageSize()
{
	return m_ImageSize;
}

void* CMemLoadDll::GetLoadMoudleBase()
{
	return m_pImageBase;
}
 
BOOL CMemLoadDll::IsLoadOk()
{
    return m_bIsLoadOk;
}
 
/*
*函数名: MemGetProcAddress
*功能: 函数从dll中获取指定函数的地址,与系统GetPrcessAdress功能一样
*参数1: 要获取的函数名称或函数
*返回值： 成功返回函数地址 , 失败返回NULL
*/
FARPROC CMemLoadDll::MemGetProcAddress(LPCSTR lpProcName)
{
    if (m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 || m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
    {
        return NULL;
    }

    if (!m_bIsLoadOk)
    {
        return NULL;
    }
     
    DWORD dwOffsetStart = m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD dwSize = m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
     
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)m_pImageBase + m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    int iBase = pExport->Base;
    int iNumberOfFunctions = pExport->NumberOfFunctions;
    int iNumberOfNames = pExport->NumberOfNames; //<= iNumberOfFunctions
    LPDWORD pAddressOfFunctions = (LPDWORD)(pExport->AddressOfFunctions + (PBYTE)m_pImageBase);
    LPWORD  pAddressOfOrdinals = (LPWORD)(pExport->AddressOfNameOrdinals + (PBYTE)m_pImageBase);
    LPDWORD pAddressOfNames  = (LPDWORD)(pExport->AddressOfNames + (PBYTE)m_pImageBase);
     
    int iOrdinal = -1;
     
    if (((DWORD)lpProcName & 0xFFFF0000) == 0) //IT IS A ORDINAL!
    {
        iOrdinal = (DWORD)lpProcName & 0x0000FFFF - iBase;
    }
    else  //use name
    {
        int iFound = -1;
         
        for (int i=0; i<iNumberOfNames; i++)
        {
            char* pName= (char* )(pAddressOfNames[i] + (PBYTE)m_pImageBase);
            if (strcmp(pName, lpProcName) == 0)
            {
                iFound = i;
                break;
            }
        }
        if (iFound >= 0)
        {
            iOrdinal = (int)(pAddressOfOrdinals[iFound]);
        }
    }
     
    if (iOrdinal < 0 || iOrdinal >= iNumberOfFunctions )
    {
        return NULL;
    }
    else
    {
        DWORD pFunctionOffset = pAddressOfFunctions[iOrdinal];
 
        if (pFunctionOffset > dwOffsetStart && pFunctionOffset < (dwOffsetStart + dwSize))//maybe Export Forwarding
        {
            return NULL;
        }
        else
        {
			CleanPeHead(); //清理pe头部
            return (FARPROC)(pFunctionOffset + (PBYTE)m_pImageBase);
        }
    }
     
}
 
// 重定向PE用到的地址
void CMemLoadDll::DoRelocation( void *pNewBase)
{
/* 重定位表的结构：
// DWORD sectionAddress, DWORD size (包括本节需要重定位的数据)
// 例如 1000节需要修正5个重定位数据的话，重定位表的数据是
// 00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
// -----------   -----------      ----
// 给出节的偏移  总尺寸=8+6*2     需要修正的地址           用于对齐4字节
// 重定位表是若干个相连，如果address 和 size都是0 表示结束
// 需要修正的地址是12位的，高4位是形态字，intel cpu下是3
    */
    //假设NewBase是0x600000,而文件中设置的缺省ImageBase是0x400000,则修正偏移量就是0x200000
    //注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
    PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((unsigned long)pNewBase +  m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
 
    while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
    {
        WORD *pLocData = (WORD *)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
        //计算本节需要修正的重定位项（地址）的数目
        int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);
 
        for ( int i=0 ; i < nNumberOfReloc; i++)
        {
            // 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。
            // 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。

/*
#ifdef _WIN64
            if ((DWORD)(pLocData[i] & 0x0000F000) == 0x0000A000)
            {
                // 64位dll重定位，IMAGE_REL_BASED_DIR64
                // 对于IA-64的可执行文件，重定位似乎总是IMAGE_REL_BASED_DIR64类型的。

                ULONGLONG* pAddress = (ULONGLONG *)((PBYTE)pNewBase + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
                ULONGLONG ullDelta = (ULONGLONG)pNewBase - m_pNTHeader->OptionalHeader.ImageBase;
                *pAddress += ullDelta;

            }
#endif

			*/
            if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址
            {
                // 32位dll重定位，IMAGE_REL_BASED_HIGHLOW
                // 对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。

                DWORD* pAddress = (DWORD *)((PBYTE)pNewBase + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
                DWORD dwDelta = (DWORD)pNewBase - m_pNTHeader->OptionalHeader.ImageBase;
                *pAddress += dwDelta;
		
            }
        }

        //转移到下一个节进行处理
        pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
    }
}
 
//填充引入地址表
BOOL CMemLoadDll::FillRavAddress(void *pImageBase)
{
    // 引入表实际上是一个 IMAGE_IMPORT_DESCRIPTOR 结构数组，全部是0表示结束
    // 数组定义如下：
    // 
    // DWORD   OriginalFirstThunk;         // 0表示结束，否则指向未绑定的IAT结构数组
    // DWORD   TimeDateStamp; 
    // DWORD   ForwarderChain;             // -1 if no forwarders
    // DWORD   Name;                       // 给出dll的名字
    // DWORD   FirstThunk;                 // 指向IAT结构数组的地址(绑定后，这些IAT里面就是实际的函数地址)
#define NAME_BUF_SIZE 256  //

    unsigned long nOffset = m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress ;
 
    if (nOffset == 0)
    {
        return TRUE; //No Import Table
    }
 
    PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pImageBase + nOffset);
 
    while (pID->Characteristics != 0)
    {
        PIMAGE_THUNK_DATA pRealIAT = (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pID->FirstThunk);
        PIMAGE_THUNK_DATA pOriginalIAT = (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pID->OriginalFirstThunk);
        //获取dll的名字

		char szBuf[NAME_BUF_SIZE] = {0}; //dll name;
	//	memset(szBuf, 0, NAME_BUF_SIZE);

        BYTE* pName = (BYTE*)((DWORD)pImageBase + pID->Name);
        int i=0;
 
        for (i=0; i<NAME_BUF_SIZE; i++)
        {
            if (pName[i] == 0)
            {
                break;
            }

            szBuf[i] = pName[i];
        }

        if (i >= NAME_BUF_SIZE)
        {
            return FALSE;  // bad dll name
        }
        else
        {
            szBuf[i] = 0;
        }
		 
        HMODULE hDll = GetModuleHandleA(szBuf); 
        if (hDll == NULL)     //第一次获取失败就load
        { 
             hDll =  LoadLibraryA(szBuf);   //这里是系统DLL,不用释放,90%的情况下不会到此
			 if (hDll == NULL)
			 {
				 return FALSE; //NOT FOUND DLL
			 }
        }

        //获取DLL中每个导出函数的地址，填入IAT
        //每个IAT结构是 ：
        // union { PBYTE  ForwarderString;
        //   PDWORD Function;
        //   DWORD Ordinal;
        //   PIMAGE_IMPORT_BY_NAME  AddressOfData;
        // } u1;
        // 长度是一个DWORD ，正好容纳一个地址。
        for (i = 0; ; i++)
        {
            if (pOriginalIAT[i].u1.Function == 0)
            {
                break;
            }
 
            FARPROC lpFunction = NULL;
 
            if (pOriginalIAT[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) //这里的值给出的是导出序号
            {
                lpFunction = GetProcAddress(hDll, (LPCSTR)(pOriginalIAT[i].u1.Ordinal & 0x0000FFFF));
            }
            else //按照名字导入
            {
                //获取此IAT项所描述的函数名称
                PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pImageBase + (DWORD)(pOriginalIAT[i].u1.AddressOfData));
 
                lpFunction = GetProcAddress(hDll, (char *)pByName->Name);
            }

            if (lpFunction != NULL)   //找到了！
            {
/*
#ifdef _WIN64
                pRealIAT[i].u1.Function = (ULONGLONG)lpFunction;
#else
#endif			*/
             pRealIAT[i].u1.Function = (DWORD)lpFunction;

            }
            else
            {
                return FALSE;
            }
        }
         
        //move to next 
        pID = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pID + sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }
 
    return TRUE;
}

BOOL CMemLoadDll::CheckDataValide(void* lpFileData, int nDataLength)
{
	//检查长度
	if (nDataLength < sizeof(IMAGE_DOS_HEADER))
	{
		return FALSE;
	}

	m_pDosHeader = (PIMAGE_DOS_HEADER)lpFileData;  // DOS头
	//检查dos头的标记
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;  //0x5A4D : MZ
	}

	//检查长度
	if ((DWORD)nDataLength < (m_pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
	{
		return FALSE;
	}

	//取得pe头
	m_pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)lpFileData + m_pDosHeader->e_lfanew); // PE头
	//检查pe头的合法性
	if (m_pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;  //0x00004550 : PE00
	}

	if ((m_pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) //0x2000  : File is a DLL
	{
		return FALSE;  
	}

	if ((m_pNTHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) //0x0002 : 指出文件可以运行
	{
		return FALSE;
	}

	if (m_pNTHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
	{
		return FALSE;
	}    

	//取得节表（段表）
	m_pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_pNTHeader + sizeof(IMAGE_NT_HEADERS));
	//验证每个节表的空间
	for (int i=0; i< m_pNTHeader->FileHeader.NumberOfSections; i++)
	{
		if ((m_pSectionHeader[i].PointerToRawData + m_pSectionHeader[i].SizeOfRawData) > (DWORD)nDataLength)
		{
			return FALSE;
		}
	}

	return TRUE;
}

//计算对齐边界
int CMemLoadDll::GetAlignedSize(int nOrigin, int nAlignment)
{
	return (nOrigin + nAlignment - 1) / nAlignment * nAlignment;
}

//计算整个dll映像文件的尺寸
int CMemLoadDll::CalcTotalImageSize()
{
	int nSize = 0;

	if (m_pNTHeader == NULL)
	{
		return 0;
	}

	int nAlign = m_pNTHeader->OptionalHeader.SectionAlignment; //段对齐字节数

	// 计算所有头的尺寸。包括dos, coff, pe头 和 段表的大小
	nSize = GetAlignedSize(m_pNTHeader->OptionalHeader.SizeOfHeaders, nAlign);
	// 计算所有节的大小
	for (int i=0; i < m_pNTHeader->FileHeader.NumberOfSections; ++i)
	{
		//得到该节的大小
		int nCodeSize = m_pSectionHeader[i].Misc.VirtualSize ;
		int nLoadSize = m_pSectionHeader[i].SizeOfRawData;
		int nMaxSize = max(nLoadSize, nCodeSize);
		int nSectionSize = GetAlignedSize(m_pSectionHeader[i].VirtualAddress + nMaxSize, nAlign);
		if (nSize < nSectionSize)
		{
			nSize = nSectionSize;  //Use the Max;
		}
	}
	return nSize;
}

//CopyDllDatas函数将dll数据复制到指定内存区域，并对齐所有节
//pSrc: 存放dll数据的原始缓冲区
//pDest:目标内存地址
void CMemLoadDll::CopyDllDatas(void* pDest, void* pSrc)
{
	// 计算需要复制的PE头+段表字节数
	int  nHeaderSize = m_pNTHeader->OptionalHeader.SizeOfHeaders;
	int  nSectionSize = m_pNTHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	int  nMoveSize = nHeaderSize + nSectionSize;
	//复制头和段信息
	memcpy(pDest, pSrc, nMoveSize);

	//复制每个节
	for (int i=0; i < m_pNTHeader->FileHeader.NumberOfSections; ++i)
	{
		if (m_pSectionHeader[i].VirtualAddress == 0 || m_pSectionHeader[i].SizeOfRawData == 0)
		{
			continue;
		}
		// 定位该节在内存中的位置
		void *pSectionAddress = (void *)((PBYTE)pDest + m_pSectionHeader[i].VirtualAddress);
		// 复制段数据到虚拟内存
		memcpy((void *)pSectionAddress, (void *)((PBYTE)pSrc + m_pSectionHeader[i].PointerToRawData),
			m_pSectionHeader[i].SizeOfRawData);
	}

	//修正指针，指向新分配的内存
	//新的dos头
	m_pDosHeader = (PIMAGE_DOS_HEADER)pDest;
	//新的pe头地址
	m_pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDest + (m_pDosHeader->e_lfanew));
	//新的节表地址
	m_pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_pNTHeader + sizeof(IMAGE_NT_HEADERS));
}

void CMemLoadDll::CleanPeHead(void)
{
	int HeaderSize = m_pNTHeader->OptionalHeader.SizeOfHeaders;
	int SectionSize = m_pNTHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	int memsetSize = HeaderSize + SectionSize;

	//复制头和段信息
// 	for(int i=0;i<memsetSize;i++){
// 		*(char*)((int)m_pImageBase+i) = 0;
// 	}

	//复制头和段信息
	memset((char*)m_pImageBase,0x44,memsetSize);
}
