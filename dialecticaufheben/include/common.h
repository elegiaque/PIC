#ifndef STARDUST_COMMON_H
#define STARDUST_COMMON_H

//
// system related headers
#include <windows.h>
#include <type_traits>
#include <concepts>

//
// stardust related headers
#include <constexpr.h>
#include <macros.h>
#include <memory.h>
#include <native.h>
#include <resolve.h>


extern "C" auto RipData() -> uintptr_t;
extern "C" auto RipStart() -> uintptr_t;

#if defined( DEBUG )
#define DBG_PRINTF( format, ... ) { ntdll.DbgPrint( symbol<PCH>( "[DEBUG::%s::%d] " format ), symbol<PCH>( __FUNCTION__ ), __LINE__, ##__VA_ARGS__ ); }
#else
#define DBG_PRINTF( format, ... ) { ; }
#endif

#ifdef _M_X64
#define END_OFFSET 0x10
#else
#define END_OFFSET 0x10
#endif

namespace stardust
{
    template <typename T>
    inline T symbol(T s) {
        return reinterpret_cast<T>(RipData()) - (reinterpret_cast<uintptr_t>(&RipData) - reinterpret_cast<uintptr_t>(s));
    }

    class instance {
        struct {
            uintptr_t address;
            uintptr_t length;
        } base = {};

        struct {
            uintptr_t handle;

            struct {
                D_API( LoadLibraryA )
                D_API( GetProcAddress )
                D_API( CreateFileTransactedW )
                D_API( CloseHandle )
                D_API( CreateFileW )
                D_API( GetFileSize )
                D_API( ReadFile )
                D_API( SetFilePointer )
                D_API( VirtualAlloc )
                D_API( GetCurrentProcess )
                D_API( CreateThread )
                D_API( WaitForSingleObject )
                D_API( VirtualFree )
                D_API( WriteFile )
            };
        } kernel32 = {
            RESOLVE_TYPE( LoadLibraryA ),
            RESOLVE_TYPE( GetProcAddress ),
            RESOLVE_TYPE( CreateFileTransactedW ),
            RESOLVE_TYPE( CloseHandle ),
            RESOLVE_TYPE( CreateFileW ),
            RESOLVE_TYPE( GetFileSize ),
            RESOLVE_TYPE( ReadFile ),
            RESOLVE_TYPE( SetFilePointer ),
            RESOLVE_TYPE( VirtualAlloc ),
            RESOLVE_TYPE( GetCurrentProcess ),
            RESOLVE_TYPE( CreateThread ),
            RESOLVE_TYPE( WaitForSingleObject ),
            RESOLVE_TYPE( VirtualFree ),
            RESOLVE_TYPE( WriteFile )
        };

        struct {
            uintptr_t handle;

            struct
            {
                D_API( NtCreateSection )
                D_API( NtMapViewOfSection )
                D_API( NtCreateTransaction )
            };
        } ntdll = {
            RESOLVE_TYPE( NtCreateSection ),
            RESOLVE_TYPE( NtMapViewOfSection ),
            RESOLVE_TYPE( NtCreateTransaction ),
        };

    public:
        explicit instance();

        auto start(
            _In_ void* arg
        ) -> void;

        auto getHdr(
            IMAGE_NT_HEADERS* pNtHdrs,
            IMAGE_SECTION_HEADER* pInitialSectHeader,
            uint64_t qwRVA
        ) -> IMAGE_SECTION_HEADER*;

        auto getPA(
            uint8_t* PEBuf,
            IMAGE_NT_HEADERS* pNtHdrs,
            IMAGE_SECTION_HEADER* pInitialSectHdrs,
            uint64_t qwRVA
        ) -> void*;

        auto checkReloc(
            uint8_t* pRelocBuf,
            uint32_t dwRelocBufSize,
            uint32_t dwStartRVA,
            uint32_t dwEndRVA
        ) -> BOOL;

        auto parseTransaction(
            HANDLE hFile,
            BYTE* pCodeBuf,
            uint32_t dwReqBufSize,
            HANDLE *hTransaction,
            LPVOID *pFileBuf,
            DWORD *dwFileSize
        ) -> BOOL;

        auto createTransaction(
            HANDLE *hTransaction,
            LPVOID *pFileBuf,
            DWORD *dwFileSize
        ) -> HANDLE;


    };

    template<typename T = char>
    inline auto declfn hash_string(
        _In_ const T* string
    ) -> uint32_t {
        uint32_t hash = 0x811c9dc5;
        uint8_t  byte = 0;

        while ( * string ) {
            byte = static_cast<uint8_t>( * string++ );

            if ( byte >= 'a' ) {
                byte -= 0x20;
            }

            hash ^= byte;
            hash *= 0x01000193;
        }

        return hash;
    }
}


#endif //STARDUST_COMMON_H
