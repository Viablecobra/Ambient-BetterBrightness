#include <unistd.h>
#include <pthread.h>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include "stub.h"
#include "memscan.h"
#include "proc.h"

static const char* GFX_GAMMA_SIG =
    "CA 92 06 F8 29 01 40 F9 C8 E2 06 F8 48 02 80 52 "
    "A8 03 16 38 28 0C 80 52 BF E3 1A 38 C9 92 02 F8 "
    "C8 12 03 78 E8 4D 82 52 01 E4 00 2F 00 10 2C 1E "
    "68 50 A7 72 02 10 2E 1E";

static constexpr uint32_t MOV_W8_10   = 0x52800148;
static constexpr uint32_t SCVTF_S2_W8 = 0x1E220102;
static constexpr uint32_t FMOV_S2_1_0 = 0x1E2E1002;

static constexpr size_t OFFSET_MOVK = 48;
static constexpr size_t OFFSET_FMOV = 52;
static constexpr size_t PATCH_SIZE  = sizeof(uint32_t);

static void*   g_addr_movk = nullptr;
static void*   g_addr_fmov = nullptr;
static uint8_t g_saved_movk[PATCH_SIZE];
static uint8_t g_saved_fmov[PATCH_SIZE];
static bool    g_patched   = false;

static bool PatchMemory(void* addr, const void* data, size_t size) {
    uintptr_t page_start = (uintptr_t)addr & ~(4095UL);
    size_t    page_size  = ((uintptr_t)addr + size - page_start + 4095) & ~(4095UL);

    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return false;

    memcpy(addr, data, size);
    __builtin___clear_cache((char*)addr, (char*)addr + size);
    mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);
    return true;
}

static void* PatchThread(void*) {
    while (!g_patched) {
        sigscan_handle* h = sigscan_setup(GFX_GAMMA_SIG, "libminecraftpe.so", 0);
        if (h) {
            void* addr = get_sigscan_result(h);
            sigscan_cleanup(h);

            if (addr) {
                uint8_t*  base      = (uint8_t*)addr;
                uint32_t* fmov_addr = (uint32_t*)(base + OFFSET_FMOV);

                // Guard: verify expected instruction before patching
                if (*fmov_addr == FMOV_S2_1_0) {
                    uint32_t* movk_addr = (uint32_t*)(base + OFFSET_MOVK);

                    g_addr_movk = movk_addr;
                    g_addr_fmov = fmov_addr;

                    int prot = get_prot((uintptr_t)g_addr_movk);
                    if (prot > 0 && (prot & PROT_READ)) {
                        memcpy(g_saved_movk, g_addr_movk, PATCH_SIZE);
                        memcpy(g_saved_fmov, g_addr_fmov, PATCH_SIZE);

                        g_patched = PatchMemory(g_addr_movk, &MOV_W8_10,   PATCH_SIZE)
                                 && PatchMemory(g_addr_fmov,  &SCVTF_S2_W8, PATCH_SIZE);
                    }
                }
            }
        }

        if (!g_patched) usleep(100 * 1000);
    }
    return nullptr;
}

__attribute__((constructor))
void BetterBrightness_Init() {
    pthread_t t;
    pthread_create(&t, nullptr, PatchThread, nullptr);
    pthread_detach(t);
}

__attribute__((destructor))
void Shutdown() {
    if (!g_patched || !g_addr_movk || !g_addr_fmov) return;
    PatchMemory(g_addr_movk, g_saved_movk, PATCH_SIZE);
    PatchMemory(g_addr_fmov, g_saved_fmov, PATCH_SIZE);
}