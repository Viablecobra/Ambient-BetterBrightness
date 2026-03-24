#include <unistd.h>
#include <pthread.h>
#include <cstring>
#include "stub.h"
#include "memscan.h"
#include "nop.h"
#include "proc.h"
#include <sys/mman.h>

static const char* GFX_GAMMA_SIG =
    "68 E1 0D F8 48 02 80 52 A8 03 16 38 28 0C 80 52 "
    "BF E3 1A 38 69 91 09 F8 68 11 0A 78 E8 4D 82 52 "
    "01 E4 00 2F 00 10 2C 1E 68 50 A7 72 02 10 2E 1E";

// ARM64: MOV W8, #10  →  SCVTF S2, W8  (replaces MOVK+FMOV pair)
static constexpr uint32_t MOV_W8_10    = 0x52800148;
static constexpr uint32_t SCVTF_S2_W8  = 0x1E220102;
static constexpr uint32_t FMOV_S2_1_0  = 0x1E2E1002; // guard: expected original at +44

static constexpr size_t OFFSET_MOV    = 40;
static constexpr size_t OFFSET_SCVTF  = 44;
static constexpr size_t PATCH_SIZE    = sizeof(uint32_t);

static void*   g_addr_mov   = nullptr;
static void*   g_addr_scvtf = nullptr;
static uint8_t g_saved_mov  [PATCH_SIZE];
static uint8_t g_saved_scvtf[PATCH_SIZE];
static bool    g_patched    = false;

// patch_nop() only writes NOPs — we need arbitrary instruction writes,
// so keep a direct mprotect/memcpy helper for the two specific patches.
static bool PatchMemory(void* addr, const void* data, size_t size) {
    uintptr_t page_start = (uintptr_t)addr & ~(uintptr_t)4095;
    size_t    page_size  = ((uintptr_t)addr + size - page_start + 4095) & ~(uintptr_t)4095;

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
                uint8_t*  base       = (uint8_t*)addr;
                uint32_t* scvtf_slot = (uint32_t*)(base + OFFSET_SCVTF);

                // Guard: make sure this is the right hit before patching
                if (*scvtf_slot == FMOV_S2_1_0) {
                    g_addr_mov   = (void*)(base + OFFSET_MOV);
                    g_addr_scvtf = (void*)scvtf_slot;

                    int prot = get_prot((uintptr_t)g_addr_mov);
                    if (prot > 0 && (prot & PROT_READ)) {
                        memcpy(g_saved_mov,   g_addr_mov,   PATCH_SIZE);
                        memcpy(g_saved_scvtf, g_addr_scvtf, PATCH_SIZE);

                        g_patched = PatchMemory(g_addr_mov,   &MOV_W8_10,   PATCH_SIZE)
                                 && PatchMemory(g_addr_scvtf, &SCVTF_S2_W8, PATCH_SIZE);
                    }
                }
            }
        }
        if (!g_patched) usleep(100 * 1000);
    }
    return nullptr;
}

__attribute__((constructor))
void StartUp() {
    pthread_t t;
    pthread_create(&t, nullptr, PatchThread, nullptr);
    pthread_detach(t);
}

__attribute__((destructor))
void Shutdown() {
    if (!g_patched || !g_addr_mov || !g_addr_scvtf) return;
    PatchMemory(g_addr_mov,   g_saved_mov,   PATCH_SIZE);
    PatchMemory(g_addr_scvtf, g_saved_scvtf, PATCH_SIZE);
}