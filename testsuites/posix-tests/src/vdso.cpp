#include <assert.h>
#include <elf.h>
#include <sys/auxv.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "testsuite.hpp"

#ifndef AT_SYSINFO_EHDR
#define AT_SYSINFO_EHDR 33
#endif

static uint32_t sysv_hash(const char *name) {
        uint32_t h = 0;
        while(*name) {
                h = (h << 4) + (unsigned char)*name++;
                uint32_t g = h & 0xF0000000;
                if(g)
                        h ^= g >> 24;
                h &= ~g;
        }
        return h;
}

// Ищет символ в .dynsym vDSO через sysv-хэш; vDSO слинкован по базе 0,
// поэтому и d_un.d_val, и st_value складываются с базой напрямую.
static void *vdso_lookup(uintptr_t base, const char *name) {
        auto ehdr = reinterpret_cast<Elf64_Ehdr *>(base);
        if(memcmp(ehdr->e_ident, ELFMAG, SELFMAG))
                return nullptr;

        Elf64_Dyn *dyn = nullptr;
        for(int i = 0; i < ehdr->e_phnum; i++) {
                auto phdr = reinterpret_cast<Elf64_Phdr *>(
                                base + ehdr->e_phoff + i * ehdr->e_phentsize);
                if(phdr->p_type == PT_DYNAMIC) {
                        dyn = reinterpret_cast<Elf64_Dyn *>(base + phdr->p_offset);
                        break;
                }
        }
        if(!dyn)
                return nullptr;

        uint32_t *hash = nullptr;
        Elf64_Sym *symtab = nullptr;
        const char *strtab = nullptr;
        for(; dyn->d_tag != DT_NULL; dyn++) {
                if(dyn->d_tag == DT_HASH)
                        hash = reinterpret_cast<uint32_t *>(base + dyn->d_un.d_val);
                else if(dyn->d_tag == DT_SYMTAB)
                        symtab = reinterpret_cast<Elf64_Sym *>(base + dyn->d_un.d_val);
                else if(dyn->d_tag == DT_STRTAB)
                        strtab = reinterpret_cast<const char *>(base + dyn->d_un.d_val);
        }
        if(!hash || !symtab || !strtab)
                return nullptr;

        uint32_t nbucket = hash[0];
        uint32_t *buckets = hash + 2;
        uint32_t *chains = buckets + nbucket;
        uint32_t h = sysv_hash(name);
        for(uint32_t i = buckets[h % nbucket]; i; i = chains[i]) {
                auto sym = &symtab[i];
                if(!strcmp(strtab + sym->st_name, name))
                        return reinterpret_cast<void *>(base + sym->st_value);
        }
        return nullptr;
}

DEFINE_TEST(vdso_present, ([] {
        uintptr_t base = getauxval(AT_SYSINFO_EHDR);
        assert(base);

        auto ehdr = reinterpret_cast<Elf64_Ehdr *>(base);
        assert(!memcmp(ehdr->e_ident, ELFMAG, SELFMAG));
        assert(ehdr->e_type == ET_DYN);
        assert(ehdr->e_phnum >= 1);
}));

DEFINE_TEST(vdso_clock_gettime, ([] {
        uintptr_t base = getauxval(AT_SYSINFO_EHDR);
        assert(base);
        auto fn = reinterpret_cast<int (*)(int, struct timespec *)>(
                        vdso_lookup(base, "__vdso_clock_gettime"));
        assert(fn);

        struct timespec vds, sys;
        assert(!fn(CLOCK_MONOTONIC, &vds));
        assert(!clock_gettime(CLOCK_MONOTONIC, &sys));
        assert(llabs(vds.tv_sec - sys.tv_sec) <= 1);

        assert(!fn(CLOCK_REALTIME, &vds));
        assert(!clock_gettime(CLOCK_REALTIME, &sys));
        assert(llabs(vds.tv_sec - sys.tv_sec) <= 1);

        // Неподдерживаемый clockid -> -EINVAL, как в Linux.
        assert(fn(0x5a5a, &vds) == -EINVAL);
}));

DEFINE_TEST(vdso_gettimeofday, ([] {
        uintptr_t base = getauxval(AT_SYSINFO_EHDR);
        assert(base);
        auto fn = reinterpret_cast<int (*)(struct timeval *, void *)>(
                        vdso_lookup(base, "__vdso_gettimeofday"));
        assert(fn);

        struct timeval vds, sys;
        assert(!fn(&vds, nullptr));
        assert(!gettimeofday(&sys, nullptr));
        assert(llabs(vds.tv_sec - sys.tv_sec) <= 1);
}));

DEFINE_TEST(vdso_time, ([] {
        uintptr_t base = getauxval(AT_SYSINFO_EHDR);
        assert(base);
        auto fn = reinterpret_cast<time_t (*)(time_t *)>(
                        vdso_lookup(base, "__vdso_time"));
        assert(fn);

        time_t vds = fn(nullptr);
        time_t sys = time(nullptr);
        assert(llabs(vds - sys) <= 1);
}));
