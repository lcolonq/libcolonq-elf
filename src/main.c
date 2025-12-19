#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"

u8 TEST_PROG[] = {
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, /* mov $0x3c,%rax */
    0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00, /* mov $0x2a,%rdi */
    0x0f, 0x05 /* syscall */
};

int main(int argc, char **argv) {
    elf_ctx e = {0};
    elf_header h = {0};
    elf_section_header sh = {0};
    elf_program_header ph = {0};
    i64 i = 0;

    if (argc < 3) { fprintf(stderr, "usage: %s MODE ELF-PATH\n", argv[0]); return 1; }
    if (strcmp(argv[1], "read") == 0) {
        e = elf_load_from_path(argv[2]);
        elf_read_header(&h, &e);
        printf("%d %d %d %d %d\n", e.ident.file_class, e.ident.endianness, e.ident.version, e.ident.abi, e.ident.abi_version);
        printf("type=%u, machine=%u\n", h.type, h.machine);
        printf("version=%u, entry=0x%lx\n", h.version, h.entry);
        printf("ph=%lu, sh=%lu\n", h.program_header_offset, h.section_header_offset);
        printf("flags=%u, eh=%u\n", h.flags, h.elf_header_size);
        printf("ph_ent_size=%u, ph_ents=%u\n", h.program_header_entry_size, h.program_header_entries);
        printf("sh_ent_size=%u, sh_ents=%u\n", h.section_header_entry_size, h.section_header_entries);
        printf("nametable=%u\n", h.section_name_table_index);

        for (i = 0; i < h.section_header_entries; ++i) {
            char *name = NULL;
            elf_read_section_header(&sh, &e, elf_section_header_offset(&h, (u64) i));
            name = elf_read_section_name(&e, &h, &sh);
            printf("section %ld (%s) type: %u\n", i, name, sh.type);
        }
        for (i = 0; i < h.section_header_entries; ++i) {
            elf_read_section_header(&sh, &e, elf_section_header_offset(&h, (u64) i));
            if (sh.type == ELF_SECTION_TYPE_SYMTAB) {
                u64 symoff = 0;
                for (symoff = 0; symoff < sh.size; symoff += sh.entry_size) {
                    elf_symbol s = {0};
                    elf_read_symbol(&s, &e, sh.offset + symoff);
                    printf("symbol offset %ld (%s) type: %u\n",
                        symoff,
                        elf_read_symbol_name(&e, &h, &sh, &s),
                        s.type
                    );
                }
            }
        }
    } else {
        elf_symbol s = {0};
        i64 len = 1024 * 16;
        u8 *buf = calloc((size_t) len, sizeof(u8));
        FILE *f = NULL;
        u64 sh_off = 0,
            shstrtab_off = 0,
            shstrtab_name_off = 0,
            shstrtab_len = 0,
            strtab_off = 0,
            strtab_name_off = 0,
            strtab_len = 0,
            symtab_off = 0,
            symtab_name_off = 0,
            symtab_len = 0,
            text_off = 0,
            text_name_off = 0,
            text_len = 0,
            program_header_off = 0,
            off = 0,
            symbols = 0,
            sections = 0;
        e = elf_ctx_new(buf, len, ELF_CLASS_64, ELF_ENDIANNESS_LITTLE);
        off = ELF64_HEADER_SIZE;

        /* make space for program header */
        program_header_off = off;
        off += ELF64_PROGRAM_HEADER_SIZE;

        /* write shstrtab */
        shstrtab_off = off;
        e.buf[off++] = 0;
        shstrtab_name_off = off - shstrtab_off; elf_write_bytes(&e, &off, ELF_STRTAB_BYTES_OFF(".shstrtab"));
        strtab_name_off = off - shstrtab_off; elf_write_bytes(&e, &off, ELF_STRTAB_BYTES_OFF(".strtab"));
        symtab_name_off = off - shstrtab_off; elf_write_bytes(&e, &off, ELF_STRTAB_BYTES_OFF(".symtab"));
        text_name_off = off - shstrtab_off; elf_write_bytes(&e, &off, ELF_STRTAB_BYTES_OFF(".text"));
        e.buf[off++] = 0;
        shstrtab_len = off - shstrtab_off;

        /* write strtab */
        strtab_off = off;
        e.buf[off++] = 0;
        elf_write_bytes(&e, &off, ELF_STRTAB_BYTES_OFF("_start"));
        e.buf[off++] = 0;
        strtab_len = off - strtab_off;

        /* write symtab */
        symtab_off = off;
        printf("symtab_off: %lu\n", symtab_off);
        /* null symbol */
        symbols += 1;
        s.size = 0;
        s.value = 0;
        s.name_index = 0;
        s.bind = ELF_SYMBOL_BINDING_LOCAL;
        s.type = ELF_SYMBOL_TYPE_NOTYPE;
        s.visibility = ELF_SYMBOL_VISIBILITY_DEFAULT;
        s.section_header_index = 0;
        elf_write_symbol(&s, &e, off);
        off += ELF64_SYMBOL_SIZE;

        /* _start */
        symbols += 1;
        s.size = 0;
        s.value = 0x401000;
        s.name_index = 1;
        s.bind = ELF_SYMBOL_BINDING_GLOBAL;
        s.type = ELF_SYMBOL_TYPE_NOTYPE;
        s.visibility = ELF_SYMBOL_VISIBILITY_DEFAULT;
        s.section_header_index = 4;
        elf_write_symbol(&s, &e, off);
        off += ELF64_SYMBOL_SIZE;
        symtab_len = off - symtab_off;

        /* write text */
        /* text_off = off; */
        text_off = 0x1000;
        text_len = text_off;
        elf_write_bytes(&e, &text_len, TEST_PROG, sizeof(TEST_PROG));
        /* text_len = off - text_off; */
        text_len -= text_off;

        /* write section headers */
        sh_off = off;

        /* null section */
        sections += 1;
        sh.name_index = 0; sh.type = ELF_SECTION_TYPE_NULL;
        sh.flags = 0; sh.addr = 0; sh.offset = 0; sh.size = 0;
        sh.link = 0; sh.info = 0; sh.addr_alignment = 0; sh.entry_size = 0;
        elf_write_section_header(&sh, &e, off); off += ELF64_SECTION_HEADER_SIZE;

        /* .shstrtab */
        sections += 1;
        sh.name_index = (u32) shstrtab_name_off; sh.type = ELF_SECTION_TYPE_STRTAB;
        sh.flags = 0; sh.addr = 0; sh.offset = shstrtab_off; sh.size = shstrtab_len;
        sh.link = 0; sh.info = 0; sh.addr_alignment = 0; sh.entry_size = 0;
        elf_write_section_header(&sh, &e, off); off += ELF64_SECTION_HEADER_SIZE;

        /* .strtab */
        sections += 1;
        sh.name_index = (u32) strtab_name_off; sh.type = ELF_SECTION_TYPE_STRTAB;
        sh.flags = 0; sh.addr = 0; sh.offset = strtab_off; sh.size = strtab_len;
        sh.link = 0; sh.info = 0; sh.addr_alignment = 0; sh.entry_size = 0;
        elf_write_section_header(&sh, &e, off); off += ELF64_SECTION_HEADER_SIZE;

        /* .symtab */
        sections += 1;
        sh.name_index = (u32) symtab_name_off; sh.type = ELF_SECTION_TYPE_SYMTAB;
        sh.flags = 0; sh.addr = 0; sh.offset = symtab_off; sh.size = symtab_len;
        sh.link = 2; sh.info = 1; sh.addr_alignment = 0; sh.entry_size = ELF64_SYMBOL_SIZE;
        elf_write_section_header(&sh, &e, off); off += ELF64_SECTION_HEADER_SIZE;

        /* .text */
        sections += 1;
        sh.name_index = (u32) text_name_off; sh.type = ELF_SECTION_TYPE_PROGBITS;
        sh.flags = ELF_SECTION_FLAG_ALLOC | ELF_SECTION_FLAG_EXECINSTR;
        sh.addr = 0x401000; sh.offset = text_off; sh.size = text_len;
        sh.link = 0; sh.info = 0; sh.addr_alignment = 0; sh.entry_size = 0;
        elf_write_section_header(&sh, &e, off); off += ELF64_SECTION_HEADER_SIZE;

        /* write program header */
        ph.type = ELF_PROGRAM_HEADER_TYPE_LOAD;
        ph.offset = text_off;
        ph.virtual_addr = 0x401000;
        ph.physical_addr = 0;
        ph.file_size = (u32) text_len;
        ph.mem_size = (u32) text_len;
        ph.flags = ELF_PROGRAM_HEADER_FLAG_R | ELF_PROGRAM_HEADER_FLAG_X;
        ph.align = 0;
        elf_write_program_header(&ph, &e, program_header_off);

        /* write header at the start */
        h.type = ELF_TYPE_EXEC;
        h.machine = ELF_MACHINE_AMD64;
        h.version = 1;
        h.entry = 0x401000;
        h.program_header_offset = program_header_off;
        h.program_header_entry_size = ELF64_PROGRAM_HEADER_SIZE;
        h.program_header_entries = 1;
        h.section_header_offset = sh_off;
        h.section_header_entry_size = ELF64_SECTION_HEADER_SIZE;
        h.section_header_entries = (u16) sections;
        h.section_name_table_index = 1;
        elf_write_header(&h, &e);
        f = fopen(argv[2], "w+");
        fwrite(buf, sizeof(u8), (size_t) len, f);
        fclose(f);
    }
    return 0;
}
