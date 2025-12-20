#ifndef LIBCOLONQ_ELF_H
#define LIBCOLONQ_ELF_H

#include <lcq/elf/utils.h>
#include <lcq/elf/platform/x86.h>
#include <lcq/elf/platform/amd64.h>

/* context */
typedef enum elf_class {
    ELF_CLASS_INVALID = 0,
    ELF_CLASS_32 = 1,
    ELF_CLASS_64 = 2
} elf_class;
typedef enum elf_endianness {
    ELF_ENDIANNESS_INVALID = 0,
    ELF_ENDIANNESS_LITTLE = 1,
    ELF_ENDIANNESS_BIG = 2
} elf_endianness;
#define ELF_HEADER_IDENT_SIZE 16
typedef struct elf_header_ident {
    elf_class file_class;
    elf_endianness endianness;
    u8 version;
    u8 abi;
    u8 abi_version;
} elf_header_ident;
typedef struct elf_ctx {
    u8 *buf; i64 len;
    elf_header_ident ident;
} elf_ctx;
i64 elf_read_header_ident(elf_header_ident *i, u8 *buf, i64 len);
i64 elf_write_header_ident(elf_header_ident *i, u8 *buf, i64 len);
elf_ctx elf_load_from_path(char *p);
elf_ctx elf_ctx_new(u8 *buf, i64 len, elf_class cl, elf_endianness end);

/* header */
typedef enum elf_type {
    ELF_TYPE_NONE = 0,
    ELF_TYPE_REL = 1,
    ELF_TYPE_EXEC = 2,
    ELF_TYPE_DYN = 3,
    ELF_TYPE_CORE = 4,
    ELF_TYPE_LO_OS = 0xfe00, ELF_TYPE_HI_OS = 0xfeff,
    ELF_TYPE_LO_PROC = 0xff00, ELF_TYPE_HI_PROC = 0xffff
} elf_type;
typedef enum elf_machine {
    ELF_MACHINE_NONE = 0,
    ELF_MACHINE_X86 = 3,
    ELF_MACHINE_AMD64 = 62
} elf_machine;
#define ELF32_HEADER_SIZE 52
#define ELF64_HEADER_SIZE 64
i64 elf_header_size(elf_ctx *ctx);
typedef struct elf_header {
    elf_type type;
    elf_machine machine;
    u32 version;
    u64 entry;
    u64 program_header_offset;
    u64 section_header_offset;
    u32 flags;
    u16 elf_header_size;
    u16 program_header_entry_size;
    u16 program_header_entries;
    u16 section_header_entry_size;
    u16 section_header_entries;
    u16 section_name_table_index;
} elf_header;
i64 elf_read_header(elf_header *ret, elf_ctx *ctx);
i64 elf_write_header(elf_header *h, elf_ctx *ctx);
u64 elf_program_header_offset(elf_header *h, u64 idx);
u64 elf_section_header_offset(elf_header *h, u64 idx);

/* section header */
typedef enum elf_section_type {
    ELF_SECTION_TYPE_NULL = 0,
    ELF_SECTION_TYPE_PROGBITS = 1,
    ELF_SECTION_TYPE_SYMTAB = 2,
    ELF_SECTION_TYPE_STRTAB = 3,
    ELF_SECTION_TYPE_RELA = 4,
    ELF_SECTION_TYPE_HASH = 5,
    ELF_SECTION_TYPE_DYNAMIC = 6,
    ELF_SECTION_TYPE_NOTE = 7,
    ELF_SECTION_TYPE_NOBITS = 8,
    ELF_SECTION_TYPE_REL = 9,
    ELF_SECTION_TYPE_SHLIB = 10,
    ELF_SECTION_TYPE_DYNSYM = 11,
    ELF_SECTION_TYPE_INIT_ARRAY = 14,
    ELF_SECTION_TYPE_FINI_ARRAY = 15,
    ELF_SECTION_TYPE_PREINIT_ARRAY = 16,
    ELF_SECTION_TYPE_GROUP = 17,
    ELF_SECTION_TYPE_SYMTAB_SHNDX = 18
} elf_section_type;
/* enums are only guaranteed to represent signed int in c89 */
#define ELF_SECTION_TYPE_LO_OS 0x60000000
#define ELF_SECTION_TYPE_HI_OS 0x6fffffff
#define ELF_SECTION_TYPE_LO_PROC 0x70000000
#define ELF_SECTION_TYPE_HI_PROC 0x7fffffff
#define ELF_SECTION_TYPE_LO_USER 0x80000000
#define ELF_SECTION_TYPE_HI_USER 0x8fffffff
typedef enum elf_section_flag {
    ELF_SECTION_FLAG_WRITE = 0x1,
    ELF_SECTION_FLAG_ALLOC = 0x2,
    ELF_SECTION_FLAG_EXECINSTR = 0x4,
    ELF_SECTION_FLAG_MERGE = 0x10,
    ELF_SECTION_FLAG_STRINGS = 0x20,
    ELF_SECTION_FLAG_INFO_LINK = 0x40,
    ELF_SECTION_FLAG_LINK_ORDER = 0x80,
    ELF_SECTION_FLAG_OS_NONCOMFORMING = 0x100,
    ELF_SECTION_FLAG_GROUP = 0x200,
    ELF_SECTION_FLAG_TLS = 0x400,
    ELF_SECTION_FLAG_COMPRESSED = 0x800
} elf_section_flag;
#define ELF_SECTION_FLAG_MASKOS 0x0ff00000
#define ELF_SECTION_FLAG_MASKPROC 0xf0000000
#define ELF32_SECTION_HEADER_SIZE 40
#define ELF64_SECTION_HEADER_SIZE 64
i64 elf_section_header_size(elf_ctx *ctx);
typedef struct elf_section_header {
    u32 name_index;
    u32 /* elf_section_type */ type;
    u64 /* elf_section_flag */ flags;
    u64 addr;
    u64 offset;
    u64 size;
    u32 link;
    u32 info;
    u64 addr_alignment;
    u64 entry_size;
} elf_section_header;
i64 elf_read_section_header(elf_section_header *ret, elf_ctx *ctx, u64 off);
i64 elf_write_section_header(elf_section_header *sh, elf_ctx *ctx, u64 off);
char *elf_read_section_name(elf_ctx *ctx, elf_header *h, elf_section_header *sh);

/* symbols */
typedef enum elf_symbol_binding {
    ELF_SYMBOL_BINDING_LOCAL = 0,
    ELF_SYMBOL_BINDING_GLOBAL = 1,
    ELF_SYMBOL_BINDING_WEAK = 2,
    ELF_SYMBOL_BINDING_LO_OS = 10,
    ELF_SYMBOL_BINDING_HI_OS = 12,
    ELF_SYMBOL_BINDING_LO_PROC = 13,
    ELF_SYMBOL_BINDING_HI_PROC = 15
} elf_symbol_binding;
typedef enum elf_symbol_type {
    ELF_SYMBOL_TYPE_NOTYPE = 0,
    ELF_SYMBOL_TYPE_OBJECT = 1,
    ELF_SYMBOL_TYPE_FUNC = 2,
    ELF_SYMBOL_TYPE_SECTION = 3,
    ELF_SYMBOL_TYPE_FILE = 4,
    ELF_SYMBOL_TYPE_COMMON = 5,
    ELF_SYMBOL_TYPE_TLS = 6,
    ELF_SYMBOL_TYPE_LO_OS = 10,
    ELF_SYMBOL_TYPE_HI_OS = 12,
    ELF_SYMBOL_TYPE_LO_PROC = 13,
    ELF_SYMBOL_TYPE_HI_PROC = 15
} elf_symbol_type;
typedef enum elf_symbol_visibility {
    ELF_SYMBOL_VISIBILITY_DEFAULT = 0,
    ELF_SYMBOL_VISIBILITY_INTERNAL = 1,
    ELF_SYMBOL_VISIBILITY_HIDDEN = 2,
    ELF_SYMBOL_VISIBILITY_PROTECTED = 3
} elf_symbol_visibility;
#define ELF32_SYMBOL_SIZE 16
#define ELF64_SYMBOL_SIZE 24
i64 elf_symbol_size(elf_ctx *ctx);
typedef struct elf_symbol {
    u64 size;
    u64 value;
    u32 name_index;
    elf_symbol_binding bind; elf_symbol_type type; /* info */
    elf_symbol_visibility visibility; /* other */
    u16 section_header_index;
} elf_symbol;
i64 elf_read_symbol(elf_symbol *ret, elf_ctx *ctx, u64 off);
i64 elf_write_symbol(elf_symbol *sym, elf_ctx *ctx, u64 off);
char *elf_read_symbol_name(elf_ctx *ctx, elf_header *h, elf_section_header *sh, elf_symbol *sym);

/* relocations */
#define ELF32_REL_SIZE 8
#define ELF64_REL_SIZE 16
i64 elf_rel_size(elf_ctx *ctx);
typedef struct elf_rel {
    u64 offset;
    u64 symtab_index, type; /* info */
} elf_rel;
#define ELF32_RELA_SIZE 12
#define ELF64_RELA_SIZE 24
i64 elf_rela_size(elf_ctx *ctx);
typedef struct elf_rela {
    u64 offset;
    u64 symtab_index; u64 type;
    i64 addend;
} elf_rela;
i64 elf_read_rel(elf_rel *ret, elf_ctx *ctx, u64 off);
i64 elf_read_rela(elf_rela *ret, elf_ctx *ctx, u64 off);

typedef enum elf_program_header_type {
    ELF_PROGRAM_HEADER_TYPE_NULL = 0,
    ELF_PROGRAM_HEADER_TYPE_LOAD = 1,
    ELF_PROGRAM_HEADER_TYPE_DYNAMIC = 2,
    ELF_PROGRAM_HEADER_TYPE_INTERP = 3,
    ELF_PROGRAM_HEADER_TYPE_NOTE = 4,
    ELF_PROGRAM_HEADER_TYPE_SHLIB = 5,
    ELF_PROGRAM_HEADER_TYPE_PHDR = 6,
    ELF_PROGRAM_HEADER_TYPE_TLS = 7
} elf_program_header_type;
#define ELF_PROGRAM_HEADER_TYPE_LOOS 0x60000000
#define ELF_PROGRAM_HEADER_TYPE_HIOS 0x6fffffff
#define ELF_PROGRAM_HEADER_TYPE_LOPROC 0x70000000
#define ELF_PROGRAM_HEADER_TYPE_HIPROC 0x7fffffff
typedef enum elf_program_header_flag {
    ELF_PROGRAM_HEADER_FLAG_X = 0x1,
    ELF_PROGRAM_HEADER_FLAG_W = 0x2,
    ELF_PROGRAM_HEADER_FLAG_R = 0x4
} elf_program_header_flag;
#define ELF_PROGRAM_HEADER_FLAG_MASKOS 0xff00000
#define ELF_PROGRAM_HEADER_FLAG_MASKPROC 0xf0000000
#define ELF32_PROGRAM_HEADER_SIZE 32
#define ELF64_PROGRAM_HEADER_SIZE 56
i64 elf_program_header_size(elf_ctx *ctx);
typedef struct elf_program_header {
    u32 /* elf_program_header_type */ type;
    u64 offset;
    u64 virtual_addr;
    u64 physical_addr;
    u64 file_size;
    u64 mem_size;
    u32 /* elf_program_header_flag */ flags;
    u64 align;
} elf_program_header;
i64 elf_read_program_header(elf_program_header *ret, elf_ctx *ctx, u64 off);
i64 elf_write_program_header(elf_program_header *ph, elf_ctx *ctx, u64 off);

/* writing bytes */
i64 elf_write_bytes(elf_ctx *ctx, u64 *off, u8 *buf, i64 len);
#define ELF_STRTAB_BYTES_OFF(str) (u8*)str,strlen(str)+1

#endif
