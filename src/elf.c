#include "elf.h"

#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

i64 elf_read_header_ident(elf_header_ident *ret, u8 *buf, i64 len) {
    if (len < ELF_HEADER_IDENT_SIZE) return -1;
    if (buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') return -1;
    ret->file_class = buf[4];
    ret->endianness = buf[5];
    ret->version = buf[6];
    ret->abi = buf[7];
    ret->abi_version = buf[8];
    return 0;
}

i64 elf_write_header_ident(elf_header_ident *i, u8 *buf, i64 len) {
    if (len < ELF_HEADER_IDENT_SIZE) return -1;
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[4] = i->file_class;
    buf[5] = i->endianness;
    buf[6] = i->version;
    buf[7] = i->abi;
    buf[8] = i->abi_version;
    return 0;
}

elf_ctx elf_load_from_path(char *p) {
    FILE *f = NULL;
    i64 len = 0;
    u8 *buf = NULL;
    elf_ctx ret;
    ret.buf = NULL; ret.len = -1;
    if (!p) return ret;
    f = fopen(p, "r");
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = calloc((size_t) len, sizeof(u8));
    if ((size_t) len != fread(buf, sizeof(u8), (size_t) len, f)
        || elf_read_header_ident(&ret.ident, buf, len) < 0) {
        free(buf);
    } else {
        ret.buf = buf; ret.len = len;
    }
    fclose(f);
    return ret;
}

elf_ctx elf_ctx_new(u8 *buf, i64 len, elf_class cl, elf_endianness end) {
    elf_ctx ret;
    ret.buf = buf; ret.len = len;
    ret.ident.file_class = cl;
    ret.ident.endianness = end;
    ret.ident.version = 1;
    ret.ident.abi = 0;
    ret.ident.abi_version = 0;
    elf_write_header_ident(&ret.ident, ret.buf, ret.len);
    return ret;
}

static u8 read_u8(elf_ctx *ctx, u64 *off) {
    assert(off != NULL);
    assert((i64) *off < ctx->len);
    return ctx->buf[(*off)++];
}
static void write_u8(elf_ctx *ctx, u64 *off, u8 x) {
    assert(off != NULL);
    assert((i64) *off < ctx->len);
    ctx->buf[(*off)++] = x;
}
static u16 read_u16(elf_ctx *ctx, u64 *off) {
    u16 b0, b1;
    assert(off != NULL);
    assert((i64) *off < ctx->len);
    assert(ctx->ident.endianness == ELF_ENDIANNESS_LITTLE
        || ctx->ident.endianness == ELF_ENDIANNESS_BIG);
    b0 = ctx->buf[(*off)++]; b1 = ctx->buf[(*off)++];
    if (ctx->ident.endianness == ELF_ENDIANNESS_LITTLE) {
        return b0 | b1 << 8;
    } else {
        return b0 << 8 | b1;
    }
}
static void write_u16(elf_ctx *ctx, u64 *off, u16 x) {
    u16 b0, b1;
    assert(off != NULL);
    assert((i64) *off < ctx->len);
    assert(ctx->ident.endianness == ELF_ENDIANNESS_LITTLE
        || ctx->ident.endianness == ELF_ENDIANNESS_BIG);
    b0 = x; b1 = x >> 8;
    if (ctx->ident.endianness == ELF_ENDIANNESS_LITTLE) {
        ctx->buf[(*off)++] = (u8) b0; ctx->buf[(*off)++] = (u8) b1;
    } else {
        ctx->buf[(*off)++] = (u8) b1; ctx->buf[(*off)++] = (u8) b0;
    }
}
static u32 read_u32(elf_ctx *ctx, u64 *off) {
    u32 b0, b1, b2, b3;
    assert(off != NULL);
    assert((i64) *off < ctx->len);
    assert(ctx->ident.endianness == ELF_ENDIANNESS_LITTLE
        || ctx->ident.endianness == ELF_ENDIANNESS_BIG);
    b0 = ctx->buf[(*off)++]; b1 = ctx->buf[(*off)++];
    b2 = ctx->buf[(*off)++]; b3 = ctx->buf[(*off)++];
    if (ctx->ident.endianness == ELF_ENDIANNESS_LITTLE) {
        return b0 | b1 << 8 | b2 << 16 | b3 << 24;
    } else {
        return b0 << 24 | b1 << 16 | b2 << 8 | b3;
    }
}
static void write_u32(elf_ctx *ctx, u64 *off, u32 x) {
    u32 b0, b1, b2, b3;
    assert(off != NULL);
    assert((i64) *off < ctx->len);
    assert(ctx->ident.endianness == ELF_ENDIANNESS_LITTLE
        || ctx->ident.endianness == ELF_ENDIANNESS_BIG);
    b0 = x; b1 = x >> 8; b2 = x >> 16; b3 = x >> 24;
    if (ctx->ident.endianness == ELF_ENDIANNESS_LITTLE) {
        ctx->buf[(*off)++] = (u8) b0; ctx->buf[(*off)++] = (u8) b1;
        ctx->buf[(*off)++] = (u8) b2; ctx->buf[(*off)++] = (u8) b3;
    } else {
        ctx->buf[(*off)++] = (u8) b3; ctx->buf[(*off)++] = (u8) b2;
        ctx->buf[(*off)++] = (u8) b1; ctx->buf[(*off)++] = (u8) b0;
    }
}
static u64 read_u64(elf_ctx *ctx, u64 *off) {
    u64 b0, b1, b2, b3, b4, b5, b6, b7;
    assert(off != NULL);
    assert((i64) *off < ctx->len);
    assert(ctx->ident.endianness == ELF_ENDIANNESS_LITTLE
        || ctx->ident.endianness == ELF_ENDIANNESS_BIG);
    b0 = ctx->buf[(*off)++]; b1 = ctx->buf[(*off)++];
    b2 = ctx->buf[(*off)++]; b3 = ctx->buf[(*off)++];
    b4 = ctx->buf[(*off)++]; b5 = ctx->buf[(*off)++];
    b6 = ctx->buf[(*off)++]; b7 = ctx->buf[(*off)++];
    if (ctx->ident.endianness == ELF_ENDIANNESS_LITTLE) {
        return b0 | b1 << 8 | b2 << 16 | b3 << 24
            | b4 << 32 | b5 << 40 | b6 << 48 | b7 << 56;
    } else {
        return b0 << 56 | b1 << 48 | b2 << 40 | b3 << 32
            | b4 << 24 | b5 << 16 | b6 << 8 | b7;
    }
}
static void write_u64(elf_ctx *ctx, u64 *off, u64 x) {
    u64 b0, b1, b2, b3, b4, b5, b6, b7;
    assert(off != NULL);
    assert((i64) *off < ctx->len);
    assert(ctx->ident.endianness == ELF_ENDIANNESS_LITTLE
        || ctx->ident.endianness == ELF_ENDIANNESS_BIG);
    b0 = x; b1 = x >> 8; b2 = x >> 16; b3 = x >> 24;
    b4 = x >> 32; b5 = x >> 40; b6 = x >> 48; b7 = x >> 56;
    if (ctx->ident.endianness == ELF_ENDIANNESS_LITTLE) {
        ctx->buf[(*off)++] = (u8) b0; ctx->buf[(*off)++] = (u8) b1;
        ctx->buf[(*off)++] = (u8) b2; ctx->buf[(*off)++] = (u8) b3;
        ctx->buf[(*off)++] = (u8) b4; ctx->buf[(*off)++] = (u8) b5;
        ctx->buf[(*off)++] = (u8) b6; ctx->buf[(*off)++] = (u8) b7;
    } else {
        ctx->buf[(*off)++] = (u8) b7; ctx->buf[(*off)++] = (u8) b6;
        ctx->buf[(*off)++] = (u8) b5; ctx->buf[(*off)++] = (u8) b4;
        ctx->buf[(*off)++] = (u8) b3; ctx->buf[(*off)++] = (u8) b2;
        ctx->buf[(*off)++] = (u8) b1; ctx->buf[(*off)++] = (u8) b0;
    }
}
static u64 read_file_class_word(elf_ctx *ctx, u64 *off) {
    assert(ctx);
    assert(ctx->ident.file_class == ELF_CLASS_32
        || ctx->ident.file_class == ELF_CLASS_64);
    if (ctx->ident.file_class == ELF_CLASS_32) {
        return (u64) read_u32(ctx, off);
    } else {
        return (u64) read_u64(ctx, off);
    }
}
static void write_file_class_word(elf_ctx *ctx, u64 *off, u64 x) {
    assert(ctx);
    assert(ctx->ident.file_class == ELF_CLASS_32
        || ctx->ident.file_class == ELF_CLASS_64);
    if (ctx->ident.file_class == ELF_CLASS_32) {
        write_u32(ctx, off, (u32) x);
    } else {
        write_u64(ctx, off, x);
    }
}
static i64 read_file_class_signed_word(elf_ctx *ctx, u64 *off) {
    assert(ctx);
    assert(ctx->ident.file_class == ELF_CLASS_32
        || ctx->ident.file_class == ELF_CLASS_64);
    if (ctx->ident.file_class == ELF_CLASS_32) {
        return (i64) (i32) read_u32(ctx, off);
    } else {
        return (i64) read_u64(ctx, off);
    }
}
static void write_file_class_signed_word(elf_ctx *ctx, u64 *off, i64 x) {
    assert(ctx);
    assert(ctx->ident.file_class == ELF_CLASS_32
        || ctx->ident.file_class == ELF_CLASS_64);
    if (ctx->ident.file_class == ELF_CLASS_32) {
        assert(x < UINT32_MAX);
        write_u32(ctx, off, (u32) (u64) x);
    } else {
        write_u64(ctx, off, (u64) x);
    }
}

i64 elf_read_header(elf_header *ret, elf_ctx *ctx) {
    u64 off = ELF_HEADER_IDENT_SIZE;
    i64 sz = ctx->ident.file_class == ELF_CLASS_32
        ? ELF32_HEADER_SIZE : ELF64_HEADER_SIZE;
    if (!ret || !ctx || ctx->len < sz) return -1;
    ret->type = read_u16(ctx, &off);
    ret->machine = read_u16(ctx, &off);
    ret->version = read_u32(ctx, &off);
    ret->entry = read_file_class_word(ctx, &off);
    ret->program_header_offset = read_file_class_word(ctx, &off);
    ret->section_header_offset = read_file_class_word(ctx, &off);
    ret->flags = read_u32(ctx, &off);
    ret->elf_header_size = read_u16(ctx, &off);
    ret->program_header_entry_size = read_u16(ctx, &off);
    ret->program_header_entries = read_u16(ctx, &off);
    ret->section_header_entry_size = read_u16(ctx, &off);
    ret->section_header_entries = read_u16(ctx, &off);
    ret->section_name_table_index = read_u16(ctx, &off);
    return 0;
}
i64 elf_write_header(elf_header *h, elf_ctx *ctx) {
    u64 off = ELF_HEADER_IDENT_SIZE;
    i64 sz = ctx->ident.file_class == ELF_CLASS_32
        ? ELF32_HEADER_SIZE : ELF64_HEADER_SIZE;
    if (!h || !ctx || ctx->len < sz) return -1;
    write_u16(ctx, &off, h->type);
    write_u16(ctx, &off, h->machine);
    write_u32(ctx, &off, h->version);
    printf("entry off: %lu\n", off);
    write_file_class_word(ctx, &off, h->entry);
    write_file_class_word(ctx, &off, h->program_header_offset);
    write_file_class_word(ctx, &off, h->section_header_offset);
    write_u32(ctx, &off, h->flags);
    write_u16(ctx, &off, h->elf_header_size);
    write_u16(ctx, &off, h->program_header_entry_size);
    write_u16(ctx, &off, h->program_header_entries);
    write_u16(ctx, &off, h->section_header_entry_size);
    write_u16(ctx, &off, h->section_header_entries);
    write_u16(ctx, &off, h->section_name_table_index);
    return 0;
}

/* given the index of a program/section header, return its file offset */
u64 elf_program_header_offset(elf_header *h, u64 idx) {
    return h->program_header_offset + idx * h->program_header_entry_size;
}
u64 elf_section_header_offset(elf_header *h, u64 idx) {
    return h->section_header_offset + idx * h->section_header_entry_size;
}

i64 elf_read_section_header(elf_section_header *ret, elf_ctx *ctx, u64 off) {
    i64 sz = ctx->ident.file_class == ELF_CLASS_32
        ? ELF32_SECTION_HEADER_SIZE : ELF64_SECTION_HEADER_SIZE;
    if (!ret || !ctx || ctx->len < (i64) off + sz) return -1;
    ret->name_index = read_u32(ctx, &off);
    ret->type = read_u32(ctx, &off);
    ret->flags = read_file_class_word(ctx, &off);
    ret->addr = read_file_class_word(ctx, &off);
    ret->offset = read_file_class_word(ctx, &off);
    ret->size = read_file_class_word(ctx, &off);
    ret->link = read_u32(ctx, &off);
    ret->info = read_u32(ctx, &off);
    ret->addr_alignment = read_file_class_word(ctx, &off);
    ret->entry_size = read_file_class_word(ctx, &off);
    return 0;
}
i64 elf_write_section_header(elf_section_header *sh, elf_ctx *ctx, u64 off) {
    i64 sz = ctx->ident.file_class == ELF_CLASS_32
        ? ELF32_SECTION_HEADER_SIZE : ELF64_SECTION_HEADER_SIZE;
    if (!sh || !ctx || ctx->len < (i64) off + sz) return -1;
    printf("section off: %lu\n", off);
    write_u32(ctx, &off, sh->name_index);
    write_u32(ctx, &off, sh->type);
    write_file_class_word(ctx, &off, sh->flags);
    write_file_class_word(ctx, &off, sh->addr);
    write_file_class_word(ctx, &off, sh->offset);
    write_file_class_word(ctx, &off, sh->size);
    write_u32(ctx, &off, sh->link);
    write_u32(ctx, &off, sh->info);
    write_file_class_word(ctx, &off, sh->addr_alignment);
    write_file_class_word(ctx, &off, sh->entry_size);
    return 0;
}

char *elf_read_section_name(elf_ctx *ctx, elf_header *h, elf_section_header *sh) {
    elf_section_header name_section;
    if (!ctx || !h || !sh) return NULL;
    if (h->section_name_table_index >= h->section_header_entries) return NULL;
    if (elf_read_section_header(&name_section, ctx,
            elf_section_header_offset(h, h->section_name_table_index)) < 0)
        return NULL;
    return (char *) &ctx->buf[name_section.offset + sh->name_index];
}

i64 elf_read_symbol(elf_symbol *ret, elf_ctx *ctx, u64 off) {
    i64 sz = ctx->ident.file_class == ELF_CLASS_32
        ? ELF32_SYMBOL_SIZE : ELF64_SYMBOL_SIZE;
    u8 info, other;
    assert(ctx->ident.file_class == ELF_CLASS_32
        || ctx->ident.file_class == ELF_CLASS_64);
    if (!ret || !ctx || ctx->len < (i64) off + sz) return -1;
    if (ctx->ident.file_class == ELF_CLASS_32) {
        ret->name_index = read_u32(ctx, &off);
        ret->value = read_u32(ctx, &off);
        ret->size = read_u32(ctx, &off);
        info = read_u8(ctx, &off);
        ret->bind = info >> 4;
        ret->type = info & 0xf;
        other = read_u8(ctx, &off);
        ret->visibility = other & 0x3;
        ret->section_header_index = read_u16(ctx, &off);
    } else {
        ret->name_index = read_u32(ctx, &off);
        info = read_u8(ctx, &off);
        ret->bind = info >> 4;
        ret->type = info & 0xf;
        other = read_u8(ctx, &off);
        ret->visibility = other & 0x3;
        ret->section_header_index = read_u16(ctx, &off);
        ret->value = read_u64(ctx, &off);
        ret->size = read_u64(ctx, &off);
    }
    return 0;
}
i64 elf_write_symbol(elf_symbol *sym, elf_ctx *ctx, u64 off) {
    i64 sz = ctx->ident.file_class == ELF_CLASS_32
        ? ELF32_SYMBOL_SIZE : ELF64_SYMBOL_SIZE;
    u8 info, other;
    assert(ctx->ident.file_class == ELF_CLASS_32
        || ctx->ident.file_class == ELF_CLASS_64);
    if (!sym || !ctx || ctx->len < (i64) off + sz) return -1;
    if (ctx->ident.file_class == ELF_CLASS_32) {
        write_u32(ctx, &off, sym->name_index);
        write_u32(ctx, &off, (u32) sym->value);
        write_u32(ctx, &off, (u32) sym->size);
        info = (u8) sym->bind << 4 | sym->type;
        write_u8(ctx, &off, info);
        other = sym->visibility;
        write_u8(ctx, &off, other);
        write_u16(ctx, &off, sym->section_header_index);
    } else {
        write_u32(ctx, &off, sym->name_index);
        info = (u8) sym->bind << 4 | sym->type;
        write_u8(ctx, &off, info);
        other = sym->visibility;
        write_u8(ctx, &off, other);
        write_u16(ctx, &off, sym->section_header_index);
        write_u64(ctx, &off, sym->value);
        write_u64(ctx, &off, sym->size);
    }
    return 0;
}

static void parse_relocation_info(
    u64 *symtab_index, u64 *type, elf_ctx *ctx, u64 info
) {
    assert(symtab_index != NULL && type != NULL);
    assert(ctx->ident.file_class == ELF_CLASS_32
        || ctx->ident.file_class == ELF_CLASS_64);
    if (ctx->ident.file_class == ELF_CLASS_32) {
        info &= 0xffffffff;
        *symtab_index = info >> 8;
        *type = (u8) info;
    } else {
        *symtab_index = info > 32;
        *type = info & 0xffffffff;
    }
}
char *elf_read_symbol_name(
    elf_ctx *ctx, elf_header *h, elf_section_header *sh, elf_symbol *sym
) {
    elf_section_header name_section;
    if (!ctx || !sh || !sh) return NULL;
    if (!(sh->type == ELF_SECTION_TYPE_SYMTAB
            || sh->type == ELF_SECTION_TYPE_DYNSYM))
        return NULL;
    if (sh->link >= h->section_header_entries) return NULL;
    if (elf_read_section_header(&name_section, ctx,
            elf_section_header_offset(h, sh->link)) < 0)
        return NULL;
    return (char *) &ctx->buf[name_section.offset + sym->name_index];
}

i64 elf_read_rel(elf_rel *ret, elf_ctx *ctx, u64 off) {
    i64 sz = ctx->ident.file_class == ELF_CLASS_32
        ? ELF32_REL_SIZE : ELF64_REL_SIZE;
    u64 info;
    if (!ret || !ctx || ctx->len < (i64) off + sz) return -1;
    ret->offset = read_file_class_word(ctx, &off);
    info = read_file_class_word(ctx, &off);
    parse_relocation_info(&ret->symtab_index, &ret->type, ctx, info);
    return 0;
}

i64 elf_read_rela(elf_rela *ret, elf_ctx *ctx, u64 off) {
    i64 sz = ctx->ident.file_class == ELF_CLASS_32
        ? ELF32_RELA_SIZE : ELF64_RELA_SIZE;
    u64 info;
    if (!ret || !ctx || ctx->len < (i64) off + sz) return -1;
    ret->offset = read_file_class_word(ctx, &off);
    info = read_file_class_word(ctx, &off);
    parse_relocation_info(&ret->symtab_index, &ret->type, ctx, info);
    ret->addend = read_file_class_signed_word(ctx, &off);
    return 0;
}

i64 elf_read_program_header(elf_program_header *ret, elf_ctx *ctx, u64 off) {
    i64 sz = ctx->ident.file_class == ELF_CLASS_32
        ? ELF32_PROGRAM_HEADER_SIZE : ELF64_PROGRAM_HEADER_SIZE;
    if (!ret || !ctx || ctx->len < (i64) off + sz) return -1;
    if (ctx->ident.file_class == ELF_CLASS_32) {
        ret->type = read_u32(ctx, &off);
        ret->offset = read_file_class_word(ctx, &off);
        ret->virtual_addr = read_file_class_word(ctx, &off);
        ret->physical_addr = read_file_class_word(ctx, &off);
        ret->file_size = read_u32(ctx, &off);
        ret->mem_size = read_u32(ctx, &off);
        ret->flags = read_u32(ctx, &off);
        ret->align = read_u32(ctx, &off);
    } else {
        ret->type = read_u32(ctx, &off);
        ret->flags = read_u32(ctx, &off);
        ret->offset = read_file_class_word(ctx, &off);
        ret->virtual_addr = read_file_class_word(ctx, &off);
        ret->physical_addr = read_file_class_word(ctx, &off);
        ret->file_size = read_u64(ctx, &off);
        ret->mem_size = read_u64(ctx, &off);
        ret->align = read_u64(ctx, &off);
    }
    return 0;
}
i64 elf_write_program_header(elf_program_header *ph, elf_ctx *ctx, u64 off) {
    i64 sz = ctx->ident.file_class == ELF_CLASS_32
        ? ELF32_PROGRAM_HEADER_SIZE : ELF64_PROGRAM_HEADER_SIZE;
    if (!ph || !ctx || ctx->len < (i64) off + sz) return -1;
    if (ctx->ident.file_class == ELF_CLASS_32) {
        write_u32(ctx, &off, ph->type);
        write_file_class_word(ctx, &off, ph->offset);
        write_file_class_word(ctx, &off, ph->virtual_addr);
        write_file_class_word(ctx, &off, ph->physical_addr);
        write_u32(ctx, &off, (u32) ph->file_size);
        write_u32(ctx, &off, (u32) ph->mem_size);
        write_u32(ctx, &off, ph->flags);
        write_u32(ctx, &off, (u32) ph->align);
    } else {
        write_u32(ctx, &off, ph->type);
        write_u32(ctx, &off, ph->flags);
        write_file_class_word(ctx, &off, ph->offset);
        write_file_class_word(ctx, &off, ph->virtual_addr);
        write_file_class_word(ctx, &off, ph->physical_addr);
        write_u64(ctx, &off, ph->file_size);
        write_u64(ctx, &off, ph->mem_size);
        write_u64(ctx, &off, ph->align);
    }
    return 0;
}

i64 elf_write_bytes(elf_ctx *ctx, u64 *off, u8 *buf, i64 len) {
    i64 i = 0;
    if (!ctx || !buf || ctx->len < (i64) *off + len) return -1;
    for (; i < len; ++i) {
        printf("byte off: %ld\n", (i64) *off + i);
        ctx->buf[(i64) *off + i] = buf[i];
    }
    *off += (u64) len;
    return 0;
}
