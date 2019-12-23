#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#define _Noreturn __declspec(noreturn)
#endif

typedef struct { size_t fo; } fo_t;
typedef struct { uintptr_t va; } va_t;
typedef struct { uint32_t rva; } rva_t;

struct list_node {
    struct list_node *next;
};

struct list {
    struct list_node *head;
    struct list_node *tail;
};

struct cursor {
    fo_t fpos;
    rva_t vpos;
};

struct pe {
    uint8_t *file;
    size_t file_size;
    uintptr_t base;
};

struct iat_list {
    struct list modules;
    size_t module_count;
    struct cursor term_pos;
};

struct iat_module {
    struct list_node node;
    struct list entries;
    char *name;
    size_t name_len;
    struct cursor desc_pos;
    struct cursor name_pos;
};

struct iat_entry {
    struct list_node node;
    rva_t site;
    char *name;
    size_t name_len;
    struct cursor oft_pos;
    struct cursor hint_pos;
    struct cursor name_pos;
};

static _Noreturn void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    exit(EXIT_FAILURE);
}

static void *xmalloc(size_t nbytes)
{
    void *mem;

    mem = malloc(nbytes);

    if (mem == NULL) {
        abort();
    }

    return mem;
}

static void *xcalloc(size_t nbytes)
{
    void *mem;

    mem = calloc(nbytes, 1);

    if (mem == NULL) {
        abort();
    }

    return mem;
}

static void *xrealloc(void *src, size_t nbytes)
{
    void *dest;

    dest = realloc(src, nbytes);

    if (dest == NULL) {
        abort();
    }

    return dest;
}

static char *xstrdup(const char *src)
{
    char *dest;
    size_t len;

    assert(src != NULL);

    len = strlen(src) + 1;
    dest = xmalloc(len);
    memcpy(dest, src, len);

    return dest;
}

static void file_load(
        const char *filename,
        void **bytes_out,
        size_t *nbytes_out)
{
    assert(filename != NULL);
    assert(bytes_out != NULL);
    assert(nbytes_out != NULL);

    size_t nbytes;
    size_t nread;
    void *bytes;
    FILE *f;

    f = fopen(filename, "rb");

    if (f == NULL) {
        die("%s: %s\n", filename, strerror(errno));
    }

    fseek(f, 0, SEEK_END);
    nbytes = ftell(f);
    fseek(f, 0, SEEK_SET);

    bytes = xmalloc(nbytes);
    nread = fread(bytes, 1, nbytes, f);

    if (nread != nbytes) {
        die("%s: Read error\n", filename);
    }

    fclose(f);

    *bytes_out = bytes;
    *nbytes_out = nbytes;
}

static void file_save(const char *filename, void *bytes, size_t nbytes)
{
    size_t nwrit;
    FILE *f;

    assert(filename != NULL);
    assert(bytes != NULL);

    f = fopen(filename, "wb");

    if (f == NULL) {
        die("%s: %s\n", filename, strerror(errno));
    }

    nwrit = fwrite(bytes, 1, nbytes, f);

    if (nwrit != nbytes) {
        die("%s: Write error\n", filename);
    }

    fclose(f);
}

static void list_init(struct list *list)
{
    assert(list != NULL);
    memset(list, 0, sizeof(*list));
}

static void list_append(struct list *list, struct list_node *node)
{
    assert(list != NULL);
    assert(node != NULL);

    node->next = NULL;

    if (list->head != NULL) {
        list->tail->next = node;
        list->tail = node;
    } else {
        list->head = node;
        list->tail = node;
    }
}

static void *mem_offset(void *ptr, size_t off)
{
    uint8_t *base;

    assert(ptr != NULL);

    base = ptr;

    return base + off;
}

static void cursor_advance(struct cursor *cursor, size_t delta)
{
    assert(cursor != NULL);

    cursor->fpos.fo += delta;
    cursor->vpos.rva += delta;
}

static void cursor_align(struct cursor *cursor, size_t alignment)
{
    size_t fdiff;
    size_t vdiff;

    assert(cursor != NULL);

    fdiff = cursor->fpos.fo % alignment;
    vdiff = cursor->vpos.rva % alignment;

    //assert(fdiff == vdiff);

    if (vdiff != 0) {
        cursor_advance(cursor, alignment - vdiff);
    }
}

static IMAGE_NT_HEADERS *pe_get_nt_header(void *file)
{
    IMAGE_DOS_HEADER *dh;
    IMAGE_NT_HEADERS *nth;

    assert(file != NULL);

    dh = (IMAGE_DOS_HEADER *) file;
    nth = mem_offset(file, dh->e_lfanew);

    return nth;
}

static size_t pe_get_section_count(void *bytes)
{
    IMAGE_NT_HEADERS *nth;

    nth = pe_get_nt_header(bytes);

    return nth->FileHeader.NumberOfSections;
}

static IMAGE_SECTION_HEADER *pe_get_section_headers(void *bytes)
{
    IMAGE_NT_HEADERS *nth;

    nth = pe_get_nt_header(bytes);

    return mem_offset(
            nth->OptionalHeader.DataDirectory,
            nth->OptionalHeader.NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY));
}

/* Takes ownership of bytes! Well, or would, if we ever freed anything. */
static void pe_init(struct pe *pe, void *bytes, size_t nbytes)
{
    IMAGE_NT_HEADERS *nth;

    assert(pe != NULL);
    assert(bytes != NULL);

    nth = pe_get_nt_header(bytes);

    pe->file = bytes;
    pe->file_size = nbytes;
    pe->base = nth->OptionalHeader.ImageBase;
}

static rva_t pe_rva_from_va(struct pe *pe, va_t va)
{
    int64_t tmp;
    rva_t result;

    assert(pe != NULL);

    tmp = (int64_t) va.va - (int64_t) pe->base;

    if (tmp > INT32_MAX) {
        die(    "Excessive distance between base %p and VA %p. Check both "
                "inputs were derived from the same process.\n",
                pe->base,
                va.va);
    }

    result.rva = tmp;

    return result;
}

static fo_t pe_fo_from_rva(struct pe *pe, rva_t rva)
{
    IMAGE_SECTION_HEADER *sections;
    IMAGE_SECTION_HEADER *pos;
    fo_t result;
    size_t section_pos;
    size_t nsections;
    size_t i;

    assert(pe != NULL);

    sections = pe_get_section_headers(pe->file);
    nsections = pe_get_section_count(pe->file);

    for (i = 0 ; i < nsections ; i++) {
        pos = &sections[i];

        if (    rva.rva >= pos->VirtualAddress &&
                rva.rva <  pos->VirtualAddress + pos->Misc.VirtualSize) {
            section_pos = rva.rva - pos->VirtualAddress;

            if (section_pos >= pos->SizeOfRawData) {
                die(    "%p: Section %8s offset %p > backing store size %p\n",
                        rva.rva,
                        pos->Name,
                        section_pos,
                        pos->SizeOfRawData);
            }

            result.fo = pos->PointerToRawData + section_pos;

            return result;
        }
    }

    die("%p: RVA is not located inside a section\n", rva);
}

static void pe_get_limit(struct pe *pe, struct cursor *limit)
{
    IMAGE_SECTION_HEADER *sections;
    IMAGE_SECTION_HEADER *pos;
    size_t nsections;
    size_t i;

    assert(pe != NULL);
    assert(limit != NULL);

    sections = pe_get_section_headers(pe->file);
    nsections = pe_get_section_count(pe->file);

    limit->fpos.fo = 0;
    limit->vpos.rva = 0;

    for (i = 0 ; i < nsections ; i++) {
        pos = &sections[i];

        if (limit->fpos.fo < pos->PointerToRawData + pos->SizeOfRawData) {
            limit->fpos.fo = pos->PointerToRawData + pos->SizeOfRawData;
        }

        if (limit->vpos.rva < pos->VirtualAddress + pos->Misc.VirtualSize) {
            limit->vpos.rva = pos->VirtualAddress + pos->Misc.VirtualSize;
        }
    }
}

static void pe_add_section(struct pe *pe, const IMAGE_SECTION_HEADER *hdr)
{
    IMAGE_NT_HEADERS *nth;
    IMAGE_SECTION_HEADER *sections;
    uint32_t vlimit;
    size_t nsections;
    size_t i;
    fo_t limit;
    fo_t pos;

    assert(pe != NULL);
    assert(hdr != NULL);

    pos.fo = hdr->PointerToRawData;
    limit.fo = pos.fo + hdr->SizeOfRawData;

    if (pe->file_size < limit.fo) {
        pe->file = xrealloc(pe->file, limit.fo);
        memset(&pe->file[pe->file_size], 0, limit.fo - pe->file_size);
        pe->file_size = limit.fo;
    }

    nth = pe_get_nt_header(pe->file);
    sections = pe_get_section_headers(pe->file);
    nsections = nth->FileHeader.NumberOfSections;

    memcpy(&sections[nsections], hdr, sizeof(*hdr));
    nth->FileHeader.NumberOfSections++;

    for (i = 0 ; i < nth->FileHeader.NumberOfSections ; i++) {
        vlimit = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;

        if (nth->OptionalHeader.SizeOfImage < vlimit) {
            nth->OptionalHeader.SizeOfImage = vlimit;
        }
    }
}

static void pe_write(struct pe *pe, fo_t fo, const void *bytes, size_t nbytes)
{
    size_t end;

    assert(pe != NULL);
    assert(pe->file != NULL);
    assert(bytes != NULL);

    if (fo.fo >= pe->file_size) {
        die("PE write begins out of bounds: %p >= %p\n", fo.fo, pe->file_size);
    }

    end = fo.fo + nbytes;

    if (end >= pe->file_size) {
        die("PE write ends out of bounds: %p >= %p\n", end, pe->file_size);
    }

    memcpy(pe->file + fo.fo, bytes, nbytes);
}

static void pe_write_dd(struct pe *pe, size_t entry_no, rva_t rva, size_t len)
{
    IMAGE_NT_HEADERS *nth;
    IMAGE_DATA_DIRECTORY *dd;

    assert(pe != NULL);

    nth = pe_get_nt_header(pe->file);
    dd = &nth->OptionalHeader.DataDirectory[entry_no];
    dd->VirtualAddress = rva.rva;
    dd->Size = len;
}

static struct iat_module *iat_list_get_module(
        struct iat_list *list,
        const char *name)
{
    struct iat_module *module;
    struct iat_module *newmod;

    assert(list != NULL);
    assert(name != NULL);

    if (list->modules.tail != NULL) {
        module = CONTAINING_RECORD(list->modules.tail, struct iat_module, node);

        if (_stricmp(module->name, name) == 0) {
            return module;
        }
    }

    newmod = xcalloc(sizeof(*newmod));
    list_init(&newmod->entries);
    newmod->name = xstrdup(name);
    list_append(&list->modules, &newmod->node);

    return newmod;
}

static void iat_list_load(
        struct iat_list *list,
        const char *filename,
        struct pe *pe)
{
    /* Allocate some rather large stack buffers. C++ name mangling and STL can
       get quite excessive. Ideally we'd load_file() and then punch NULs
       between the tokens but I really don't feel like writing a full
       tokenizer FSM for this right now. */

    va_t va;
    uintptr_t dummy;
    char line[1024];
    char dll_name[1024];
    char symbol_name[1024];
    struct iat_module *module;
    struct iat_entry *entry;
    int line_no;
    int result;
    FILE *f;

    assert(list != NULL);
    assert(filename != NULL);
    assert(pe != NULL);

    list_init(&list->modules);
    list->module_count = 0;

    f = fopen(filename, "r");

    if (f == NULL) {
        die("%s: %s\n", filename, strerror(errno));
    }

    line_no = 0;

    while (fgets(line, _countof(line), f)) {
        line_no++;
        result = sscanf(
                line,
                "%p %p %s %s",
                (void **) &va.va,
                (void **) &dummy,
                dll_name,
                symbol_name);

        if (result != 4) {
            die(    "%s:%i: Invalid input (matched %i/4 cols)\n",
                    filename,
                    line_no,
                    result);
        }

        module = iat_list_get_module(list, dll_name);

        entry = xcalloc(sizeof(*entry));
        entry->site = pe_rva_from_va(pe, va);
        entry->name = xstrdup(symbol_name);

        list_append(&module->entries, &entry->node);
    }

    fclose(f);
}

static void iat_module_allocate(
        struct iat_module *module,
        struct cursor *cursor)
{
    struct iat_entry *entry;
    struct list_node *pos;

    assert(module != NULL);
    assert(cursor != NULL);

    /* Pass 1: Allocate OFT */

    cursor_align(cursor, sizeof(uintptr_t));

    for (pos = module->entries.head ; pos != NULL ; pos = pos->next) {
        entry = CONTAINING_RECORD(pos, struct iat_entry, node);
        entry->oft_pos = *cursor;
        cursor_advance(cursor, sizeof(uintptr_t));
    }

    /* (terminating entry) */

    cursor_advance(cursor, sizeof(uintptr_t));

    /* Pass 2: Allocate IMAGE_IMPORT_BY_NAME records */

    for (pos = module->entries.head ; pos != NULL ; pos = pos->next) {
        cursor_align(cursor, 2);

        entry = CONTAINING_RECORD(pos, struct iat_entry, node);
        entry->name_len = strlen(entry->name) + 1;
        entry->hint_pos = *cursor;

        cursor_advance(cursor, sizeof(WORD));

        entry->name_pos = *cursor;

        cursor_advance(cursor, entry->name_len);
    }
}

static void iat_list_allocate(struct iat_list *list, struct cursor *cursor)
{
    struct iat_module *module;
    struct list_node *pos;

    assert(list != NULL);
    assert(cursor != NULL);

    /* Pass 1: Allocate IMAGE_IMPORT_DESCRIPTOR array */

    for (pos = list->modules.head ; pos != NULL ; pos = pos->next) {
        list->module_count++;

        module = CONTAINING_RECORD(pos, struct iat_module, node);
        module->desc_pos = *cursor;

        cursor_advance(cursor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    /* (terminating entry) */

    list->module_count++;
    list->term_pos = *cursor;
    cursor_advance(cursor, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    /* Pass 2: Allocate names */

    for (pos = list->modules.head ; pos != NULL ; pos = pos->next) {
        module = CONTAINING_RECORD(pos, struct iat_module, node);
        module->name_pos = *cursor;
        module->name_len = strlen(module->name) + 1;
        cursor_advance(cursor, module->name_len);
    }

    /* Pass 3: Allocate entries */

    for (pos = list->modules.head ; pos != NULL ; pos = pos->next) {
        module = CONTAINING_RECORD(pos, struct iat_module, node);
        iat_module_allocate(module, cursor);
    }
}

static void iat_module_write(struct iat_module *module, struct pe *pe)
{
    struct iat_entry *entry;
    struct list_node *pos;
    uintptr_t entry_val;
    uint16_t hint;
    fo_t site_fo;

    assert(module != NULL);
    assert(pe != NULL);

    hint = 0;

    for (pos = module->entries.head ; pos != NULL ; pos = pos->next) {
        entry = CONTAINING_RECORD(pos, struct iat_entry, node);

        /* IAT entries hold either an IMAGE_IMPORT_BY_NAME RVA for symbols
           imported by name or an ordinal for symbols imported by ordinal
           (in which case the high bit of the entry is set). Because IAT
           entries get overwritten by actual VAs (pointers) to their resolved
           symbols they need to be machine word-sized, not 32 bit RVA sized.

           The first write repairs an IAT entry (which is located within an
           existing section). The writes after that write to our newly-created
           section holding reconstructed import metadata (which the IAT entry
           will refer to). */

        entry_val = entry->hint_pos.vpos.rva;

        site_fo = pe_fo_from_rva(pe, entry->site);
        pe_write(pe, site_fo, &entry_val, sizeof(entry_val));
        pe_write(pe, entry->oft_pos.fpos, &entry_val, sizeof(entry_val));
        pe_write(pe, entry->hint_pos.fpos, &hint, sizeof(hint));
        pe_write(pe, entry->name_pos.fpos, entry->name, entry->name_len);
    }
}

static void iat_list_write(struct iat_list *list, struct pe *pe)
{
    IMAGE_IMPORT_DESCRIPTOR iid;
    struct iat_module *module;
    struct iat_entry *first_entry;
    struct list_node *pos;

    assert(list != NULL);
    assert(pe != NULL);

    for (pos = list->modules.head ; pos != NULL ; pos = pos->next) {
        module = CONTAINING_RECORD(pos, struct iat_module, node);

        assert(module->entries.head != NULL);

        first_entry = CONTAINING_RECORD(
                module->entries.head,
                struct iat_entry,
                node);

        memset(&iid, 0, sizeof(iid));
        iid.Characteristics = first_entry->oft_pos.vpos.rva;
        iid.Name = module->name_pos.vpos.rva;
        iid.FirstThunk = first_entry->site.rva;

        pe_write(pe, module->desc_pos.fpos, &iid, sizeof(iid));
        pe_write(pe, module->name_pos.fpos, module->name, module->name_len);
        iat_module_write(module, pe);
    }

    /* Write zeroed-out terminating descriptor */

    memset(&iid, 0, sizeof(iid));
    pe_write(pe, list->term_pos.fpos, &iid, sizeof(iid));
}

static void iat_list_perform_repairs(struct iat_list *list, struct pe *pe)
{
    IMAGE_SECTION_HEADER sec;
    struct cursor begin;
    struct cursor end;
    struct cursor pos;

    assert(list != NULL);
    assert(pe != NULL);

    pe_get_limit(pe, &begin);

    cursor_align(&begin, 0x1000);
    pos = begin;
    iat_list_allocate(list, &pos);
    cursor_align(&pos, 0x1000);
    end = pos;

    memset(&sec, 0, sizeof(sec));
    strcpy_s((char *) sec.Name, _countof(sec.Name) - 1, ".idata");
    sec.Misc.VirtualSize = end.vpos.rva - begin.vpos.rva;
    sec.VirtualAddress = begin.vpos.rva;
    sec.SizeOfRawData = end.fpos.fo - begin.fpos.fo;
    sec.PointerToRawData = begin.fpos.fo;
    sec.Characteristics =
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ |
            IMAGE_SCN_MEM_WRITE ;

    pe_add_section(pe, &sec);
    iat_list_write(list, pe);

    /* This step doesn't really fit well anywhere in particular... */

    pe_write_dd(
            pe,
            IMAGE_DIRECTORY_ENTRY_IMPORT,
            begin.vpos,
            list->module_count * sizeof(IMAGE_IMPORT_DESCRIPTOR));
}

int main(int argc, char **argv)
{
    struct pe pe;
    struct iat_list list;
    void *bytes;
    size_t nbytes;

    if (argc != 4) {
        die("Usage: %s [src exe] [iat listing] [dest exe]\n", argv[0]);
    }

    file_load(argv[1], &bytes, &nbytes);
    pe_init(&pe, bytes, nbytes);
    iat_list_load(&list, argv[2], &pe);
    iat_list_perform_repairs(&list, &pe);
    file_save(argv[3], pe.file, pe.file_size);

    return EXIT_SUCCESS;
}
