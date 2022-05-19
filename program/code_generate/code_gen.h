#ifndef CODEGEN
#define CODEGEN

#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h> 
#include <assert.h>
#include <stdint.h>

#include "..\..\library\tree\tree.h"
#include "..\..\library\stack\stack.h"
#include "..\..\library\onegin\dora.h"


const int VALUE_CONST_NAMES_NODE = 20;

const int SIZEOF_DATA = 8;

const int MAX_SIZE_BUFFER = 0x1000000;
const int MAX_AMOUNT_LABELS = 1000;
const int MAX_LENGTH_LABEL = 20;
const int START_EXECUTE_CODE = 2 * 4096;
const int START_LIB_CODE = 4096;
const int SIZE_CODE = 0x10000; //////firstly trash value
const int SIZE_LIB = 4096;
const int VAL_AM = 128;

const int AMOUNT_VAR = 1000;


#define ELFMAG      "\177ELF"
#define AMD64       0x3e
#define SELFMAG     4
#define EI_CLASS    4       /* File class byte index */
#define ELFCLASS64  2       /* 64-bit objects */
#define EI_DATA     5       /* Data encoding byte index */
#define ELFDATA2LSB 1       /* 2's complement, little endian */
#define ET_EXEC     2       /* Executable file */
#define PT_LOAD     1       /* Loadable program segment */
#ifdef __x86_64__
#define EM_MACH     62      /* AMD x86-64 architecture */
#endif
#ifdef __aarch64__
#define EM_MACH     183     /* ARM aarch64 architecture */
#endif

typedef struct
{
    uint8_t  e_ident[16] = {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};   /* Magic number and other info */
    uint16_t e_type = ET_EXEC;        /* Object file type */
    uint16_t e_machine = AMD64;     /* Architecture */
    uint32_t e_version = 1;     /* Object file version */
    uint64_t e_entry = 0x401000;       /* Entry point virtual address */ ////////////////////////////////////////////////////////////////////
    uint64_t e_phoff = 64;       /* Program header table file offset */
    uint64_t e_shoff;       /* Section header table file offset */
    uint32_t e_flags = 0x0;       /* Processor-specific flags */
    uint16_t e_ehsize = 64;      /* ELF header size in bytes */
    uint16_t e_phentsize = 56;   /* Program header table entry size */
    uint16_t e_phnum = 1;       /* Program header table entry count */
    uint16_t e_shentsize;   /* Section header table entry size */
    uint16_t e_shnum;       /* Section header table entry count */
    uint16_t e_shstrndx;    /* Section header string table index */
} Elf64_Ehdr;

typedef struct
{
    uint32_t p_type = 1;        /* Segment type */
    uint32_t p_flags = 7;       /* Segment flags */
    uint64_t p_offset = START_LIB_CODE;      /* Segment file offset */
    uint64_t p_vaddr = 0x401000;       /* Segment virtual address */
    uint64_t p_paddr = 0;       /* Segment physical address */
    uint64_t p_filesz = SIZE_CODE;      /* Segment size in file */
    uint64_t p_memsz = SIZE_CODE;       /* Segment size in memory */
    uint64_t p_align = 0x1000;       /* Segment alignment */
} Elf64_Phdr;


enum System_regs
{
    RET_REG = 'J',
    R_COND = 'K',
    L_COND = 'L',
    V_COND = 'G',
    FREE_MEM_REG = 'F',
    SAVE_MEM_REG = 'E',
    ARG_SUM_REG = 'C'
};

enum PTR_FUNCTIONS
{
    SQRT_PTR = 7,
    PRINTF_PTR = 0x3e,
    SCANF_PTR = 0x4b4
};

enum LabelOrient
{
    LABEL_IN,
    LABEL_FROM
};

enum CONST_NAMES_NODE
{
    CALC_COND,
    DEFINE,
    CALL,
    STATEMENT,
    DECISION,
    PARAMETER,
    ARRAY,
    DORA,/////
    DURA, ///;/////
    VTURILAS,///if
    VKRASHILAS,////else
    VLYAPALAS,///while
    POSHLU,////return///////
    FUNCTION
};

enum Type_Error
{
    NO_ERROR,
    NO_PARENTHESIS,
    NO_NUMBER,
    NO_END_DOLLAR,
    NO_END_OP,
    NO_END_ARRAY_PAR
};

struct Labels
{
    char name[MAX_LENGTH_LABEL] = {0};
    unsigned int ip = 0;
};


struct Asm_values
{
    FILE* asm_output_file;
    FILE* bin_output_file;
    FILE* lib_input_file;
    
    Labels* labels = 0;
    int am_labels = 0;
    unsigned char* buffer = 0;
    char* middle_buffer = 0;
    unsigned int ip = 0;
    unsigned int ip_end_code = 0;

    bool need_push = 1;
    int cur_amount_var = 0;
    
    int cur_am_var;///cur amount variables
    int cur_field; /// num what means a ptr of new var of function
    int cur_am_if;
    int cur_am_wh;
    int size_arr;
    int delta = 0;      /// after pushes ptr of var in stack need to add with var like delta
    int am_var_func = 0; ////// need to know a num of var in fuction just to make scope of var
    int cur_func = 0;  //////cur function (need to skip after ret)
};

struct Variables
{
    char* name;
    int size;
    int ptr;
};

struct node_st
{
    Tree** array;
    int size;
    int capacity;
    int cur_node;
};

int tree_nodes_ctr(node_st* nodes_st);

int tree_nodes_dtor(node_st* nodes_st);

int make_nodes_arr (node_st* nodes_st, char* str);

Tree* get_general (node_st* nodes_st);

int make_from_tree_asm_bin (Tree* tree_node);

int make_code (Tree* tree_node);

Onegin* make_tree_from_library (Tree* tree_node, char** buffer);

#endif