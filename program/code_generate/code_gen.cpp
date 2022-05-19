#include "code_gen.h"

#define CHECK_ERROR_(name, type_error, ret)                                             \
        do{                                                                             \
            if ((name) == NULL)                                                         \
            {                                                                           \
                printf ("\nERROR in function : %s \n"                                   \
                        "%s have %s on line %d\n", __func__,                            \
                        #name, type_error, __LINE__);                                   \
                return ret;                                                             \
            }                                                                           \
        } while (0)

#define $ printf("\t\t\t---ON LINE %d IN FUNCTION %s---\n", __LINE__, __func__);


static int make_asm (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);
static int make_asm_bin_recurse (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);

static int take_var_ptr (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);

int operation_array_ctor (char** array);
int operation_array_dtor (char** array);

static int var_arr_ctor (Variables** var_arr);
static int var_arr_dtor (Variables** var_arr);

static int make_tree_recursion (Tree* tree_node, Onegin* line, int* ammount, const int amount_str);
static char *copy_in_buffer_from_file (int* amount_str);

static int check_stat (Asm_values* asm_st, Tree* tree_node);

static int TakeConstTree (Tree* tree_node);
static int IsDifTree (Tree* tree_node, Asm_values* asm_st);

static int MakeLabel (Asm_values* asm_st, int dest);

static int AsmStrDtr (Asm_values* asm_st);
static int AsmStrCtr (Asm_values* asm_st);

static int MakeBeginBuffer (Asm_values* asm_st);
static int PrintIntoVarArr (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);

#define STR_EQ_(arg1, arg2, size) ( strcmp (arg1, arg2) == 0 )

#define _LOG_                     log_make (__func__, nodes_st);

static int AsmStrCtr (Asm_values* asm_st)
{
    asm_st->labels = (Labels*) calloc (MAX_AMOUNT_LABELS, sizeof (Labels));
    CHECK_ERROR_(asm_st->labels, "ZERO PTR CALLOC", -1);
    asm_st->buffer = (unsigned char*) calloc (MAX_SIZE_BUFFER, sizeof (unsigned char));
    CHECK_ERROR_(asm_st->buffer, "ZERO PTR CALLOC", -1);
    asm_st->middle_buffer = (char*) calloc (MAX_LENGTH_LABEL, sizeof (char));
    CHECK_ERROR_(asm_st->middle_buffer, "ZERO PTR CALLOC", -1);
    asm_st->asm_output_file = fopen ("../../output/asm.asm", "w");
    CHECK_ERROR_(asm_st->asm_output_file, "NOT OPENED", -1);
    asm_st->bin_output_file = fopen ("../../output/bin", "wb");
    CHECK_ERROR_(asm_st->bin_output_file, "NOT OPENED", -1);
    asm_st->lib_input_file = fopen ("../../input/lib", "rb");
    CHECK_ERROR_(asm_st->bin_output_file, "NOT OPENED", -1);
    return 0;
}

static int AsmStrDtr (Asm_values* asm_st)
{
    free (asm_st->buffer);
    free (asm_st->labels);
    free (asm_st->middle_buffer);

    if (ferror (asm_st->asm_output_file) != 0)
    {
        printf ("ERROR WITH file_asmT\n");
        return -1;
    }
    fclose (asm_st->asm_output_file);
    if (ferror (asm_st->asm_output_file) != 0)
    {
        printf ("ERROR WITH file_asmT\n");
        return -1;
    }
    fclose (asm_st->bin_output_file);
    if (ferror (asm_st->lib_input_file) != 0)
    {
        printf ("ERROR WITH file_asmT\n");
        return -1;
    }
    fclose (asm_st->lib_input_file);

    return 0;
}

static int MakeBeginBuffer (Asm_values* asm_st)
{
    unsigned char* buffer = asm_st->buffer;
    Elf64_Ehdr elf_header = {};
    Elf64_Phdr seg_header = {};

    *((Elf64_Ehdr*) buffer) = elf_header;
    seg_header.p_filesz = asm_st->ip + 2 * SIZE_LIB ;
    seg_header.p_memsz  = asm_st->ip + 2 * SIZE_LIB ;
    int seg_ip = 64;
    *((Elf64_Phdr*) (buffer + seg_ip)) = seg_header;

    return 0;
}

static int MakeEndBuffer (Asm_values* asm_st)
{
    fseek (asm_st->lib_input_file, START_LIB_CODE, SEEK_SET);
    fread (asm_st->buffer + START_LIB_CODE, sizeof (unsigned char), SIZE_LIB, asm_st->lib_input_file);
    return 0;
}

int make_from_tree_asm_bin (Tree* tree_node)
{
    CHECK_ERROR_(tree_node, "NUL ADDRESS", -1);

    Asm_values asm_st = {};
    asm_st.size_arr = 0;

    AsmStrCtr (&asm_st);

    Variables* var_arr = {};
    var_arr_ctor (&var_arr);

    make_asm (&asm_st, tree_node, var_arr);
    var_arr_dtor (&var_arr);


    MakeBeginBuffer (&asm_st);
    MakeEndBuffer (&asm_st);
    fwrite (asm_st.buffer, sizeof (unsigned char), MAX_SIZE_BUFFER, asm_st.bin_output_file);

    AsmStrDtr (&asm_st);

    return 0;
}

int var_arr_ctor (Variables** var_arr)
{
    CHECK_ERROR_(var_arr, "NULL ADDRESS", -1);

    *var_arr = (Variables*) calloc (AMOUNT_VAR, sizeof (Variables));
    CHECK_ERROR_(*var_arr, "NULL ADDRESS", -1);

    memset (*var_arr, 0, AMOUNT_VAR * sizeof (Variables));

    return 0;
}

int var_arr_dtor (Variables** var_arr)
{
    CHECK_ERROR_(var_arr, "NULL ADDRESS", -1);

    memset (*var_arr, 0, AMOUNT_VAR * sizeof (Variables));

    free (*var_arr);

    return 0;
}


#define ARG_NODE_           (tree_node->value.data)
#define ARG_LEFT_NODE_      (tree_node->left_ptr->value.data)
#define ARG_RIGHT_NODE_     (tree_node->right_ptr->value.data)

#define SIZE_ARG_NODE_      (tree_node->size_value)
#define SIZE_ARG_LEFT_NODE  (tree_node->left_ptr->size_value)
#define SIZE_ARG_RIGHT_NODE (tree_node->right_ptr->size_value)

#define LEFT_NODE_  (tree_node->left_ptr)
#define RIGHT_NODE_ (tree_node->right_ptr)

#define TAKE_VAR_(node) take_var_ptr (asm_st, node, var_arr)

#define RECURSE_(node)                                              \
            do{                                                     \
                if (node != NULL)                                   \
                {                                                   \
                    make_asm_bin_recurse (asm_st, node, var_arr);   \
                }                                                   \
            }while(0)

#define STR_EQ_NODE_(arg) STR_EQ_(ARG_NODE_, #arg, SIZE_ARG_NODE_)

#define _WRITE_VAL_ONE_(num)\
                    asm_st->buffer [asm_st->ip] = num;\
                    asm_st->ip = asm_st->ip + 1;


#define _WRITE_VAL_THR_(num1, num2, num3)\
                    _WRITE_VAL_ONE_(num1)\
                    _WRITE_VAL_ONE_(num2)\
                    _WRITE_VAL_ONE_(num3)
                    
#define _PUSH_RAX_\
                    fprintf (file_output, "push rax\n");\
                   _WRITE_VAL_ONE_(0x50)

#define _PUSH_RPB_ \
                    fprintf (file_output, "push rbp\n");\
                   _WRITE_VAL_ONE_(0x55)
#define _POP_RBP_ \
                    fprintf (file_output, "pop rbp\n");\
                   _WRITE_VAL_ONE_(0x5d) 

#define _POP_RBX_\
                    fprintf (file_output, "pop rbx\n");\
                   _WRITE_VAL_ONE_(0x5b) 

#define _POP_RAX_\
                    fprintf (file_output, "pop rax\n");\
                   _WRITE_VAL_ONE_(0x58)

#define _POP_RCX_\
                    fprintf (file_output, "pop rcx\n");\
                   _WRITE_VAL_ONE_(0x59)

#define _PUSH_RCX_\
                    fprintf (file_output, "push rcx\n");\
                   _WRITE_VAL_ONE_(0x51)

#define _MOV_MEMRCX_RDX_\
                    fprintf (file_output, "mov [rcx], rdx\n");\
                    _WRITE_VAL_THR_(0x48, 0x89, 0x11)

#define _MOV_RAX_MEMRCX_\
                    fprintf (file_output, "mov rax, [rcx]\n");\
                    _WRITE_VAL_THR_(0x48, 0x8b, 0x01)

#define _MOV_MEMRBPPLUS_RAX_(arg)\
                    fprintf (file_output, "mov [rbp + %d], rax\n", arg);\
                    _WRITE_VAL_THR_(0x48, 0x89, 0x45)\
                    _WRITE_VAL_ONE_(arg)

#define _MOV_MEMRBPMINUS_RAX_(arg)\
                    fprintf (file_output, "mov [rbp - %d], rax\n", arg);\
                    _WRITE_VAL_THR_(0x48, 0x89, 0x45)\
                    _WRITE_VAL_ONE_(256 - arg)

#define _MOV_RAX_MEMRBPMINUS_(arg)\
                    fprintf (file_output, "mov rax, [rbp - %d]\n", arg);\
                    _WRITE_VAL_THR_(0x48, 0x8b, 0x45)\
                    _WRITE_VAL_ONE_(256 - arg)

#define _MOV_RAX_MEMRBPPLUS_(arg)\
                    fprintf (file_output, "mov rax, [rbp + %d]\n", arg);\
                    _WRITE_VAL_THR_(0x48, 0x8b, 0x45)\
                    _WRITE_VAL_ONE_(arg)

#define _MOV_RBP_RSP_ \
                    fprintf (file_output, "mov rbp, rsp\n");\
                    _WRITE_VAL_THR_(0x48, 0x89, 0xe5)

#define _MOV_RAX_ARG_(arg) \
                    fprintf (file_output, "mov rax, %d\n", arg);\
                    _WRITE_VAL_THR_(0x48, 0xc7, 0xc0)\
                    *((unsigned int*)(asm_st->buffer + asm_st->ip)) = arg;  \
                    asm_st->ip = asm_st->ip + 4;

#define _MOV_RCX_RAX_ \
                    fprintf (file_output, "mov rcx, rax\n");\
                    _WRITE_VAL_THR_(0x48, 0x89, 0xc1)

#define _MOV_RCX_RBP_ \
                    fprintf (file_output, "mov rcx, rbp\n");\
                    _WRITE_VAL_THR_(0x48, 0x89, 0xe9)

#define _MOV_RSP_RBP_ \
                    fprintf (file_output, "mov rsp, rbp\n");\
                    _WRITE_VAL_THR_(0x48, 0x89, 0xec)

#define _XOR_RBX_RBX_\
                    fprintf (file_output, "xor rbx, rbx\n");\
                    _WRITE_VAL_THR_(0x48, 0x31, 0xdb)

#define _XOR_RAX_RAX_\
                    fprintf (file_output, "xor rax, rax\n");\
                    _WRITE_VAL_THR_(0x48, 0x31, 0xc0)

#define _XOR_RDX_RDX_\
                    fprintf (file_output, "xor rdx, rdx\n");\
                    _WRITE_VAL_THR_(0x48, 0x31, 0xd2)

#define _MOV_RDX_RAX_ \
                    fprintf (file_output, "mov rdx, rax\n");\
                    _WRITE_VAL_THR_(0x48, 0x89, 0xc2)

#define _INT_0x80_ \
                    fprintf (file_output, "int 0x80\n");\
                   _WRITE_VAL_ONE_(0xcd)\
                   _WRITE_VAL_ONE_(0x80)

#define _ADD_RAX_ARG_(num)\
                    fprintf (file_output, "add rax, %d\n", num);\
                    _WRITE_VAL_THR_(0x48, 0x83, 0xc0)\
                    _WRITE_VAL_ONE_(num)

#define _ADD_RAX_ARG_(num)\
                    fprintf (file_output, "add rax, %d\n", num);\
                    _WRITE_VAL_THR_(0x48, 0x83, 0xc0)\
                    _WRITE_VAL_ONE_(num)

#define _ADD_RAX_RCX_\
                    fprintf (file_output, "add rax, rcx\n");\
                    _WRITE_VAL_THR_(0x48, 0x01, 0xc8)

#define _SUB_RAX_RCX_\
                    fprintf (file_output, "sub rax, rcx\n");\
                    _WRITE_VAL_THR_(0x48, 0x29, 0xc8)

#define _SUB_RSP_ARG_(num) \
                    fprintf (file_output, "sub rsp, %d\n", num);            \
                    _WRITE_VAL_THR_(0x48, 0x81, 0xec)                       \
                    *((unsigned int*)(asm_st->buffer + asm_st->ip)) = num;  \
                    asm_st->ip = asm_st->ip + 4;

#define _SUB_RCX_RAX_\
                    fprintf (file_output, "sub rcx, rax\n");\
                    _WRITE_VAL_THR_(0x48, 0x29, 0xc1)

#define _MUL_RCX_\
                    fprintf (file_output, "mul rcx\n");\
                    _WRITE_VAL_THR_(0x48, 0xf7, 0xe9)

#define _DIV_RCX_\
                    fprintf (file_output, "idiv rcx\n");\
                    _WRITE_VAL_THR_(0x48, 0xf7, 0xf9)

#define _LEA_RAX_RAX_8_\
                    fprintf (file_output, "lea rax, [rax * 8]\n");\
                    _WRITE_VAL_THR_(0x48, 0x8d, 0x04)\
                    _WRITE_VAL_ONE_(0xc5)\
                    asm_st->ip = asm_st->ip + 3;


#define _CMP_RCX_RAX_\
                    fprintf (file_output, "cmp rcx, rax\n");\
                    _WRITE_VAL_THR_(0x48, 0x39, 0xc1)

#define _CALL_\
                    fprintf (file_output, "call ");\
                    _WRITE_VAL_ONE_(0xe8)
                    
#define _RET_\
                    fprintf (file_output, "ret\n");\
                    _WRITE_VAL_ONE_(0xc3)
#define _JMP_\
                    fprintf (file_output, "jmp ");\
                     _WRITE_VAL_ONE_(0xe9)


#define PRINT_BASIC_OP_(str, arg)                                           \
        do{                                                                 \
            if (*ARG_NODE_ == arg)                                          \
            {                                                               \
                RECURSE_(LEFT_NODE_);                                       \
                _PUSH_RCX_                                                  \
                _PUSH_RAX_                                                  \
                RECURSE_(RIGHT_NODE_);                                      \
                _MOV_RCX_RAX_                                               \
                _POP_RAX_                                                   \
                if (*ARG_NODE_ == '*')                                      \
                {                                                           \
                    _MUL_RCX_                                               \
                }                                                           \
                if (*ARG_NODE_ == '/')                                      \
                {                                                           \
                    _XOR_RDX_RDX_                                           \
                    _DIV_RCX_                                               \
                }                                                           \
                if (*ARG_NODE_ == '+')                                      \
                {                                                           \
                    _ADD_RAX_RCX_                                           \
                }                                                           \
                if (*ARG_NODE_ == '-')                                      \
                {                                                           \
                    _SUB_RAX_RCX_                                           \
                }                                                           \
                _POP_RCX_                                                   \
                return 0;                                                   \
            }                                                               \
        }while(0)

static int make_asm (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    CHECK_ERROR_(asm_st, "NULL ADDRESS", -1);
    CHECK_ERROR_(asm_st->asm_output_file, "NULL ADDRESS", -1);
    CHECK_ERROR_(tree_node, "NULL ADDRESS", -1);
    CHECK_ERROR_(var_arr, "NULL ADDRESS", -1);

    FILE* file_output = asm_st->asm_output_file;
    
    asm_st->cur_amount_var = 0;
    IsDifTree (tree_node, asm_st);
    int save_am_var = asm_st->cur_amount_var;

    asm_st->ip = START_EXECUTE_CODE;

    _PUSH_RPB_
    _MOV_RBP_RSP_
    _SUB_RSP_ARG_(save_am_var * SIZEOF_DATA)
    asm_st->cur_amount_var  = 0;
    make_asm_bin_recurse (asm_st, tree_node, var_arr);
    _MOV_RSP_RBP_
    _POP_RBP_
    _MOV_RAX_ARG_(1)
    _XOR_RBX_RBX_
    _INT_0x80_

    memset (var_arr, 0, asm_st->cur_am_var * sizeof (Variables));
    asm_st->cur_am_var = 0;
    asm_st->cur_field = 0;
    asm_st->am_var_func = 0;
    asm_st->cur_am_wh = 0;
    asm_st->cur_am_if = 0;
    asm_st->cur_func = 0;
    asm_st->ip_end_code = asm_st->ip;
    asm_st->ip = START_EXECUTE_CODE;

    //printf ("\n\n\n\n");
    
    fseek (file_output, 0, SEEK_SET);
    fprintf (file_output, "section .text\n");
    fprintf (file_output, "global _start\n" );
    fprintf (file_output, "_start:\n");

    _PUSH_RPB_
    _MOV_RBP_RSP_
    _SUB_RSP_ARG_(save_am_var * SIZEOF_DATA)
    make_asm_bin_recurse (asm_st, tree_node, var_arr);
    _MOV_RSP_RBP_
    _POP_RBP_
    _MOV_RAX_ARG_(1)
    _XOR_RBX_RBX_
    _INT_0x80_

    return 0;
}

static int IsDifTree (Tree* tree_node, Asm_values* asm_st)
{  
    int res = 0;

    if (LEFT_NODE_ != NULL)
    {
        res += IsDifTree (LEFT_NODE_, asm_st);
    }
    if (RIGHT_NODE_ != NULL)
    {
        res += IsDifTree (RIGHT_NODE_, asm_st);
    }

    if (STR_EQ_NODE_(CALL))
    {
        res += 1;
    }
    if (*ARG_NODE_ == '#') 
    {
        res += 1;
        asm_st->cur_amount_var ++;
    }

    return res;
}
static int TakeConstTree (Tree* tree_node)
{
    int res1 = 0;
    int res2 = 0;
    int res = 0;

    if (LEFT_NODE_ != NULL)
    {
        res1 = TakeConstTree (LEFT_NODE_);
        res = res1;
    }

    if (RIGHT_NODE_ != NULL)
    {
        res2 = TakeConstTree (RIGHT_NODE_);
        res = res2;
    }

    char op = *ARG_NODE_;

    switch (op)
    {
        case '*':
            res = res1 * res2;
            break;
        case '+':
            res = res1 + res2;
            break;
        case '-':
            res = res1 - res2;
            break;
        case '/':
            res = res1 / res2;
            break;
        case '^':
            res = pow (res1, res2);
            break;
        default:
            break;
    }

    if (isdigit (op))
    {
        res = atoi (ARG_NODE_);
    }
    
    return res;
}

#define _MAKE_LABEL_(str, arg, des)                     \
        do                                              \
        {                                               \
            fprintf (file_output, str, arg);            \
            if (des == LABEL_IN)                        \
            {                                           \
                fprintf (file_output, ":");             \
            }                                           \
            fprintf (file_output, "\n");                \
            sprintf (asm_st->middle_buffer, str, arg);  \
            MakeLabel (asm_st, des);                    \
        } while (0)
        

static int PrintIntoVarArr (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    if (tree_node->left_ptr != NULL)
    {
        PrintIntoVarArr (asm_st, tree_node->left_ptr, var_arr);
    }
    TAKE_VAR_(tree_node->right_ptr);
    return 0;
}

static int ParsParameter (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);
static int ParsDefine    (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);
static int ParsCall      (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);
static int ParsArray     (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);
static int ParsPoshlu    (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);
static int ParsVturilas  (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);
static int ParsVlyapalas (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);
static int ParsEqual     (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);
static int ParsVar       (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);

static int ParsParameter (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;

    if (asm_st->need_push == 1)
    {
        RECURSE_(LEFT_NODE_);
        RECURSE_(RIGHT_NODE_);

        _PUSH_RAX_
    }
    else
    {
        RECURSE_(LEFT_NODE_);
        _POP_RBX_
    }

    return 0;
}
static int ParsDefine (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;

    _JMP_
    _MAKE_LABEL_("skip%s", LEFT_NODE_->left_ptr->value.data, LABEL_FROM);

    _MAKE_LABEL_("%s", LEFT_NODE_->left_ptr->value.data, LABEL_IN);

    Tree* node = LEFT_NODE_->right_ptr;
    asm_st->am_var_func = 1;

    while (node->left_ptr != NULL)
    {
        asm_st->am_var_func ++;
        node = node->left_ptr;
    }
    int save_field = asm_st->cur_field;
    asm_st->cur_field = asm_st->cur_am_var + asm_st->am_var_func;

    node = LEFT_NODE_->right_ptr;

    PrintIntoVarArr (asm_st, node, var_arr);
    
    asm_st->cur_amount_var  = IsDifTree (RIGHT_NODE_, asm_st);
    _PUSH_RPB_
    _MOV_RBP_RSP_
    _SUB_RSP_ARG_(SIZEOF_DATA * asm_st->cur_amount_var );
    asm_st->cur_amount_var  = 0;

    asm_st->delta = 8;

    RECURSE_(RIGHT_NODE_);
    
    asm_st->delta = 0;
    memset (var_arr + asm_st->cur_field - asm_st->am_var_func, 0, sizeof (Variables) * asm_st->am_var_func);
    asm_st->cur_field = save_field;

    _MAKE_LABEL_("skip%s", LEFT_NODE_->left_ptr->value.data, LABEL_IN);

    asm_st->am_var_func = 0;

    return 0;
}
static int ParsCall (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;

    asm_st->need_push = 1;
    _PUSH_RPB_
    RECURSE_(RIGHT_NODE_->right_ptr);

    _CALL_

    unsigned int ptr_from = asm_st->ip + 4;
    unsigned int delta = START_LIB_CODE - ptr_from;

    if (STR_EQ_(RIGHT_NODE_->left_ptr->value.data, "printf", sizeof ("printf")))
    {
        *((unsigned int*)(asm_st->buffer + asm_st->ip)) = PRINTF_PTR + delta;
        asm_st->ip = ptr_from;
    }
    else if (STR_EQ_(RIGHT_NODE_->left_ptr->value.data, "scanf", sizeof ("scanf")))
    {
        *((unsigned int*)(asm_st->buffer + asm_st->ip)) = SCANF_PTR + delta;
        asm_st->ip = ptr_from;
    }
    else if (STR_EQ_(RIGHT_NODE_->left_ptr->value.data, "sqrt", sizeof ("sqrt")))
    {
        *((unsigned int*)(asm_st->buffer + asm_st->ip)) = SQRT_PTR + delta;
        asm_st->ip = ptr_from;
    }
    else
    {
        _MAKE_LABEL_("%s", RIGHT_NODE_->left_ptr->value.data, LABEL_FROM);
    }
    
    
    asm_st->need_push = 0;
    RECURSE_(RIGHT_NODE_->right_ptr);
    _POP_RBP_

    return 0;
}
static int ParsArray (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;
    _XOR_RAX_RAX_

    RECURSE_(RIGHT_NODE_);
    _LEA_RAX_RAX_8_

    int var_ptr = TAKE_VAR_(LEFT_NODE_) * 8 + 8;

    _ADD_RAX_ARG_(var_ptr)
    _MOV_RCX_RBP_
    _SUB_RCX_RAX_
    _MOV_RAX_MEMRCX_

    return 0;
}
static int ParsPoshlu (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;
    RECURSE_(RIGHT_NODE_);

    _MOV_RSP_RBP_
    _POP_RBP_
    _RET_

    return 0;
}
static int ParsVturilas (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;
    
    asm_st->cur_am_if = asm_st->cur_am_if + 1;
    int cur_if = asm_st->cur_am_if;

    RECURSE_(RIGHT_NODE_->left_ptr);
    _MOV_RCX_RAX_

    RECURSE_(RIGHT_NODE_->right_ptr);
    _CMP_RCX_RAX_


    check_stat (asm_st, RIGHT_NODE_); ///print !if

    if (LEFT_NODE_->left_ptr == NULL)
    {
        _MAKE_LABEL_("skipall%d", cur_if, LABEL_FROM);

        RECURSE_(LEFT_NODE_->right_ptr);
    }
    else
    {
        _MAKE_LABEL_("else%d", cur_if, LABEL_FROM);

        RECURSE_(LEFT_NODE_->right_ptr);

        _JMP_
        _MAKE_LABEL_("skipall%d", cur_if, LABEL_FROM);
        _MAKE_LABEL_("else%d", cur_if, LABEL_IN);
        RECURSE_(LEFT_NODE_->left_ptr);
    }

    _MAKE_LABEL_("skipall%d", cur_if, LABEL_IN);

    return 0;
}
static int ParsVlyapalas (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;

    asm_st->cur_am_if = asm_st->cur_am_if + 1;
    int am_if = asm_st->cur_am_if;

    _MAKE_LABEL_("while_if%d", am_if, LABEL_IN);
    RECURSE_(RIGHT_NODE_->left_ptr);

    _MOV_RCX_RAX_
    RECURSE_(RIGHT_NODE_->right_ptr);

    _CMP_RCX_RAX_

    check_stat (asm_st, RIGHT_NODE_);
    _MAKE_LABEL_("skipall%d", am_if, LABEL_FROM);

    RECURSE_(LEFT_NODE_);
    

    _JMP_
    _MAKE_LABEL_("while_if%d", am_if, LABEL_FROM);

    _MAKE_LABEL_("skipall%d", am_if, LABEL_IN);

    return 0;
}
static int ParsEqual (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;

    _PUSH_RAX_
    _XOR_RAX_RAX_

    if (*ARG_LEFT_NODE_ == '#')
    {
        int var_ptr = TAKE_VAR_(LEFT_NODE_) * 8;
        RECURSE_(RIGHT_NODE_);

        if (var_ptr < 0)
        {
            var_ptr = -var_ptr + asm_st->delta;
            _MOV_MEMRBPPLUS_RAX_(var_ptr);
        }
        else
        {
            var_ptr = var_ptr + 8;
            _MOV_MEMRBPMINUS_RAX_(var_ptr);
        }
    }
    else
    {
        RECURSE_(RIGHT_NODE_);
        _MOV_RDX_RAX_

        RECURSE_(LEFT_NODE_->right_ptr);
        _LEA_RAX_RAX_8_
        _MOV_RCX_RBP_

        int var_ptr = TAKE_VAR_(LEFT_NODE_->left_ptr) * 8;
        _ADD_RAX_ARG_(var_ptr + 8)
        _SUB_RCX_RAX_

        _MOV_MEMRCX_RDX_
    }

    _POP_RAX_

    return 0;
}
static int ParsVar (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;

    int var_ptr = TAKE_VAR_(tree_node) * 8;
    if (var_ptr < 0)
    {
        var_ptr = -var_ptr + asm_st->delta;
        _MOV_RAX_MEMRBPPLUS_(var_ptr);
    }
    else
    {
        var_ptr = var_ptr + 8;
        _MOV_RAX_MEMRBPMINUS_(var_ptr);
    }
    return 0;
}
static int make_asm_bin_recurse (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;

    if (STR_EQ_NODE_(PARAMETER))
    {
        ParsParameter(asm_st, tree_node, var_arr);
        return 0;
    }

    if (STR_EQ_NODE_(DEFINE))
    {
        ParsDefine (asm_st, tree_node, var_arr);
        return 0;
    }

    if (STR_EQ_NODE_(CALL))
    {
        ParsCall (asm_st, tree_node, var_arr);
        return 0;
    }

    if (STR_EQ_NODE_(ARRAY))
    {
        ParsArray (asm_st, tree_node, var_arr);
        return 0;
    }

    if (STR_EQ_NODE_(POSHLU))
    {
        ParsPoshlu (asm_st, tree_node, var_arr);
        return 0;
    }

    if (STR_EQ_NODE_(VTURILAS))
    {
        ParsVturilas (asm_st, tree_node, var_arr);
        return 0;
    }

    if (STR_EQ_NODE_(VLYAPALAS))
    {
        ParsVlyapalas (asm_st, tree_node, var_arr);
        return 0;
    }

    if ((*ARG_NODE_ == '=') && (SIZE_ARG_NODE_ == 1))
    {
        ParsEqual (asm_st, tree_node, var_arr);
        return 0;
    }

    if ((STR_EQ_NODE_(STATEMENT)) && (RIGHT_NODE_ == NULL))
    {
        return 0;
    }

    PRINT_BASIC_OP_("add", '+');
    PRINT_BASIC_OP_("mul", '*');
    PRINT_BASIC_OP_("div", '/');
    PRINT_BASIC_OP_("sub", '-');

    if (*ARG_NODE_ == '#')
    {
        ParsVar (asm_st, tree_node, var_arr);
        return 0;
    }

    RECURSE_(RIGHT_NODE_);
    RECURSE_(LEFT_NODE_);
    if (STR_EQ_NODE_(STATEMENT))
    {
        return 0;
    }

    int num = TakeConstTree (tree_node);
    _MOV_RAX_ARG_(num)

    return 0;
}

static int MakeLabel (Asm_values* asm_st, int dest)
{
    int found = 0;
    for (int i = 0; i < asm_st->am_labels; i++)
    {
        if (strcmp (asm_st->labels[i].name, asm_st->middle_buffer) == 0)
        {
            if (dest == LABEL_IN)
            {
                asm_st->labels[i].ip = asm_st->ip;
            }
            else
            {
                unsigned int ptr_from = asm_st->ip + 4;
                *((unsigned int*)(asm_st->buffer + asm_st->ip)) = asm_st->labels[i].ip - ptr_from;
            }
            found = 1;
        }
    }
    if (found == 0)
    {
        if (dest == LABEL_IN)
        {
            asm_st->labels[asm_st->am_labels].ip = asm_st->ip;
        }

        strcpy (asm_st->labels[asm_st->am_labels].name, asm_st->middle_buffer);
        asm_st->am_labels ++;
    }

    if (dest != LABEL_IN)
    {
        asm_st->ip = asm_st->ip + 4;
    }
    memset (asm_st->middle_buffer, 0, MAX_LENGTH_LABEL * sizeof (char));

    return 0;
}

#define _JE_                                                 \
        fprintf (output_file, "je ");                        \
        _WRITE_VAL_ONE_(0x0f)                                \
        _WRITE_VAL_ONE_(0x84)

#define _JNE_                                                 \
        fprintf (output_file, "jne ");                        \
        _WRITE_VAL_ONE_(0x0f)                                 \
        _WRITE_VAL_ONE_(0x85)

#define _JGE_                                                 \
        fprintf (output_file, "jge ");                        \
        _WRITE_VAL_ONE_(0x0f)                                 \
        _WRITE_VAL_ONE_(0x8d)

#define _JLE_                                                 \
        fprintf (output_file, "jle ");                        \
        _WRITE_VAL_ONE_(0x0f)                                 \
        _WRITE_VAL_ONE_(0x8e)

#define _JL_                                                 \
        fprintf (output_file, "jl ");                        \
        _WRITE_VAL_ONE_(0x0f)                                \
        _WRITE_VAL_ONE_(0x8c)

#define _JG_                                                 \
        fprintf (output_file, "jg ");                        \
        _WRITE_VAL_ONE_(0x0f)                                \
        _WRITE_VAL_ONE_(0x8f)
        

static int check_stat (Asm_values* asm_st, Tree* tree_node)
{
    FILE* output_file = asm_st->asm_output_file;
    char arg = *ARG_NODE_;

    if (SIZE_ARG_NODE_ == 2)
    {
        switch (arg)
        {
        case '!':
            _JE_
            return 0;
        case '=':
            _JNE_
            return 0;
        case '<':
            _JGE_
            return 0;
        case '>':
            _JLE_
            return 0;
        default:
            break;
        }
    }
    else
    {
        if (arg == '>')
        {
            _JL_
            return 0;
        }

        if (arg == '<')
        {
            _JG_
            return 0;
        }
    }

    return 0;
}

#undef PRINT_IFS_
#undef _JE_
#undef _JNE_
#undef _JGE_
#undef _JLE_
#undef _JL_
#undef _JG_


static int take_var_ptr (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    for (int i = asm_st->cur_field - asm_st->am_var_func; i < asm_st->cur_am_var; i++)
    {
        if ((var_arr[i].size != 0) && (STR_EQ_(ARG_NODE_, var_arr[i].name, var_arr[i].size)))
        {
            return i - asm_st->cur_field;
        }
    }

    int am_var = asm_st->cur_am_var;

    var_arr[am_var].ptr = am_var;
    var_arr[am_var].name = ARG_NODE_;
    var_arr[am_var].size = SIZE_ARG_NODE_;

    asm_st->cur_am_var = asm_st->cur_am_var + 1 + asm_st->size_arr;
    //printf ("%s\n", var_arr[am_var].name);

    return am_var - asm_st->cur_field;
}

#undef _MAKE_LABEL_
#undef _WRITE_VAL_ONE_
#undef _WRITE_VAL_THR_   
#undef _PUSH_RAX_
#undef _PUSH_RPB_ 
#undef _POP_RBP_ 
#undef _POP_RBX_
#undef _POP_RAX_
#undef _POP_RCX_
#undef _PUSH_RCX_
#undef _MOV_MEMRCX_RDX_
#undef _MOV_RAX_MEMRCX_
#undef _MOV_MEMRBPPLUS_RAX_
#undef _MOV_MEMRBPMINUS_RAX_
#undef _MOV_RAX_MEMRBPMINUS_
#undef _MOV_RAX_MEMRBPPLUS_
#undef _MOV_RBP_RSP_
#undef _MOV_RAX_ARG_
#undef _MOV_RCX_RAX_
#undef _MOV_RCX_RBP_
#undef _MOV_RSP_RBP_
#undef _XOR_RBX_RBX_
#undef _XOR_RAX_RAX_
#undef _XOR_RDX_RDX_
#undef _MOV_RDX_RAX_
#undef _INT_0x80_
#undef _ADD_RAX_ARG_
#undef _ADD_RAX_ARG_
#undef _ADD_RAX_RCX_
#undef _SUB_RAX_RCX_
#undef _SUB_RSP_ARG_
#undef _SUB_RCX_RAX_
#undef _MUL_RCX_
#undef _DIV_RCX_
#undef _LEA_RAX_RAX_8_
#undef _CMP_RCX_RAX_
#undef _CALL_   
#undef _RET_
#undef _JMP_
#undef STR_EQ_NODE_
#undef PRINT_
#undef RECURSE_
#undef PRINT_BASIC_OP_
#undef ARG_NODE_
#undef ARG_LEFT_NODE_
#undef ARG_RIGHT_NODE_
#undef SIZE_ARG_NODE_
#undef SIZE_ARG_LEFT_NODE
#undef SIZE_ARG_RIGHT_NODE
#undef LEFT_NODE_
#undef RIGHT_NODE_
#undef TAKE_VAR_

#undef symb

Onegin* make_tree_from_library (Tree* tree_node, char** buffer)
{
    CHECK_ERROR_(tree_node, "NULL ADRESS", NULL);

    int amount_str = 0; 

    *buffer = copy_in_buffer_from_file (&amount_str);

    Onegin* line = (Onegin*) calloc (amount_str, sizeof (Onegin));
    CHECK_ERROR_(line, "NULL ADRESS (Not Enough Memory)", NULL);

    make_array_adress (*buffer, amount_str, line);

    tree_push (tree_node, IN, line[1].adress);
    tree_node->size_value = line[1].length;
    int ammount = 2;
    
    make_tree_recursion (tree_node, line, &ammount, amount_str);
    
    return line;
}

#define _pars_tree_def_(arg, side)                                              \
        do{                                                                     \
            if ((*(line[*ammount].adress) == '{') &&                            \
                (*(line[1 + *ammount].adress) != '}'))                          \
            {                                                                   \
                tree_push (tree_node, side, line[*ammount + 1].adress);         \
                tree_node->arg->size_value = line[*ammount + 1].length;         \
                *ammount = *ammount + 2;                                        \
                make_tree_recursion (tree_node->arg, line, ammount, amount_str);\
            }                                                                   \
            else                                                                \
            {                                                                   \
                *ammount = *ammount + 2;                                        \
            }                                                                   \
        }while(0)

static int make_tree_recursion (Tree* tree_node, Onegin* line, int* ammount, const int amount_str)
{   
    while (*ammount < amount_str)
    {
        if (*(line[*ammount].adress) == '}')
        {
            *ammount = *ammount + 1;
            return 0;
        }

        _pars_tree_def_(left_ptr, LEFT);

        _pars_tree_def_(right_ptr, RIGHT);


    }
    return 0;
}
#undef _pars_tree_def_

static char *copy_in_buffer_from_file (int* amount_str)
{
    CHECK_ERROR_(amount_str, "NULL_ADRESS", NULL);

    char* buffer = NULL; 
   
    FILE* input_file = fopen ("../../output/tree_dump_text.txt", "r");
    CHECK_ERROR_(input_file, "NOT OPENED", NULL);

    buffer = remove_trash_and_copy_in_buffer (amount_str, input_file);

    if (ferror(input_file))
    {
        printf ("ERROR in function : %s \n"
                "reading file falled\n", __func__);
        return NULL;
    }
    fclose (input_file);

    return buffer;
}


#undef CHECK_ERROR_