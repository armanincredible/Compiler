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
static int make_asm_recurse (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);

static int take_var_ptr (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);

int operation_array_ctor (char** array);
int operation_array_dtor (char** array);

static int var_arr_ctor (Variables** var_arr);
static int var_arr_dtor (Variables** var_arr);

static int make_tree_recursion (Tree* tree_node, Onegin* line, int* ammount, const int amount_str);
static char *copy_in_buffer_from_file (int* amount_str);

static int check_stat (Asm_values* asm_st, Tree* tree_node, Variables* var_arr);


static int TakeConstTree (Tree* tree_node);
static int IsDifTree (Tree* tree_node);


#define STR_EQ_(arg1, arg2, size) ( strcmp (arg1, arg2) == 0 )

#define _LOG_                     log_make (__func__, nodes_st);

char** OPERTAIONS_ARR = (char**) calloc (VALUE_CONST_NAMES_NODE, sizeof (char*));

#define MAKE_STR_(name)                                                 \
        do                                                              \
        {                                                               \
            str = (char*) calloc (sizeof (#name), sizeof(char));        \
            CHECK_ERROR_(str, "NULL ADDRESS", NULL);                    \
            strcpy (str, #name);                                        \
                                                                        \
            OPERTAIONS_ARR[name] = str;                                 \
            str = NULL;                                                 \
        }while (0)

int operation_array_ctor (char** array)
{
    CHECK_ERROR_(array, "NULL ADDRESS", -1);

    char* str = NULL;

    MAKE_STR_(CALC_COND);

    MAKE_STR_(CALL);

    MAKE_STR_(DEFINE);

    MAKE_STR_(STATEMENT);

    MAKE_STR_(DECISION);

    MAKE_STR_(PARAMETER);

    MAKE_STR_(ARRAY);

    MAKE_STR_(DORA);

    MAKE_STR_(DURA);

    //printf ("%s", OPERTAIONS_ARR[DURA]);

    MAKE_STR_(VKRASHILAS);

    MAKE_STR_(VTURILAS);

    MAKE_STR_(VLYAPALAS);

    MAKE_STR_(POSHLU);

    MAKE_STR_(FUNCTION);

    return 0;
}

#undef MAKE_STR_

int operation_array_dtor (char** array)
{
    for (int i = 0; i < FUNCTION; i++)
    {
        memset (array[i], 0, strlen (array[i]));
        free (array[i]);
    }
    return 0;
}

int make_tree_asm (Tree* tree_node)
{
    CHECK_ERROR_(tree_node, "NUL ADDRESS", -1);

    Asm_values asm_st = {};
    asm_st.size_arr = 0;

    asm_st.asm_output_file = fopen ("../../output/asm.asm", "w");////////////////////////////////////////////////////////////////////////////////////////////////////////
    CHECK_ERROR_(asm_st.asm_output_file, "NOT OPENED", -1);
    asm_st.bin_output_file = fopen ("../../output/bin.txt", "w");
    CHECK_ERROR_(asm_st.bin_output_file, "NOT OPENED", -1);

    Variables* var_arr = {};
    var_arr_ctor (&var_arr);
    operation_array_ctor (OPERTAIONS_ARR);

    make_asm (&asm_st, tree_node, var_arr);

    operation_array_dtor (OPERTAIONS_ARR);
    var_arr_dtor (&var_arr);

    if (ferror (asm_st.asm_output_file) != 0)
    {
        printf ("ERROR WITH file_asmT\n");
        return -1;
    }
    fclose (asm_st.asm_output_file);
    if (ferror (asm_st.asm_output_file) != 0)
    {
        printf ("ERROR WITH file_asmT\n");
        return -1;
    }
    fclose (asm_st.bin_output_file);

    return 0;
}

int var_arr_ctor (Variables** var_arr)
{
    CHECK_ERROR_(var_arr, "NULL ADDRESS", -1);

    *var_arr = (Variables*) calloc (AMOUNT_VAR, sizeof (Variables));
    CHECK_ERROR_(*var_arr, "NULL ADDRESS", -1);

    memset (*var_arr, NULL, AMOUNT_VAR * sizeof (Variables));

    return 0;
}

int var_arr_dtor (Variables** var_arr)
{
    CHECK_ERROR_(var_arr, "NULL ADDRESS", -1);

    memset (*var_arr, NULL, AMOUNT_VAR * sizeof (Variables));

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
                    make_asm_recurse (asm_st, node, var_arr);       \
                }                                                   \
            }while(0)

#define _PUSH_RAX_   fprintf (file_output, "push rax\n")
#define _POP_RAX_    fprintf (file_output, "pop rax\n")
#define _OP_ARG_RAX_(op, arg)  fprintf (file_output, "%s %s, rax\n", op, arg)

#define PRINT_BASIC_OP_(str, arg)                                           \
        do{                                                                 \
            if (*ARG_NODE_ == arg)                                          \
            {                                                               \
                RECURSE_(LEFT_NODE_);                                       \
                fprintf (file_output, "push rcx\n"                          \
                                      "push rax\n");                        \
                RECURSE_(RIGHT_NODE_);                                      \
                if (*ARG_NODE_ == '*')                                      \
                {                                                           \
                    fprintf (file_output, "mov rcx, rax\n"                  \
                                          "pop rax\n"                       \
                                          "%s rcx\n"                        \
                                          "pop rcx\n", str);                \
                    return 0;                                               \
                }                                                           \
                fprintf (file_output, "mov rcx, rax\n"                      \
                                      "pop rax\n"                           \
                                      "%s rax, rcx\n"                       \
                                      "pop rcx\n", str);                    \
                                                                            \
                return 0;                                                   \
            }                                                               \
        }while(0)

#define STR_EQ_NODE_(arg) STR_EQ_(ARG_NODE_, OPERTAIONS_ARR [arg], SIZE_ARG_NODE_)

int cur_amount_var = 0;

static int make_asm (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    CHECK_ERROR_(asm_st, "NULL ADDRESS", -1);
    CHECK_ERROR_(asm_st->asm_output_file, "NULL ADDRESS", -1);
    CHECK_ERROR_(tree_node, "NULL ADDRESS", -1);
    CHECK_ERROR_(var_arr, "NULL ADDRESS", -1);

    FILE* file_output = asm_st->asm_output_file;
    
    cur_amount_var = 0;
    IsDifTree (tree_node);

    fprintf (file_output, "section .text\n"
                          "global _start\n" 
                          "_start:\n"
                          "push rbp\n"
                          "mov rbp, rsp\n"
                          "sub rsp, %d\n", SIZEOF_DATA * cur_amount_var);
    cur_amount_var = 0;

    make_asm_recurse (asm_st, tree_node, var_arr);

    fprintf (file_output, "mov rsp, rbp\n"
                          "pop rbp\n"
                          "mov rax, 1\n"
                          "xor rbx, rbx\n" 
                          "int 0x80\n");


    return 0;
}

static int IsDifTree (Tree* tree_node)
{  
    int res = 0;

    if (LEFT_NODE_ != NULL)
    {
        res += IsDifTree (LEFT_NODE_);
    }
    if (RIGHT_NODE_ != NULL)
    {
        res += IsDifTree (RIGHT_NODE_);
    }

    if (STR_EQ_NODE_(CALL))
    {
        res += 1;
    }
    if (*ARG_NODE_ == '#') 
    {
        res += 1;
        cur_amount_var++;
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

bool need_push = 1;

static int make_asm_recurse (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* file_output = asm_st->asm_output_file;
    //FILE* file_bin    = asm_st->bin_output_file;

    if (STR_EQ_NODE_(PARAMETER))
    {
        if (need_push == 1)
        {
            RECURSE_(LEFT_NODE_);

            RECURSE_(RIGHT_NODE_);

            /*int var_ptr = TAKE_VAR_(RIGHT_NODE_) * 8;
            if (var_ptr < 0)
            {
                fprintf (file_output, "mov rax, [rbp + %d]\n", -var_ptr + asm_st->delta);
            }
            else
            {
                fprintf (file_output, "mov rax, [rbp - %d]\n", var_ptr + 8);
            }*/

            fprintf (file_output, "push rax\n");
        }
        else
        {
            RECURSE_(LEFT_NODE_);
            fprintf (file_output, "pop rbx\n");
        }

        return 0;
    }

    /*if (STR_EQ_NODE_(FUNCTION))
    {
        print_val (file_output, LEFT_NODE_);

        if (need_push == 0)
        {
            fprintf (file_output, " :\n");
        }

        RECURSE_(RIGHT_NODE_);


        return 0;
    }*/

    if (STR_EQ_NODE_(DEFINE))
    {
        fprintf (file_output, "jmp skip%s\n", LEFT_NODE_->left_ptr->value.data);
        fprintf (file_output, "%s :\n", LEFT_NODE_->left_ptr->value.data);

        Tree* node = LEFT_NODE_->right_ptr;
        asm_st->am_var_func = 1;
        while (node->left_ptr != NULL)
        {
            asm_st->am_var_func ++;
            node = node->left_ptr;
        }
        
        cur_amount_var = IsDifTree (RIGHT_NODE_);
        fprintf (file_output,"push rbp\n"
                             "mov rbp, rsp\n"
                             "sub rsp, %d\n", SIZEOF_DATA * cur_amount_var);
        cur_amount_var = 0;

        asm_st->delta = 8;
        asm_st->cur_field = asm_st->cur_am_var;
        RECURSE_(RIGHT_NODE_);
        asm_st->delta = 0;

        /*fprintf (file_output, "mov rsp, rbp\n"
                              "pop rbp\n");
        fprintf (file_output, "ret\n");*/
        fprintf (file_output, "skip%s:\n", LEFT_NODE_->left_ptr->value.data);

        asm_st->am_var_func = 0;
        return 0;
    }

    if (STR_EQ_NODE_(CALL))
    {
        need_push = 1;
        RECURSE_(RIGHT_NODE_->right_ptr);
        //char* name_tree = RIGHT_NODE_->left_ptr->value.data;

        /*if (STR_EQ_ (name_tree, "print", sizeof ("print") - 1))
        {
            need_push = 1;
            RECURSE_(RIGHT_NODE_->right_ptr);
            fprintf (file_output, "OUT\n");
            need_push = 0;
            return 0;
        }

        if (STR_EQ_ (name_tree, "scan", sizeof ("scan") - 1))
        {
            fprintf (file_output, "IN\n");
            need_push = 0;
            RECURSE_(RIGHT_NODE_->right_ptr);
            need_push = 1;
            return 0;
        }

        if (STR_EQ_ (name_tree, "sqrt", sizeof ("sqrt") - 1))
        {
            need_push = 1;
            RECURSE_(RIGHT_NODE_->right_ptr);
            fprintf (file_output, "SQRT\n");
            need_push = 0;
            return 0;
        }*/

        fprintf (file_output, "call %s\n", RIGHT_NODE_->left_ptr->value.data);
        need_push = 0;
        RECURSE_(RIGHT_NODE_->right_ptr);

        return 0;
    }

    if (STR_EQ_NODE_(ARRAY))
    {
        fprintf (file_output, "xor rax, rax\n");
        RECURSE_(RIGHT_NODE_);
        fprintf (file_output, "lea rax, [rax * 8]\n");

        int var_ptr = TAKE_VAR_(LEFT_NODE_) * 8;
        fprintf (file_output, "add rax, %d\n", var_ptr + 8);
        fprintf (file_output, "mov rcx, rbp\n"
                              "sub rcx, rax\n");
        fprintf (file_output, "mov rax, [rcx]\n");

        return 0;

    }

    if (STR_EQ_NODE_(POSHLU))
    {
        RECURSE_(RIGHT_NODE_);

        fprintf (file_output, "mov rsp, rbp\n"
                              "pop rbp\n");
        fprintf (file_output, "ret\n");
        //fprintf (file_output, "ret\n");
        return 0;
    }

    if (STR_EQ_NODE_(VTURILAS))
    {
        asm_st->cur_am_if = asm_st->cur_am_if + 1;
        int cur_if = asm_st->cur_am_if;

        //check_stat (asm_st, RIGHT_NODE_, var_arr);

        RECURSE_(RIGHT_NODE_->left_ptr);
        fprintf (file_output, "mov rcx, rax\n");
        RECURSE_(RIGHT_NODE_->right_ptr);
        fprintf (file_output, "cmp rcx, rax\n");

        check_stat (asm_st, RIGHT_NODE_, var_arr); ///print !if

        if (LEFT_NODE_->left_ptr == NULL)
        {
            fprintf (file_output, "skipall%d\n", cur_if);
            RECURSE_(LEFT_NODE_->right_ptr);
        }
        else
        {
            fprintf (file_output, "else%d\n", cur_if);
            RECURSE_(LEFT_NODE_->right_ptr);
            fprintf (file_output, "jmp skipall%d\n"
                                  "else%d:\n", cur_if, cur_if);
            RECURSE_(LEFT_NODE_->left_ptr);
        }

        fprintf (file_output, "skipall%d:\n", cur_if);

        return 0;
    }

    if (STR_EQ_NODE_(VLYAPALAS))//////////////////////////////
    {
        asm_st->cur_am_if = asm_st->cur_am_if + 1;
        int am_if = asm_st->cur_am_if;

        fprintf (file_output, "while_if%d :\n", am_if);
        RECURSE_(RIGHT_NODE_->left_ptr);
        fprintf (file_output, "mov rcx, rax\n");
        RECURSE_(RIGHT_NODE_->right_ptr);
        fprintf (file_output, "cmp rcx, rax\n");

        check_stat (asm_st, RIGHT_NODE_, var_arr);
        fprintf (file_output, " skipall%d:\n", am_if);

        RECURSE_(LEFT_NODE_);

        fprintf (file_output, "jmp while_if%d\n", am_if);
        fprintf (file_output, "skipall%d:\n", am_if);
        return 0;
    }

    if ((*ARG_NODE_ == '=') && (SIZE_ARG_NODE_ == 1))
    {
        fprintf (file_output, "push rax\n"
                              "xor rax, rax\n");

        if (*ARG_LEFT_NODE_ == '#')
        {
            int var_ptr = TAKE_VAR_(LEFT_NODE_) * 8;
            RECURSE_(RIGHT_NODE_);

            if (var_ptr < 0)
            {
                fprintf (file_output, "mov [rbp + %d], rax\n", -var_ptr + asm_st->delta);
            }
            else
            {
                fprintf (file_output, "mov [rbp - %d], rax\n", var_ptr + 8);
            }
        }
        else
        {
            RECURSE_(RIGHT_NODE_);
            fprintf (file_output, "mov rdx, rax\n");

            RECURSE_(LEFT_NODE_->right_ptr);
            fprintf (file_output, "lea rax, [rax * 8]\n");
            fprintf (file_output, "mov rcx, rbp\n");

            int var_ptr = TAKE_VAR_(LEFT_NODE_->left_ptr) * 8;
            fprintf (file_output, "add rax, %d\n", var_ptr + 8);
            fprintf (file_output, "sub rcx, rax\n");

            fprintf (file_output, "mov [rcx], rdx\n");
        }

        fprintf (file_output, "pop rax\n");

        return 0;
    }

    if ((STR_EQ_NODE_(STATEMENT)) && (RIGHT_NODE_ == NULL))
    {
        return 0;
    }

    /*if (IsDifTree (tree_node) == 0)
    {
        fprintf (file_output, "mov rax, %d\n", TakeConstTree (tree_node));
        return 0;
    }*/

    PRINT_BASIC_OP_("add", '+');
    PRINT_BASIC_OP_("mul", '*');
    PRINT_BASIC_OP_("div", '/');
    PRINT_BASIC_OP_("sub", '-');
    //PRINT_BASIC_OP_("pow", '^');

    if (*ARG_NODE_ == '#')
    {
        int var_ptr = TAKE_VAR_(tree_node) * 8;
        if (var_ptr < 0)
        {
            fprintf (file_output, "mov rax, [rbp + %d]\n", -var_ptr + asm_st->delta);
        }
        else
        {
            fprintf (file_output, "mov rax, [rbp - %d]\n", var_ptr + 8);
        }
        return 0;
    }

    RECURSE_(RIGHT_NODE_);
    RECURSE_(LEFT_NODE_);
    if (STR_EQ_NODE_(STATEMENT))
    {
        return 0;
    }

    fprintf (file_output, "mov rax, %d\n", TakeConstTree (tree_node));

    return 0;
}

#define PRINT_IFS_(type)                                                \
        do                                                              \
        {                                                               \
            fprintf (output_file, "%s ", #type);                        \
        }while(0)

static int check_stat (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    FILE* output_file = asm_st->asm_output_file;
    char arg = *ARG_NODE_;

    if (SIZE_ARG_NODE_ == 2)
    {
        switch (arg)
        {
        case '!':
            PRINT_IFS_(je);
            return 0;
        case '=':
            PRINT_IFS_(jne);
            return 0;
        case '<':
            PRINT_IFS_(jal);
            return 0;
        case '>':
            PRINT_IFS_(jbl);
            return 0;
        default:
            break;
        }
    }
    else
    {
        if (arg == '>')
        {
            PRINT_IFS_(jb);
            return 0;
        }

        if (arg == '<')
        {
            PRINT_IFS_(ja);
            return 0;
        }
    }

    fprintf (asm_st->asm_output_file, "PUSH 0\n");

    RECURSE_(tree_node);
    PRINT_IFS_(JAL);

    return 0;
}

#undef PRINT_IFS_

/*
static void print_val (FILE* output_file, Tree* tree_node)
{
    for (int i = 0; i < tree_node->size_value; i++)
    {
        fprintf (output_file, "%c", *(tree_node->value.data + i));
    }
}*/

static int take_var_ptr (Asm_values* asm_st, Tree* tree_node, Variables* var_arr)
{
    for (int i = asm_st->cur_field - asm_st->am_var_func; i < asm_st->cur_am_var; i++)
    {
        if ((var_arr[i].size != 0) && (STR_EQ_(ARG_NODE_, var_arr[i].name, var_arr[i].size)))
        {
            return i - asm_st->cur_field;
        }
    }

    //printf ("%c", *ARG_NODE_);

    int am_var = asm_st->cur_am_var;

    var_arr[am_var].ptr = am_var;
    var_arr[am_var].name = ARG_NODE_;
    var_arr[am_var].size = SIZE_ARG_NODE_;

    asm_st->cur_am_var = asm_st->cur_am_var + 1 + asm_st->size_arr;
    printf ("%s\n", var_arr[am_var].name);

    return am_var - asm_st->cur_field;
}
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

    printf ("%s\n", OPERTAIONS_ARR[CALC_COND]);

    int amount_str = 0; 

    *buffer = copy_in_buffer_from_file (&amount_str);

    Onegin* line = (Onegin*) calloc (amount_str, sizeof (Onegin));
    CHECK_ERROR_(line, "NULL ADRESS (Not Enough Memory)", NULL);

    make_array_adress (*buffer, amount_str, line);

    //printf ("%s", *buffer);


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