// program space usage:

// 0x0000-001f MMIO (0 : TC pins, 2-3: console)
// 0x0020-7fff while assembling, used freely as temporary storage
// 0x0020-???? assembled program is loaded here
// 0x????- up  sbrk will allocate breaks in here
//  down -7fff program stack will be placed here (%sp init. to 7ffc)

// 0x8000-bfff program
// 0xc000-c01f static data
// 0xc020- up  symbol table
//  down -fffe stack (beginning at fffe)

// assembled programs are loaded starting 0x0030
// symbols are restricted to 16 characters

// The assembled program is invoked by initializing a stack for it, then
// 'jmp'ing to the address of the label '_start'.
//
// when the assembled program is invoked, it will be given a pointer
// to SYSTEM in %a0. Calling SYSTEM with various arguments enables simple
// 'syscalls':
//   0, status: exit the program
//   1, number: print unsigned integer to console
//   2, number: print signed integer to the console
//   3, strptr: print nul-terminated string to console
//   4, size:   sbrk (returns pointer to old break)

// The assembler is _mostly_ hapy to assemble `mov` with large immediates.
// It won't work with immediates larger than 16 bits (sign extended), even
// though it supports 32-bit operations. The reason for this is that such
// large-immediate movs should generally be used with the immediate being a
// label; which are always pointer-valued and hence can take up to 16 bits.
// It will always assume such moves need 4 instructions, including when the
// immediate is a symbol which turns out to have a small value.
//
// I have no intention of fixing this. It can be worked around by writing out
// the mov-slo-slo-slo manually. Generally, this is a good idea if the immediate
// is small anyway, because you may not need all 4 instructions. Or if you need
// a 32-bit immediate, you may need more than 4 instructions, in which case the
// assembler couldn't have helped you anyway.
//
// This version also does not support `mov [r/i],r` or `mov r,[r/i]` syntax.
// I do plan to fix this. In the meantime, use the instructions `ld` and `st`
// respectively instead.
//
// `mfcr`/`mtcr` syntax is not supported. Use `mov` with a cr instead.
// Known CRs: %cpuid, %exten, %feat.
//
// Opcodes are case sensitive and must be lowercase. I'm open to fixing this
// if users want, but I can't imagine there will be users. :P

// Each assembly line contains 5 fields, each of which is optional:
//   |LABEL:    OPCODE   OP1, OP2   ; COMMENT
//
// If a label is present, it must begin at the start of the line and be followed
// immediately by the colon. It must start with an alphabetic character or '_'.
// If a label is not present, the opcode MUST be
// indented by at least one of either a space or a horizontal tab.
// Other than this, whitespace is only used to separate the opcode and OP1 tokens.
// Other whitespace is permitted and ignored.
//
// Size markers can only be used as opcode suffixes. If one is not used, the size
// is assumed to be a word - 2 bytes. Jumps and other control transfer instructions,
// including those indirected by a pointer, may use a size marker, but it will be
// completely ignored. For example, `jumph %r0` will take the lower 16 bits of r0
// as the indirect address, not the lower 8 bits.
//
// If the opcode only has one argument, then the comma and OP2 must be omitted.
// If the opcode has no arguments (eg 'ret') then OP1, the comma,
// and OP2 must be omitted.
//
// The ';' marks a line comment, and can be omitted if there is no comment.
//
// Register names _must_ begin with a '%'. Combined with the opcode indentation
// restriction and labels beginning with alphabetic characters, this makes it
// possible to determine the class of each token by its position and first
// character alone.


/**************************************
 *****    BEGIN IMPLEMENTATION    *****
 **************************************/

// When assembling this file, I don't want to use the "standard" calling
// convention. Here's the convention I will be using:
/*
    r0:  return0, arg0
    r1:  return1, arg1
    r2:           arg2
    r3:           arg3        # extra arg registers double as unsaved temps
    r4:  saved0               # during lexing, 'cur' is allocated here
    r5:  &static_data or saved1 if static_data isn't needed
    r6:  sp
    r7:  ln
*/

#ifdef COMPILE
// MUST compile with -DCOMPILE -fno-builtin !!
#include <stdlib.h>
#include <stdio.h> // getchar, puts
#include <stdint.h>

#define printf(...) fprintf(stderr, __VA_ARGS__)
#endif

// void* == int16_t
typedef signed char byte;
typedef unsigned char ubyte;
typedef ubyte bool;
#define true  1
#define false 0

#ifdef COMPILE
char *bottom_memory;
#else
void *bottom_memory = 32;
#endif

typedef struct reloc {
  void *intermediate_inst;
  void *ste;
  int16_t lineno;
} reloc_t;

// The 'kernel' uses %bp to point at this, so things here
// can be accessed with fewer instructions.
// Perhaps we want 'cur' allocated here?
typedef struct static_data_t {
  union {
    int16_t assembly_ip; // marks end of program after assembly. Is saved and restored
                         // around pass 2.
    int16_t program_heap_break;   // for sbrk while executing prog
  } top;
  void *intermediate_code_ip;   // intermediate is 1 word per instr
                                // except long moves are 3
                                // Moves during both pass 1 and pass 2.
                                // In asm, this pointer and assembly_ip
                                // are equal, and this one is not needed.
                                // When compiling, this is
                                // a host pointer, so is more annoying.
  reloc_t *relocation_table_top;
  reloc_t *relocation_table_bot;  // relocation table which grows down
                                // each pointer is a pointer to an
                                // intermediate instruction which needs
                                // a symbol relocation and the corresponding
                                // symbol table entry.
  int16_t src_lineno;
  void *symbol_table_root;
  void *symbol_table_end;
  char save_cur;
} static_data_t;
static static_data_t *static_data; // allocated as per description
static char *global_buffer;        // allocated to 0x20


// in the asm, this function can be an additional entry point to shr4 which
// sets the mask to 32 instead of 16.
uint32_t shr5(uint32_t x, uint8_t width) {
#ifdef COMPILE
  return x >> 5;
#else
  // copy of shr
#endif
}

// due to where this function is used, it should be implemented so that
// all non-argument registers keep their old values on exit, except for r0.
uint32_t shr4(uint32_t x, uint8_t width) {
#ifdef COMPILE
  return x >> 4;
#else
  uint32_t mask = 16;
  uint32_t r = 0;
  uint32_t b = 1; // which bit of r to set if x & mask
  
  for ( ; width > 0; --width) {
    if ( x & mask ) {
      r |= b;
    }
    mask = mask + mask;
    b = b + b;
  }
  return r;
#endif
}

bool strncmp(const char *a, const char *b, int16_t n) {
  char ac = 0, bc = 0;
  while ( n > 0 ) {
    ac = *a;
    bc = *b;
    if (ac == 0 || ac != bc) return ac - bc;
    
    ++a; ++b; --n;
  }
  return ac - bc;
}

typedef char* symbol;

// layout (in words):
/* { SYMBOL    : 0
 * , SYMBOL    : 2
 * , SYMBOL    : 4
 * , SYMBOL    : 6
 * , SYMBOL    : 8
 * , SYMBOL    : 10
 * , SYMBOL    : 12
 * , SYMBOL    : 14
 * , PAYLOAD   : 16
 * , PAYLOAD   : 18
 * }
 */
typedef struct table_entry_t {
  char symbol[16];
  int32_t payload;
} table_entry_t;

typedef table_entry_t* table_entry;

table_entry add_table_entry(symbol name, int32_t payload) {
  char *ptr = static_data->symbol_table_end;

  for (int i = 4; i > 0; --i) {
    *(int32_t *)ptr = *(int32_t*)name;
    ptr += 4;
    name += 4;
  }
  *(int32_t *)ptr = payload;
  ptr += 4;
  static_data->symbol_table_end = ptr;
  return (table_entry)(ptr-20);
}

table_entry find_table_entry(symbol name) {
  symbol ste = static_data->symbol_table_root;
  symbol top = static_data->symbol_table_end;

  while ( ste < top ) {
    // strncmp returns 0 if strings are equal
    if ( !strncmp(ste, name, 16) ) {
      return (table_entry) ste;
    }
    ste += 20;
  }

  return add_table_entry(name, 0);
}

void ste_attach_payload(symbol name, int32_t payload) {
  table_entry entry = find_table_entry(name);
  entry->payload = payload;
}

int32_t ste_get_payload(table_entry entry) {
  return entry->payload;
}

// The intermediate representation of instructions.
//
// Typical instructions look like this (LE):
// { opcode , operand }
// in their fully assembled form. But control transfers and long moves
// need a bit of a longer repreesentation.
//
// Control transfers to a label look like this if they need relocation.
// { opcode , -1 }
//
// Note that the target ETCa does not have opcodes larger than 0xbf (191/-65).
// Such values can be reserved for assembler meta features (none of which exist
// currently) like .half/.word/.dword when they need label operands.
//
// Long moves look like this, if the operand is a label:
// { -1`8 , 5`0 reg`3 , 0`48 }
//
// If we know the immediate, we assemble the whole instruction packet
// immediately. If we don't, we do it on the second pass.
// As a consequence of this, intermediate instructions use the same
// amount of space as their assembled counterparts. This lets us smoothly
// cross-compile between my native 64-bit machine and the target ETCa machine!
//
// There is a relocation table which stores pairs of pointers. The first pointer
// is to an instruction which needs a relocation. The second is to the
// relevant entry in the symbol table. 
//
// Note: this representation is variable-width. Intermediate control transfers
// are represented with more bytes than they will end up using.
typedef struct intermediate_instr_t {
    ubyte opcode_byte;
    ubyte operand_byte;
    union {
        struct {
            int16_t reserved0;
            int16_t reserved1;
            int16_t reserved2;
        } long_move;              // Long moves; {opcode_byte,operand_byte} = -1.
                                  // if symtab_entry == NULL, known value is in
                                  // large_immediate.
        // int0_t nothing; // Other instructions are assembled in the first pass.
    } instr_tail;
} intermediate_instr_t;

// The temporary representation of an opcode used during parsing.
// Each opcode is mapped to a number;
// in all cases the lower 4 bits are the 4-bit section of the function control.
// For computations, that's their ETCa "opcode" bits. For conditional transfers,
// it is their condition code bits. Specifically:

typedef uint8_t opcode;

/* Opcode mapping:

0  add     8  movz    16 z/e   24 be 
1  sub     9  mov(s)  17 nz/ne 25 a  
2  rsub    10 ld      18 n     26 l  
3  cmp     11 st      19 nn    27 ge 
4  or      12 slo/pop 20 c/b   28 le 
5  xor     13 push    21 nc/ae 29 g  
6  and     14 mfcr    22 o     30 ---
7  test    15 mtcr    23 no    31 ---

31 is 'never,' and we don't use it. 30 is for 'always'.
14 is used to encode 'hlt', and 15 is used to encode 'nop.'
'retcc' is encoded with values from 16-30.

Note that values 0-15 and values 16-31 have matching bottom 4 bits.
The bottom 4 bits always represent these values; which one is meant will
be known by which assembler function is called. Which assembler function
is called will be known by which state of the state machine we are in
when we decide to accept the parse.

Values 0-15 are also used for the conditional jumps. 16-31 are conditional calls;
we cannot distinguish the unconditional register-indirect txs from the
unconditional txs yet. This will have to be handled in the state machine.
The state machine also gives us the contextual distinction between how to
interpret values.

This pattern for conditional jumps/calls conveniently exactly matches the bottom
5 bits of the conditional formats from the stack+functions extension. Sometimes,
I have good ideas :)

/*****************************************************************************
 ***************** BEGIN ASSEMBLER IMPLEMENTATION ****************************
 *****************************************************************************/

// This should be allocated to a consistent register (presumably arg3) through
// all lexing procedures.
#ifdef COMPILE
static char cur;
#else
global register char cur;
#endif

/*******************
 ** forward decls **
 *******************/

// consume a single character exactly matching the given one.
// A return value of 'true' indicates a mistmatch.
// Like always, the "head" of the stream is presumed to be in 'cur'.
bool match(char);
// consume characters exactly matching the (NUL-terminated) input string
// returning false if the input string was matched perfectly and true otherwise.
bool consume(const char *);

int32_t read_immediate();

symbol read_name();

bool is_alpha(char);
bool is_num(char);
// allows both numbers and '-'
bool is_imm_start(char);
bool is_eol(char);

bool validate_u5(uint32_t);
bool validate_s5(int32_t);
bool validate_i16(int32_t);

/* Register name readers, returning a number according to the following
 * mapping:
 *   0:  r0,a0
 *   1:  r1,a1
 *   2:  r2,v0
 *   3:  r3,s0
 *   4:  r4,s1
 *   5:  r5,bp
 *   6:  r6,sp
 *   7:  r7,ln
 *   8:  cpuid
 *   9:  exten
 *   10: feat
 */
// read a general-purpose register
ubyte read_register();
// read any register
ubyte read_any_register();
ubyte read_ctrl_register();

typedef struct {
  int8_t opcode;
  int8_t state;
} read_opcode_t;

read_opcode_t read_opcode();
uint8_t read_size();

void skip_whitespace();
void syscall(int, void*);
void kill_assembler();


/******************************
 ********* first pass *********
 ******************************/


/* The state machine

Since we can always determine a token class by its first character and context,
we don't actually need an advanced lexer. This state machine controls the
parser, which is formally an attributed DFA.

Each state transitions on the first character read in that state (this is
cur, which is retrieved from 'getchar' at the end of lexing the _previous_
token). The transition indicates what class of token should be lexed. A failure
to scan a valid token of that class causes a parse error.

At the start of every iteration except the first,
whitespace is scanned automatically.

When we accept, the state is used to index a jump table containing the asm
function to tail-call.

classes:
  space: scan with 'skip_whitespace'.
  eol:   end-of-line; single character so no scanner.
  label: a 'name' followed _immediately_ by a colon.
  name:  a 'name'
  opcode: an 'opcode', optionally followed by a size suffix.
  u5:    an 'immediate' constrained to values 0-31
  s5:    an 'immediate' constrained to -16 - 15
  i16:   an 'immediate' between -32768 - 65535
  reg:   a 'register' with value < 8
  creg:  a 'register' with value >= 8

notation:
  R/L : register or label
  R/I : register or immediate
  ANY : register, immediate, or label

  STATE        |    FIRST    ||  CLASS  | ACTION
  -------------|-------------||---------|-------------------------------
  0  init      |  is_alpha   ||  label  | attach ip to label in symtab, goto 1
               |  otherwise  ||    -    | skip, goto 1
  -------------|-------------||---------|-------------------------------
               |  '\n','\0'  ||   eol   | skip, accept
  1  opcode    |  is_alpha   || opcode  | record, goto state returned by opcode scanner
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
               |     '%'     ||   reg   | record, goto 12
  2  1 r/u5 op |   is_num    ||   u5    | record, goto 13                 # this state is used for 'push'
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
               |     '%'     ||   reg   | record, goto 14
  3  1 R/L op  |  is_alpha   ||   name  | record, goto 15                 # this state is used for jump and call
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
               |     '%'     ||   reg   | record, goto 12
  4  1 reg op  |  otherwise  || invalid | reject                          # this state is used for 'pop'
  -------------|-------------||---------|-------------------------------
  5  r,r/i op  |     '%'     ||   reg   | record, scan ws, match ',', goto 6
       (1)     |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------  # these are typical computations
               |     '%'     ||   reg   | record, note 1, goto 16         # but not 'mov'
  6  r,r/i op  |   is_num    ||   i5    | record, note 2, goto 17 
       (2)     |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
               |     '%'     ||   reg   | record, scan ws, match ',', goto 8
  7    mov     |     '%'     ||  creg   | record, scan ws, match ',', goto 9
       (1)     |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
               |     '%'     ||   reg   | record, goto 16
               |     '%'     ||  creg   | record, arrange arguments in mfcr format, goto 17
  8    mov     |   is_num    ||   s5    | record, goto 17
       (r2)    |   is_num    ||   i16   | record, ensure symbol is recorded as NULL, goto 18
               |  is_alpha   ||  name   | record, goto 18
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
               |     '%'     ||   reg   | arrange arguments in mtcr format and goto 16
  9    mtcr    |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
  10 reserved for adding things.
  -------------|-------------||---------|-------------------------------
  11 0 operand |     '\n'    ||   eol   | skip, accept, tail call asm_first_pass_0
                  otherwise  || invalid | reject               # this state is used for nop,hlt,ret{code}
  -------------|-------------||---------|-------------------------------
  12    R      |     '\n'    ||   eol   | skip, accept, tail call asm_first_pass_R # push r, pop r
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
  13    I      |     '\n'    ||   eol   | skip, accept, tail call asm_first_pass_I # push u5
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
  14    RJ     |     '\n'    ||   eol   | skip, accept, tail call asm_first_pass_RJ # jump/call r
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
  15    RL     |     '\n'    ||   eol   | skip, accept, tail call asm_first_pass_LJ # jump/call lbl
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
  16    RR     |     '\n'    ||   eol   | skip, accept, tail call asm_first_pass_RR # reg-reg comp
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
  17    RI     |     '\n'    ||   eol   | skip, accept, tail call asm_first_pass_RI # reg-i5 comp
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
  18 long move |     '\n'    ||   eol   | skip, accept, tail call asm_first_pass_LM # long move
               |  otherwise  || invalid | reject
  -------------|-------------||---------|-------------------------------
  
  

Note 1: if the instruction is 'slo,' this case should reject.
Note 2: For any opcodes <8 or ==9, this is an s5. Otherwise, it is a u5.
  An invalid immediate for the opcode should be rejected.
Note 3: record, scan ws, match ',', scan reg, arrange arguments in mtcr format, goto 16

*/
#define STATE_PUSH  2
#define STATE_TX    3
#define STATE_POP   4
#define STATE_COMP  5
#define STATE_MOV   7
#define STATE_NOARG 11

// These can probably all be implemented as a single function,
// in which case it should be called 'die' and can take an argument
// to use as an index into a char** to find the error string.
// Argument should probably be in r0, die_unknown_symbol can take name in r1.
static char *invalid_syntax   = "invalid syntax";
static char *invalid_register = "invalid register";
static char *invalid_imm      = "invalid immediate";
static char *out_of_range     = "out of range";
static char *out_of_memory    = "out of memory";
static char *unknown_symbol   = "unknown symbol ";

void reject() {
  syscall(2, invalid_syntax);
  kill_assembler();
}

void die_invalid_register() {
  syscall(2, invalid_register);
  kill_assembler();
}

void die_invalid_immediate() {
  syscall(2, invalid_imm);
  kill_assembler();
}

void die_out_of_range() {
  syscall(2, out_of_range);
  kill_assembler();
}

void die_out_of_memory() {
  syscall(2, out_of_memory);
  kill_assembler();
}

void die_unkown_symbol(symbol name) {
  syscall(2, unknown_symbol);
  *(name + 16) = 0; // defend against 16-character symbol names which are
  // not nul-terminated in the symbol table. We're crashing anyway.
  syscall(2, name);
  kill_assembler();
}

// In the asm code, since this will be a call table, all these functions need to have the
// same calling interface.
// I propose regL, regR/imm, opc, size_bits, symbol_ptr arguments.
// We can have a 5-register call for these functions.

// Immediates should be already validated.

// When these functions are called, their return address should be on top of the stack
// and a pointer to static_data should be in %bp.
// Tail-calling these functions with a register jump requires an extra
// register to hold the function pointer, so we can't just have the return address in %ln.

typedef uint8_t  a_register;
typedef int16_t immediate;
typedef int16_t operand;

// first pass functions:
void asm_first_pass_one_line();
void asm_first_pass_0 (a_register, operand, opcode, uint8_t, symbol);
void asm_first_pass_R (a_register, operand, opcode, uint8_t, symbol);
void asm_first_pass_I (a_register, operand, opcode, uint8_t, symbol);
void asm_first_pass_RJ(a_register, operand, opcode, uint8_t, symbol);
void asm_first_pass_LJ(a_register, operand, opcode, uint8_t, symbol);
void asm_first_pass_RR(a_register, operand, opcode, uint8_t, symbol);
void asm_first_pass_RI(a_register, operand, opcode, uint8_t, symbol);
void asm_first_pass_LM(a_register, operand, opcode, uint8_t, symbol);

// This function sticks the final value of cur in static_data when it is done
// parsing a line successfully (if it fails, the program terminates, so that case
// is handled). The driver can check this value to decide what to do; a value of 10
// means we ended on a newline and should keep going. A value of 0 means the file
// is over and we should stop.
//
// Inside this function, the value of %ln need not be preserved. This function is
// only called in one place, and all paths through it either crash or return
// via 'finalize_encoding.' 'finalize_encoding' should be made to take %ln off
// the stack, expecting that it is there. Finalize encoding can have two entry
// points, one where it pushes the initial %ln, and one where it doesn't. This
// is quite useful for saving space in the function that assembles long moves.
//
// Note that when we don't care about %ln, 'call' instructions are just better
// 'jmp' instructions.
void asm_first_pass_one_line() {
  symbol symbolptr;
  read_opcode_t rop;
  opcode opc;
  uint8_t size_bits;
  // imm and regR should be allocated to the same register!
  ubyte regL, regR = 0;
  int32_t imm = 0;

  int state = 0;
  
  cur = getchar(); // initialize
  while ( true ) {
    switch(state) {
      case 0:
        if ( is_alpha(cur) ) {
          ste_attach_payload(read_name(), static_data->top.assembly_ip);
          if ( match(58) ) goto reject; // ':'
        }
        state = 1;
        break;
      case 1:
        if ( is_eol(cur) ) goto accept;
        rop = read_opcode();
        opc = rop.opcode;
        state = rop.state;
        size_bits = read_size();
#ifdef COMPILE
//        printf("read opcode %d(%d), -> state %d\n", opc, size_bits, state);
#endif
        break;
      case 2:
        if ( cur == 37 ) { // '%'
          regL = read_register();
          state = 12;
          break;
        }
        if ( is_imm_start(cur) ) {
          imm = read_immediate();
          if ( !validate_u5(imm) ) {
            die_invalid_immediate();
          }
          state = 13;
          break;
        }
        goto reject;
      case 3:
        if ( cur == 37 ) { // %
          regL = read_register();
          state = 14;
          break;
        }
        if ( is_alpha(cur) ) {
          symbolptr = read_name();
          state = 15;
          break;
        }
        goto reject;
      case 4:
        if ( cur == 37 ) { // %
          regL = read_register();
          state = 12;
          break;
        }
        goto reject;
      case 5:
        if ( cur == 37 ) { // %
          regL = read_register();
          state = 6;
scan_comma:
          skip_whitespace();
          match(44); // ','
          break;
        }
        goto reject;
      case 6:
        if ( cur == 37 ) { // %
          if ( opc == 12 ) { // slo
            goto reject;
          }
          regR = read_register();
          state = 16;
          break;
        }
        if ( is_imm_start(cur) ) {
          imm = read_immediate();
          if ( opc == 8 || opc >= 10 ) {
            if ( !validate_u5(imm) ) {
              die_invalid_immediate();
            }
          } else {
            if ( !validate_s5(imm) ) {
              die_invalid_immediate();
            }
          }
          state = 17;
          break;
        }
        goto reject;
      case 7:
        if ( cur == 37 ) { // %
          regL = read_any_register();
          if ( regL < 8 ) {
            state = 8;
          }
          else {
            state = 9;
          }
          goto scan_comma;
        }
        goto reject;
      case 8:
        if ( cur == 37 ) { // %
          regR = read_any_register();
          if ( regR < 8 ) {
            state = 16;
            break;
          }
          // remember regR and imm are the same register!
          imm = regR - 8; // CR index, so now dest is in regL and CR index is imm.
          opc = 14;       // 14 is 'mfcr'
          state = 17;
          break;
        }
        if ( is_imm_start(cur) ) {
          imm = read_immediate();
          if ( validate_s5(imm) ) {
            state = 17;
            break;
          }
          if ( validate_i16(imm) ) {
            symbolptr = NULL;
            state = 18;
            break;
          }
          die_invalid_immediate();
        }
        if ( is_alpha(cur) ) {
          symbolptr = read_name();
          state = 18;
          break;
        }
        goto reject;
      case 9:
        if ( cur == 37 ) { // %
          imm = regL - 8; // CR index, src is in regR and CR index is in imm.
          regL = read_register();
                          // now source register is in regL (correctly)
          opc = 15;       // 15 is 'mtcr'
          state = 17;
          break;
        }
        goto reject;        

      case 11:
      case 12:
      case 13:
      case 14:
      case 15:
      case 16:
      case 17:
      case 18:
        if ( is_eol(cur) ) goto accept;
      default:
#ifdef COMPILE
        printf("(%x) unimplemented\n", cur);
#endif
        goto reject;
    }
    skip_whitespace();
  }

accept:
  static_data->save_cur = cur;
#ifdef COMPILE
//  printf("accept in state %d\n", state);
#endif
  switch(state) {
  case 1: return; // fix up stack if necessary. Obviously this isn't part of the jump table.
  // In the asm code, since this will be a jump table, all these functions need to have the
  // same calling interface.
  // I propose regL, regR/imm, opc, size_bits, symbol_ptr arguments.
  // We can have a 5-register call for these functions.
  // These are all tail calls, so should be called with our %ln via jmp r.
  // Also remember that regR and imm should be allocated to the same register!
  case 11: return asm_first_pass_0 (regL, regR | imm, opc, size_bits, symbolptr);
  case 12: return asm_first_pass_R (regL, regR | imm, opc, size_bits, symbolptr);
  case 13: return asm_first_pass_I (regL, regR | imm, opc, size_bits, symbolptr);
  case 14: return asm_first_pass_RJ(regL, regR | imm, opc, size_bits, symbolptr);
  case 15: return asm_first_pass_LJ(regL, regR | imm, opc, size_bits, symbolptr);
  case 16: return asm_first_pass_RR(regL, regR | imm, opc, size_bits, symbolptr);
  case 17: return asm_first_pass_RI(regL, regR | imm, opc, size_bits, symbolptr);
  case 18: return asm_first_pass_LM(regL, regR | imm, opc, size_bits, symbolptr);
  default: break;
  }

reject:
#ifdef COMPILE
//  printf("state: %d\n", state);
#endif
  reject();
}

void asm_first_pass() {
  do {
    asm_first_pass_one_line();
    static_data->src_lineno++;
    if ( static_data->intermediate_code_ip > (void*)static_data->relocation_table_bot ) {
      die_out_of_memory();
    }
  } while (static_data->save_cur
#ifdef COMPILE
             && static_data->save_cur != -1 // stop on eof
#endif
    );
}

/****************************************************
 ***************** ASSEMBLING TOOLS *****************
 ****************************************************/

uint8_t shl(uint8_t x, uint8_t shamt) {
#ifdef COMPILE
  return x << shamt;
#else
  for ( ; shamt > 0 ; --shamt ) {
    x = x + x;
  }
  return x;
#endif
}

// finalize encoding by writing the bytes to the assembled segment
// and incrementing the relevant pointers by the given amount.
//
// This function should expect the top of the stack to be its return address,
// and a pointer to static_data to be in %bp.
void finalize_encoding(ubyte enc_fst, ubyte enc_snd, uint8_t numbytes) {
  char *iloc = static_data->intermediate_code_ip;
  *iloc = enc_fst;
  *(iloc + 1) = enc_snd;
  static_data->top.assembly_ip += numbytes;
  static_data->intermediate_code_ip += numbytes;
}

// For the first pass of assembling. Attempt to retrieve the value of a symbol.
// If it can be retrieved, the value is returned (nonzero, since the allocation
// region does not contain address 0). If it could not be retrieved, then 0 is
// returned, and an entry is added to the relocation table with the a new
// symbol table entry for that symbol.
int16_t get_symbol_first_pass(symbol name) {
  table_entry entry = find_table_entry(name);
  int16_t value = ste_get_payload(entry);
  if (value) return value;

  reloc_t *reloc_table = static_data->relocation_table_bot;
  reloc_table = reloc_table - 1; // note pointer arithmetic. A reloc_t is 6 bytes on target machine.

  reloc_table->intermediate_inst = static_data->intermediate_code_ip;  
  reloc_table->ste = entry;
  reloc_table->lineno = static_data->src_lineno;
  static_data->relocation_table_bot = reloc_table;
  return value;
}

// For the second pass of assembling. Attempt to retrieve the value of an ste.
// If it is non-zero, the value is returned. If it is zero, then the label
// was never defined, and we can die with an unknown label error.
uint16_t get_symbol_second_pass(table_entry entry) {
  int16_t value = ste_get_payload(entry);
  if (value) return value;

  die_unkown_symbol(entry->symbol);
  return value;
}


/*****************************************************
 **************** ASSEMBLER FUNCTIONS ****************
 *****************************************************/


// handles 3 asm instructions: nop, hlt, and retcc.
// For hlt, opcode is 14. For nop, it is 15. They
// should be assembled to base short jumps with disp 0.
//
// for retcc, the opcode is between 16 and 30 incl.
// It should be assembled as though it were jcc %ln.
void asm_first_pass_0(a_register _r, operand _o, opcode opc, uint8_t _s, symbol _p) {
  uint8_t enc_fst, enc_snd;
  if ( opc <= 15 ) {
    enc_fst = 4; // 0b 100
    enc_fst = (enc_fst << 5) | opc;
    enc_snd = 0;
    finalize_encoding(enc_fst, enc_snd, 2);
  }
  else {
    asm_first_pass_RJ(7, _o, opc & 15, _s, _p); // arguments starting with _ can be
      // whatever, don't worry about actually passing them correctly.
  }
}

// handles 2 asm instructions: push r, and pop r.
void asm_first_pass_R(a_register reg, operand _o, opcode opc, uint8_t size_bits, symbol _p) {

  if ( opc == 12 ) {
    asm_first_pass_RR(reg, 6, opc, size_bits, _p);
  } else {
    asm_first_pass_RR(6, reg, opc, size_bits, _p);
  }
}

// handles 1 asm instruction: push u5
void asm_first_pass_I(a_register _r, immediate imm, opcode opc, uint8_t size_bits, symbol _p){
  asm_first_pass_RI(6, imm, opc, size_bits, _p);
}

// handles all jcc r and callcc r instructions.
// The format is _extremely_ regular, so this is quite easy.
void asm_first_pass_RJ(a_register reg, operand _o, opcode opc, uint8_t _s, symbol _p) {
  ubyte enc_fst, enc_snd;

  enc_snd = reg;
  enc_snd = (enc_snd << 5) | opc;

  enc_fst = 5;
  enc_fst = (enc_fst << 5) | 15;

  finalize_encoding(enc_fst, enc_snd, 2);
}

// note 2047 = ~ -2048
// similarly 255 = ~ -256
// Math!

// This function should also expect its return address on the stack.
void asm_call_L(uint16_t tgt, uint16_t here) {
  int16_t disp = tgt - here;
  if ( disp < -2048 || disp > 2047  ) {
    die_out_of_range();
  }
  uint16_t imm = disp & 0x0fff;
  imm = shr4(imm, 8);
  imm = shr4(imm, 4);
  imm += 16;
  ubyte enc_fst = 5;
  enc_fst = (enc_fst << 5) | imm;
  finalize_encoding(enc_fst, disp, 2);
}

// This function should also axpect its return address on the stack.
void asm_jump_L(uint16_t tgt, uint16_t here, opcode opc) {
  int16_t disp = tgt - here;
  if ( disp < -256 || disp > 255 ) {
    die_out_of_range();
  }
  if ( disp < 0 ) {
    opc += 16;
  }
  
  ubyte enc_fst, enc_snd;

  enc_fst = 4;
  enc_fst = (enc_fst << 5) | opc;
  
  enc_snd = (ubyte)disp;

  finalize_encoding(enc_fst, enc_snd, 2);
}

// handles all jcc lbl instructions, and call lbl.
// conditional calls to a label are invalid.
void asm_first_pass_LJ(a_register _r, operand _o, opcode opc, uint8_t _s, symbol name) {
  if ( opc > 15 && opc != 30 ) {
    reject();
  }

  uint16_t payload = get_symbol_first_pass(name);

  if (!payload) {
    finalize_encoding(opc, -1, 2);
    return;
  }

  if (opc == 30) {
    asm_call_L(payload, static_data->top.assembly_ip);
  } else {
    asm_jump_L(payload, static_data->top.assembly_ip, opc);
  }
}

void asm_first_pass_RR(a_register regL, operand regR, opcode opc, uint8_t size_bits, symbol _p) {
  ubyte enc_fst, enc_snd;

  enc_fst = shl(size_bits, 4) | opc;
  enc_snd = (regL << 5) | shl(regR, 2);

  finalize_encoding(enc_fst, enc_snd, 2);
}

// this function needs a second entrypoint which takes the return address in %ln
// instead of on the stack. This is to support calls from 'asm_long_move.'
// It can push %ln and then fall through.
void asm_first_pass_RI(a_register reg, immediate imm, opcode opc, uint8_t size_bits, symbol _p) {
  ubyte enc_fst, enc_snd;

  enc_fst = shl(size_bits + 4, 4) | opc;
  enc_snd = (reg << 5) | (imm & 31);

  finalize_encoding(enc_fst, enc_snd, 2);
}

// This function should also expect its return address on the stack.
void asm_long_move(a_register reg, immediate imm) {
  asm_first_pass_RI(reg, !(!( imm < 0 )), 9, 1, NULL);

  int16_t bottom, middle, top;
  bottom = imm & 31;
  middle = shr5(imm, 10);
  top    = shr5(middle, 5);
  middle &= 31;

  asm_first_pass_RI(reg, top,    12, 1, NULL);
  asm_first_pass_RI(reg, middle, 12, 1, NULL);
  // this call should ensure our return address is at the top of the stack
  // and then use the STKLN entrypoint to asm_first_pass_RI.
  asm_first_pass_RI(reg, bottom, 12, 1, NULL);
}

void asm_first_pass_LM(a_register reg, immediate imm, opcode opc, uint8_t size_bits, symbol name) {
  if (name) {
    imm = get_symbol_first_pass(name);
    if ( !imm ) {
      return finalize_encoding(-1, reg, 8);
    }
  }

  asm_long_move(reg, imm);
}

/****************************************************
 ******************* SECOND PASS ********************
 ****************************************************/

// all paths through which this function can return want their return address
// on the stack, so this function should start by pushing it.
void asm_second_pass_visit(uint16_t asm_ip, table_entry ste) {
  int16_t target = get_symbol_second_pass(ste);

  // this is just *asm_ip when assembling, when compiling it's a host pointer
  byte opc = *(char*)(static_data->intermediate_code_ip);
  if ( opc == -1 ) {
    ubyte reg = *(char*)(static_data->intermediate_code_ip+1); // *(asm_ip+1)
    return asm_long_move(reg, target);
  }
  if ( opc == 30 ) {
    asm_call_L(target, asm_ip);
  } else {
    asm_jump_L(target, asm_ip, opc);
  }
}

// This pass is just a "quick" walk over the relocation table,
// filling in each instruction that was missing data.

void asm_second_pass() {
  uint16_t saved_end_of_prog = static_data->top.assembly_ip;
  uint16_t saved_lineno = static_data->src_lineno;

  for ( reloc_t *entry = static_data->relocation_table_bot
      // this is easily checked for because relocation_table_top is INT16_MIN
      ; entry != static_data->relocation_table_top
      ; ++entry // note pointer arith. Each reloc_t is 6 bytes.
      ) {
#ifdef COMPILE
    intptr_t x86_iptr = (intptr_t)entry->intermediate_inst;
    uint16_t iptr = x86_iptr - (intptr_t)(bottom_memory-32);
#else
    uint16_t iptr = (uint16_t)(intptr_t)entry->intermediate_inst;
#endif
    // when assembling, intermediate_code_ip should just be
    // assembly_ip. They don't need to be separated.
    static_data->intermediate_code_ip = entry->intermediate_inst;
    static_data->src_lineno = entry->lineno;
    
    asm_second_pass_visit(iptr, entry->ste);
  }

  saved_lineno = static_data->src_lineno;
  static_data->top.assembly_ip = saved_end_of_prog;
}

/****************************************************
 ******************* LEXING TOOLS *******************
 ****************************************************/

int32_t read_immediate() {
  // on entry, cur is the first textual digit of the number
  // or is '-'
  int32_t imm, immx2;
  bool negate = false;

  if (cur == 45) { // '-'
    negate = true;
    cur = getchar();
  }

  imm = cur - 48; // cur - '0'
  while ( (cur = getchar()) >= 48 && cur < 58 ) {
    imm = imm + imm;   // x2
    immx2 = imm;
    imm = imm + imm;   // x4
    imm = imm + imm;   // x8
    imm = imm + immx2; // x10
    imm = imm + cur - 48;
  }

  if (negate) {
    return -imm;
  } else {
    return imm;
  }
}

// Due to where these functions are called, they should preserve all
// registers other than r0. This should only be tricky for the i16 variant.
bool validate_u5(uint32_t imm) {
  return imm < 32;
}
bool validate_s5(int32_t imm) {
  return imm >= -16 && imm <= 15;
}
bool validate_i16(int32_t imm) {
  return imm >= -32768 && imm <= 65535;
}


bool is_alpha(char c) {
  if (c <  65)  return false;
  if (c <= 90)  return true;
  if (c == 95)  return true;  // allow _ at start of names
  if (c <  97)  return false;
  if (c <= 122) return true;
  return false;
}

// can be implemented as an extra entrypoint on is_num
bool is_imm_start(char c) {
  if (c == 45) { // '-'
    return true;
  }
  return is_num(c);
}

bool is_num(char c) {
  if (c <  48) return false;
  if (c <= 57) return true;
  return false;
}

bool is_alphanum(char c) {
  return is_alpha(c) || is_num(c);
}

bool is_eol(char c) {
  return c == 10 || c == 0
#ifdef COMPILE
           || c == -1 // eof is eol
#endif
    ; // newline or null
}

bool is_name_char(char c) {
  return is_alpha(c) || is_num(c) || c == 95;
}

symbol read_name() {
  // on entry, cur is a character satisfying is_alpha.
  char *buffer = global_buffer;
  uint8_t i = 0;
  do {
    *(buffer + i) = cur;
    ++i;
  } while ( is_name_char(cur = getchar()) && i < 16);
  if ( i < 16 ) {
    *(buffer + i) = 0;
  }
  return buffer;
}

typedef struct rt_entry {
  char name[2]; // always 2 characters, NOT NULL TERMINATED. Save space.
  ubyte number;
  char *remainder_to_consume;
} rt_entry;

ubyte read_any_register() {
  // on entry, cur is '%', we can disregard that.
  static const rt_entry register_table[19] = {
      { "r0", 0, "" }, { "a0", 0, "" },
      { "r1", 1, "" }, { "a1", 1, "" },
      { "r2", 2, "" }, { "a2", 2, "" },
      { "r3", 3, "" }, { "s0", 3, "" },
      { "r4", 4, "" }, { "s1", 4, "" },
      { "r5", 5, "" }, { "bp", 5, "" },
      { "r6", 6, "" }, { "sp", 6, "" },
      { "r7", 7, "" }, { "ln", 7, "" },
      { "cp", 8, "uid" },
      { "ex", 9, "ten" },
      { "fe", 10, "at" }
  };
  
  char *buffer = global_buffer;
  *buffer = getchar();
  *(buffer+1) = getchar();
  cur = getchar();
  for (int i = 18; i >= 0; --i) {
    if ( !strncmp(buffer, register_table[i].name,2) ) {
      if ( consume(register_table[i].remainder_to_consume) ) {
        goto die;
      }
      if ( is_alphanum(cur) ) {
        goto die;
      }
      return register_table[i].number;
    }
  }

die:
  die_invalid_register();
}

ubyte read_register() {
  ubyte r = read_any_register();
  if ( r < 8 ) {
    return r;
  }
  die_invalid_register();
}

ubyte read_ctrl_register() {
  ubyte r = read_any_register();
  if ( r >= 8 ) {
    return r;
  }
  die_invalid_register();
}

bool is_opcode_suffix(char c) {
  //          'd'         'h'         'x'
  return c == 100 || c == 104 || c == 120 || !is_alpha(c);
}

// these do not need to store state or trigger since they are
// always STATE_COMP and HIT_COMP.
typedef struct opt_entry_2 {
  opcode opcode;
  char name[2];
} opt_entry_2;
typedef struct opt_entry_3_short {
  opcode opcode;
  char name[3];
} opt_entry_3_short;
typedef struct opt_entry_3 {
  opcode opcode;
  int8_t state;
  int8_t trigger;
  char name[3];
} opt_entry_3;
typedef struct opt_entry_4 {
  opcode opcode;
  int8_t state;
  int8_t trigger;
  char name[4];
} opt_entry_4;
typedef struct cond_entry {
  opcode opcode;
  char name[3]; // these must be NUL-terminated!
} cond_entry;

read_opcode_t read_opcode() {
  // plan:
  // lookup table of opcode names (without the size) similar to reg table.
  // Table maps names to (1) the opcode, (2) the state that opcode should
  // transition to in the parser, (3) how we should act when we hit this entry.
  //
  // I think it would be cleanest to have a table of tables, one for opcodes
  // with 2 characters, another for those with 3, and a final for those with 4.
  // Condition codes are handled separately, so 4 is the cap.
  //
  // There are several ways we might want to act when we hit an entry. Most of
  // the time, we want to accept it and move on.
  // When we hit on 'mov', we need to check if the lookahead character is
  // in the follow set of opcodes. If it's not, we need to keep looking. This
  // handles 'movs' and 'movz' opcodes.
  // When we hit on 'j', 'call', or 'ret', we take the opcode section bits
  // and switch to the condition table. There are TWO trigger values for this case.
  // The condition table maps conditions to their numeric condition codes.
  //
  // Whenever we attempt to match a value out of the condition table, we use the
  // lookahead character. We only actually attempt a match if the lookahead
  // character is in the follow set of opcodes: !is_alpha, 'h', 'x', or 'd'.
  // Otherwise we keep buffering new characters until that holds.
  //
  // In the special case of a hit on opcode 'j', we get a trigger value of 0
  // instead of 1. This allows us to start indexing our condition table scan
  // using the trigger value instead of constant 0. We can then put the condition
  // 'mp' as an alias for "always" at spot 0 of the condition table.
  // The empty string in a condition should also be taken to mean "always."

  // triggers:
#define HIT_J    0 // hit on 'j', but this doesn't go through a table
#define HIT_COND 1 // hit on any other conditional context
#define HIT_MOV  2 // hit on 'mov'
#define HIT_COMP 3 // hit on anything else

#define STATE_PUSH  2
#define STATE_TX    3
#define STATE_POP   4
#define STATE_COMP  5
#define STATE_MOV   7
#define STATE_NOARG 11
  int8_t trigger = HIT_J;

  static opt_entry_2 table2[3] = {
    { 4,  "or" },
    { 10, "ld" },
    { 11, "st" },
  };
  // implicitly, state = STATE_COMP, trigger = HIT_COMP
  static opt_entry_3_short table3short[6] = {
    { 0,  "add" },
    { 1,  "sub" },
    { 3,  "cmp" },
    { 5,  "xor" },
    { 6,  "and" },
    { 12, "slo" },
  };
  static opt_entry_3 table3[5] = {
    { 9,  STATE_MOV,   HIT_MOV,  "mov" },
    { 12, STATE_POP,   HIT_COMP, "pop" },
    { 14, STATE_NOARG, HIT_COMP, "hlt" },
    { 15, STATE_NOARG, HIT_COMP, "nop" },
    { 16, STATE_NOARG, HIT_COND, "ret" }
  };
  static opt_entry_4 table4[6] = {
    { 2,  STATE_COMP,  HIT_COMP, "rsub" },
    { 7,  STATE_COMP,  HIT_COMP, "test" },
    { 8,  STATE_COMP,  HIT_COMP, "movz" },
    { 9,  STATE_COMP,  HIT_COMP, "movs" },
    { 13, STATE_PUSH,  HIT_COMP, "push" },
    { 16, STATE_TX,    HIT_COND, "call" }
  };

  static cond_entry tableCond[20] = {
    { 14, "mp" },
    { 0,  "z"  }, { 0,  "e"  },
    { 1,  "nz" }, { 1,  "ne" },
    { 2,  "n"  },
    { 3,  "nn" },
    { 4,  "c"  }, { 4,  "b"  },
    { 5,  "nc" }, { 5,  "ae" },
    { 6,  "o"  }, 
    { 7,  "no" },
    { 8,  "be" }, 
    { 9,  "a"  },
    { 10, "l"  }, 
    { 11, "ge" },
    { 12, "le" }, 
    { 13, "g"  },
    { 14, ""   },
  };

  // This is allocated to {r0,r1} and is spilled if those registers are
  // needed for something else.
  read_opcode_t r;
  r.state = STATE_TX;

  // SHORT CHECKS
  char *buffer = global_buffer;
  *buffer     = cur;
  *(buffer+1) = cur = getchar();

  if ( *buffer == 106 ) { // 'j'
    goto cond;
  }

  // this pair of loops can be cleverly implemented as a single loop
  // with an additional backwards branch conditioned on size < 3.
  // Requires replacing indexed access with strided pointer.
  int size = 2, count = 2;
  for ( ; count >= 0; --count) {
    if ( !strncmp(buffer, table2[count].name, size) ) {
      r.opcode = table2[count].opcode;
      r.state = STATE_COMP;
      cur = getchar();
      return r;
    }
  }

  size = 3, count = 5;
  *(buffer+2) = cur = getchar();
  for ( ; count >= 0; --count) {
    if ( !strncmp(buffer, table3short[count].name, size) ) {
      r.opcode = table3short[count].opcode;
      r.state = STATE_COMP;
      cur = getchar();
      return r;
    }
  }

  // similarly for this pair.
  cur = getchar();
  count = 4;
  for ( ; count >= 0; --count) {
    if ( !strncmp(buffer, table3[count].name, size) ) {
      r.opcode = table3[count].opcode;
      r.state  = table3[count].state;
      trigger = table3[count].trigger;
      if ( trigger == HIT_MOV && !is_opcode_suffix(cur) ) {
        break; // advance to trying the length-4 names
      }
      if ( trigger == HIT_COND ) {
        goto cond;
      }
      // hit comp, or hit mov exactly (not movs or movz)
      return r;
    }
  }

  *(buffer+3) = cur;
  cur = getchar();
  size = 4, count = 5;
  for ( ; count >= 0; --count) {
    if ( !strncmp(buffer, table4[count].name, size) ) {
      r.opcode = table4[count].opcode;
      r.state  = table4[count].state;
      trigger = table4[count].trigger;
      if ( trigger == HIT_COND ) {
        goto cond;
      }
      return r;
    }
  }

  // no hits in any of the tables; must be invalid.
  // Note that even if we hit, say, 'test', on the sequence 'testforthing',
  // (perhaps a misplaced label), when we call 'read_size' it will definitely
  // fail. It will also fail if the character after test would be a valid
  // suffix, because it checks that the character after the suffix is not
  // alphanumeric.
kill:
  reject();
  return r; // this statement is unreachable

cond:
  trigger = trigger; // make gcc shut up about labels on declarations
  // here we read a condition code (read until we see a valid suffix and buffer)
  // and then check the codes against the table.
  uint8_t i = 0;
  while ( !is_opcode_suffix(cur) && i < 2 ) {
    *(buffer + i) = cur;
    ++i;
    cur = getchar();
  }
  *(buffer + i) = 0;

  for ( trigger ; trigger < 20 ; ++trigger ) {
    if ( !strncmp(buffer, tableCond[trigger].name, 3) ) {
      r.opcode += tableCond[trigger].opcode;
      return r;
    }
  }
  goto kill;
}
  
uint8_t read_size() {
  if ( !is_alpha(cur) ) {
    return 1;
  }
  int8_t r;
  char temp = cur;
  cur = getchar();
  if ( temp == 100 ) { // 'd'
    r = 2;
  } else if ( temp == 120 ) { // 'x'
    r = 1;
  } else if ( temp == 104 ) { // 'h'
    r = 0;
  } else {
    goto kill;
  }
  
  if ( is_alphanum(cur) ) {
kill:
    reject();
  }
  return r;
}  

bool match(char c) {
  bool r = cur - c;
  cur = getchar();
  return r;
}

bool consume(const char *check) {
  bool r;
  while ( *check != 0 ) {
    if ( (r = match(*check)) ) {
      return r;
    }
    ++check;
  }
  return 0;
}

void skip_whitespace() {
  // on entry, 'cur' is just "something." On exit, 'cur'
  // should be a character that is not lexical whitespace.
  // This function skips comments.
  // If this function is called at the end of a (lexical) line,
  // then afterwards, 'cur' will be a newline.
  while ( cur == 32 || cur == 9 ) { // ' ' or '\t'
    cur = getchar();
  }
  if ( cur == 59 ) {                // ';'
    while ( cur != 10 ) {           // not '\n'
      cur = getchar();
    }
  }
}
  

static const char *missing_features = "Missing features :("; // NUL-terminated

void kernel() {
#ifdef COMPILE
#define BOTTOM_MEM_SIZE 50000   // lots of space, probably far more than needed
  bottom_memory = malloc(BOTTOM_MEM_SIZE); // lots of space
  global_buffer = bottom_memory;
  static_data = malloc(sizeof(static_data_t));
  static_data->intermediate_code_ip = bottom_memory + 16;
  static_data->symbol_table_root = malloc(10240); // 10 KiB
  
  static_data->relocation_table_top = (void *)(bottom_memory + BOTTOM_MEM_SIZE);
  static_data->relocation_table_bot = static_data->relocation_table_top;
#else
  // initialize pointers
  __asm__( "mov %spx, -4" : : : "sp" );
  __asm__( "mov %bpx, 0xc000" : : : "bp" );
  // check for presence of VN, 8b, and 32b feature bits
  byte features;
  __asm__( "mov %0, %feat" : : (=r) features);
  if (features & 7 != 7) {
    syscall(2, missing_features);
    exit(1);
  }

  // TODO: initialize static data
#endif
  static_data->top.assembly_ip = 48;
  static_data->symbol_table_end = static_data->symbol_table_root;
  static_data->src_lineno = 1;
  // implement things!
  asm_first_pass();
  asm_second_pass();
  get_symbol_second_pass(find_table_entry("_start"));
}

void syscall(int service, void *payload) {
  if (service == 2) {
#ifdef COMPILE
    fputs(payload, stdout);
    fflush(stdout);
#else
#endif
  }
}

void kill_assembler() {
#ifdef COMPILE
  printf("\nFailed at line %d\n", static_data->src_lineno);
#else // idk if I want to implement this part in assembly at all, but it's helpful to user...
  puts("\nFailed at line 0x");
  char buffer[4];
  int16_t lineno = static_data->src_lineno;
  buffer[3] = lineno & 15;
  lineno = shr4(lineno, 12);
  buffer[2] = lineno & 15;
  lineno = shr4(lineno, 8);
  buffer[1] = lineno & 15;
  lineno = shr4(lineno, 4);
  buffer[0] = lineno;
  puthex(buffer, 4); // unimplemented
#endif
  exit(1);
}

#ifdef COMPILE
int main() {
  kernel();
//  fwrite(bottom_memory+16, 1, static_data->top.assembly_ip - 32, stdout);

  printf("Symbol table:\n");
  for ( table_entry entry = static_data->symbol_table_root
      ; entry != static_data->symbol_table_end
      ; ++entry
      ) {
    printf("  %-16.16s 0x%04x\n", entry->symbol, entry->payload);
  }

  printf("\nRelocation table:\n");
  for ( reloc_t *entry = static_data->relocation_table_bot
      ; entry != static_data->relocation_table_top
      ; ++entry
      ) {
    intptr_t x86_iptr = (intptr_t)entry->intermediate_inst;
    intptr_t iptr = x86_iptr - (intptr_t)(bottom_memory-32);
    printf("  %04x  %-16.16s [line %d]\n", iptr, entry->ste, entry->lineno);
  }

  printf("\nAssembled segment:\n");

  int num_instrs = (static_data->top.assembly_ip - 48) / 2;
  short *binptr = (short *)(bottom_memory + 16);

  uint16_t fake_ip = 48;
  while (num_instrs >= 8) {
    printf("%04x   ", fake_ip);
    for (int i = 0; i < 8; ++i) {
      printf("%04x ", *(binptr++) & 0xFFFF);
    }
    printf("\n");
    num_instrs -= 8;
    fake_ip += 16;
  }
  if (num_instrs > 0) {
    printf("%04x   ", fake_ip);
    while (num_instrs > 0) {
      printf("%04x ", *(binptr++) & 0xFFFF);
      --num_instrs;
    }
    printf("\n");
  }

  return 0;
}
#endif
