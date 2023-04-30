.extensions byte_operations, dword_operations, real32, functions

;;; Hand-compiled from asm_loader_kernel.c
;;; I won't copy all of the comments from that file but the general ideas are important.
;;;
;;; Addresses 0-31 are MMIO:
;;;   0: unused by this program
;;;   1: A read-only file stream. This is the input. Reading from this address should
;;;      cause a single character to be read from the stream and the stream to be
;;;      advanced. This program does not require any seeking functionality.
;;;      The end of textual files should be indicated by the character '\0'.
.set STREAM 1
;;;   2: When this address is read from, the user should be queried for a mode, which
;;;      should be given back to the program. Currently, the only understood mode is
;;;      mode 0, which reads the filestream as a textual file and assembles its contents.
;;;      The assembled program is then invoked. See asm_loader_kernel.c for details.
;;;      Note to users in TC: the current version only queries the mode once, so you can
;;;      hardware this I/O to a constant if you like.
.set MODEQ 2
;;;   3: Some form of output system. The program will send bytes to this address when
;;;      the corresponding ASCII character should be printed to the output.
.set OUTPUT 3


;;; Memory between 0x00000020 and 0x1FFFFFFF must be RAM.
;;;     That is 512MB, the most that TC currently supports easily.
;;;     Addresses up to 0x7FFFFFFF being RAM is supported. Assembled programs
;;;     are currently invoked with %sp at 0x1FFFFFFC. Adjust the value below
;;;     if you support more RAM.
;;; Memory from 0x80000000 to 0x9FFFFFFF must be RAM.
;;;     This has the same caveat as above.
;;;     The assembler currently initializes its stack pointer to 0x9FFFFFFC.
;;; Memory from 0xFFFF8000 to 0xFFFFFFFF should be this program ROM.

;;; ********************************************************************************
;;; *********************** Main Implementation Comments ***************************
;;; ********************************************************************************

;;; Symbols are read just above the heap limit, at the right place for the next
;;; symbol table entry in case we will need to create one.
;;;
;;; Addresses from 0x00000020 and up are the destination for the assembled program.
;;; Addresses from 0x80000018 and up are used to hold the symbol and relocation tables.
;;; Addresses in [0x80000000,0x80000014) are used to hold a "static data" segment. The program
;;;   keeps a pointer to 0x8000000C for fast access to this segment. More information about
;;;   its layout follows.
;;;
;;; **The kernel stack is kept dword-aligned.
;;;   This is a major difference between the 16-bit and 32-bit versions of the kernel!

;;; This file does not use one consistent calling convention. *In general*, you can expect
;;;   r0: first argument
;;;   r1: second argument
;;;   r2: third argument
;;;   r3: fourth argument
;;;   r4: callee-saved
;;;   r5: pointer to 0x8000000C if at a stage where this pointer should be kept around
;;;       but sometimes, like during lexing/parsing, we do not need this pointer.
;;;       Then, r5 is a second callee-saved register.
;;;   r6: stack pointer. I will probably only ever refer to this register as %sp.
;;;   r7: link register.
;;;
;;; However, there are a few functions with different calling conventions, which are
;;; documented. Some do not clobber any registers other than those containing the
;;; function arguments (usually only r0 and r1, possibly r2).
;;; Another group of functions expects to be tail-called through a jump table. They
;;; all have 5 arguments. They take their arguments in r0-r4. r5 must be the 0xC010 pointer.
;;; r6 is still their stack pointer. r7 will contain their own address, as it should be used
;;; to call them through the pointer. However, they should not rely on this fact, since a
;;; couple of them are also called from elsewhere. They expect their return address on top
;;; of the stack. Those that are called from elsewhere have a secondary entry point which
;;; pushes %ln.


;;; ********************************************************************************
;;; ****************************** Static Data Layout ******************************
;;; ********************************************************************************

;;;                  asm time         run time
;;;              __________________________________
;;; 0x80000000  |  uint32_t src_lineno |  user %sp |
;;;             |----------------------------------|
;;; 0x80000004  |  table_entry symbol_table_head   |
;;;             |----------------------------------|
;;; 0x80000008  |  reloc_t *relocation_table_head  |
;;;             |----------------------------------|
;;; 0x8000000C  |  instr *asm_ip  |  void *break   |
;;;             |----------------------------------|
;;; 0x80000010  |        void *heap_limit          |
;;;             |----------------------------------|
;;; 0x80000014  |   char eol_char |       ?        |
;;;             |_________________|________________|

.set SRCLINENO_OFS       -12
.set SYMTAB_HEAD_OFS     -8
.set RELOC_TAB_HEAD_OFS  -4
; no value set for ASM_IP_OFS, so that I get an error if I am stupid and try to use it :)
.set HEAP_LIMIT_OFS       4
.set EOL_CHAR_OFS         8

.set STATIC_DATA_PTR    0x8000000C
.set INIT_HEAP_LIMIT    0x80000018
.set INIT_STK_PTR       0xA0000000
.set INIT_OBJ_STK_PTR   0x20000000

.set BUFFER_PTR         0x00000020   ; small buffer for reading opcodes/registers etc
.set CODE_SEGMENT       0x00000030   ; we still use 0x20-0x30 as a buffer for non read_name lexing

;;; ********************************************************************************
;;; ********************************* THE PROGRAM **********************************
;;; ********************************************************************************

            call    _start

; I have no clue what the layout needs to look like to keep related things close together.
; For now I'm just writing functions as I feel like, where I feel like.


object_return_stub:
            mov     %r0, 0                  ; SYSCALL_EXIT
            mov     %r1, 0                  ; STATUS_OK
syscall:
            cmph    %r0, 4                  ; biggest known syscall is 4.
            jbe     good_service_no         ; service <= 4? if yes, keep going. Otherwise, exit 140
            mov     %r0, 0
            mov     %r1, 140                ; exit code 140, SIGSYS
            jmp     syscall
good_service_no:
            testx   %sp, 3                  ; test the bottom 2 stack bits. The ABI requires that these
                                            ; bits be 0, so that the called function can at least
                                            ; save the 32-bit return address.
            jz      aligned_stack           ; crash the program with code 139 (segfault) if it's on
            andd    %sp, -2                 ; align the stack so that we don't weirdloop
            mov     %r0, 0
            mov     %r1, 139
            jmp syscall
aligned_stack:
            pushd   %ln                     ; the stack is now guaranteed to be aligned. Save %ln.
            addd    %sp, 4                  ; But without pushing, so that we save the right %sp.
            mov     %ln, 0x80000000         ; &static_data->user_sp
            std     %sp, %ln                ; static_data->user_sp = %sp
            subd    %sp, 4                  ; go back to where we put our return address
            popd    %ln                     ; restore our return address
            mov     %sp, INIT_STK_PTR       ; initialize our own stack
            pushd   %ln                     ; and save our return address there.
            call    syscall_with_table      ; get the syscall table
            ; all of these functions are implemented down at the bottom
            .align 4 ; align for table
            .dword   syscall_exit syscall_putuint syscall_putsint syscall_puts syscall_sbrk
syscall_with_table:
            addd    %ln, 3
            andd    %ln, -4                 ; align to correct the pointer to the table

            addh    %r0, %r0                ; service_no *= sizeof(word)
            addd    %ln, %r0                ; offset into the syscall table
            ldd     %ln, %ln                ; load the system function to call
            jmp     %ln                     ; invoke it


; The assembler/bootloader entrypoint.
_start:
            mov     %r0, %cpuid1            ; get cpuid1 to check for S&F,8b,32b
            mov     %r1, 0x4000             ; 32-bit operations
            testx   %r0, %r1
            jz      missing_feature
            mov     %r1, 0x1400A            ; S&F,8b,32b,32p
            andd    %r0, %r1
            cmpd    %r0, %r1
            jne     missing_feature
            mov     %r0, %feat              ; get features to check for VN
            testx   %r0, 1                  ; VN
            jz      missing_feature
            jmp     good_features
missing_feature:
            call    die_missing_feature

good_features:
            mov     %r0, 2                  ; 32-bit address mode
            mov     %mode, %r0

            mov     %r5, STATIC_DATA_PTR
            mov     %r6, INIT_STK_PTR
            movd    %r0, %r5
            addd    %r0, 12                 ; INIT_HEAP_LIMIT is STATIC_DATA_PTR+12
            movd    %r1, %r5
            addd    %r1, HEAP_LIMIT_OFS     ; &static_data.heap_limit
            std     %r0, %r1                ; static_data->heap_limit = INIT_HEAP_LIMIT

            subd    %r1, 4                  ; &static_data.asm_ip
            mov     %r0, CODE_SEGMENT       ; initial code segment ip
            std     %r0, %r1                ; static_data->asm_ip = CODE_SEGMENT

            subd    %r1, 4                  ; &static_data.reloc_table_head
            mov     %r0, 0                  ; NULL
            std     %r0, %r1                ; static_data->reloc_table_head = NULL
            subd    %r1, 4                  ; &static_data.symtab_head
            std     %r0, %r1                ; static_data->symtab_head = NULL

            subd    %r1, 4                  ; &static_data.src_lineno
            mov     %r0, 1                  ; initial line is line 1
            stx     %r0, %r1                ; static_data->src_lineno = 1

            call    assemble_fp
            call    assemble_sp
            call    get_start_stub
            .align  4
            .asciiz "_start"
            .align  2
get_start_stub:
            ;; even though it's character data, we have to align this pointer
            ;; to get a correct error message since the string will get copied
            ;; by add_table_entry, and the copy will be bogus if not aligned.
            addd    %ln, 3
            andd    %ln, -4                 ; dword align %ln to get to the string
            movd    %r0, %ln                ; arg 0 = "_start"
            call    find_table_entry        ; find (or create, boo) a table entry for "_start"
            call    sp_get_symbol           ; xlookup the address for _start
            pushd   %r0                     ; stash that while we clean up

            mov     %r0, completed_assembly_msg
            mov     %ln, puts
            call    %ln                     ; inform the user that their program is starting soon
                                            ; at this point, it is time to hang up our hat and give
                                            ; control to the object program. We made a few promises
                                            ; that we have to keep with regards to initialization.
                                            ; We should set the return address to a function that exits
                                            ; successfully. %r0 should be a pointer to the syscall
                                            ; function. The stack pointer needs to be initialized.
                                            ; All other registers should be cleared.
            mov     %ln, object_return_stub
            mov     %r0, 4                  ; syscall - object return stub
            addd    %r0, %ln                ; r0 = syscall
            popd    %r1                     ; reload address of _start to prepare transfer of control
            mov     %sp, INIT_OBJ_STK_PTR   ; initialize the object program stack pointer
            mov     %r2, 0
            mov     %r3, 0
            mov     %r4, 0
            mov     %r5, 0
            jmp     %r1                     ; give control to the object program!


; shr4 and shr5 functions
;   r0: x
;   r1: width
; returns r0: (x >> {4/5}) & (2^width - 1)
; clobbers r1
; r2-r7 unchanged
; Worth looking into whether saving r2/r3 here is worth it. Comment in the C
; code said it would be, but that comment was written long before the callsites.


shr5:
            pushd   %r2      ; having separated vaneers like this is fewer instructions
            movzx   %r2, 16  ; I have optimized for the placement of shr4 here.
            addx    %r2, %r2        ; 16 + 16 = 32
            jmp     shr_L1
shr4:
            pushd   %r2
            movzx   %r2, 16
shr_L1:
            pushd   %r3
            movd    %r3, %r0        ; move x to r3
            pushd   %r4
            mov     %r4, 1          ; b = 1
            mov     %r0, 0          ; clear r0 (it holds 'r')
shr_L2:                             ; top of shr loop
            testd   %r2, %r3        ; test mask & x
            jz      shr_L3          ; don't set bit of r if !(mask & x)
            ord     %r0, %r4        ; r |= b if mask & x, shifts that bit over
shr_L3:
            addd    %r2, %r2        ; mask <<= 1
            cmpd    %r2, %r3        ; mask >? x
            ja      shr_L4          ; if yes, further testds will fail and we can quit.
            addd    %r4, %r4        ; b <<= 1
            subh    %r1, 1          ; --width
            jnz     shr_L2          ; loop if width != 0
shr_L4:
            popd    %r4             ; now r0 has the result
            popd    %r3             ; so we can unwind
            popd    %r2
            ret


;;; ********************************************************************************
;;; ******************************** SYMBOL TABLE **********************************
;;; ********************************************************************************

;;; each entry must be 4-byte aligned for "rapid" copying into the table.
;;; each entry contains a 4-byte 'next' pointer.
;;;   The bottom bit of that pointer is tagged with its validity.
;;; Then a 4-byte payload, and finally an inline nul-terminated symbol.

; find_table_entry
;   r0:  symbol name
;   r5:  must be the static data pointer!
; returns
;   r0:  a pointer to a symbol table entry for 'name' which might be newly added
; Registers r1-r3 are clobbered.
find_table_entry:
            pushd   %ln                 ; prologue, we call other functions
            movd    %r3, %r5            ; copy &static_data
            addd    %r3, SYMTAB_HEAD_OFS; re = &static_data.symtab_head
            ldd     %r1, %r3            ; r1 = static_data->symtab_head

            jmp     find_table_entry_check
find_table_entry_loop:                  ; loop top
                                        ; ste is in r1, name is in r0
            pushd   %r0                 ; save name
            pushd   %r1                 ; save ste
            addd    %r1, 8              ; &ste->symbol
            mov     %r2, -1             ; uint32_t_MAX
            call    strncmp             ; r0 = !(name `streq` ste->symbol)
            test    %r0, -1             ; set Z if the strings were equal
            jnz     find_table_entry_L2 ; skip return if we missed
            popd    %r0                 ; restore ste to r0
            addd    %sp, 4              ; pop name
            popd    %ln                 ; restore return address
            ret
find_table_entry_L2:
            popd    %r1                 ; restore ste to r1
            popd    %r0                 ; restore name to r0
            ldd     %r1, %r1            ; ste = ste->next
            andd    %r1, -2             ; untag the pointer
find_table_entry_check:
            testd   %r1, -1             ; is the pointer null?
            jnz     find_table_entry_loop ; if not, loop
            popd    %ln                 ; restore return address
            ;;; jmp add_table_entry     ; tail-call add_table_entry

; add_table_entry
;   r0:  symbol  name   (symbol = char*)
;   r5:  must be the static data pointer!
; returns
;   r0:  address of new entry
;   r1:  unspecified
;   r2:  unspecified
;   r3:  guaranteed to be 0
; Other registers are unchanged.
add_table_entry:
            movd    %r2, %r5            ; char *ptr = &static_data
            addd    %r2, HEAP_LIMIT_OFS ; ptr = &static_data.heap_limit
            ldd     %r2, %r2            ; ptr = static_data->heap_limit
            movd    %r3, %r2            ; te = ptr
            addd    %r2, 8              ; ptr += offsetof(table_entry_t, symbol)
            cmpd    %r0, %r2            ; compare ptr to name
            je      add_table_entry_NCL ; jump to non-copying loop if not equal
add_table_entry_CL:                     ; otherwise fall through to copying loop
            ldd     %r1, %r0            ; temp = *name, 32-bit transfer
            std     %r1, %r2            ; *ptr = *name, 32-bit transfer
            addd    %r0, 4              ; name += 4
            addd    %r2, 4              ; ptr  += 4
            ldh     %r1, %r0            ; temp = *name again
            testh   %r1, -1             ; is *name zero?
            jnz     add_table_entry_CL  ; if not, loop
            jmp     add_table_entry_done; otherwise go after the loops
add_table_entry_NCL:
            addd    %r2, 4              ; ptr  += 4
            ldh     %r1, %r2            ; temp = *ptr
            testh   %r1, -1             ; is *ptr zero?
            jnz     add_table_entry_NCL ; if not, loop

add_table_entry_done:
            addd    %r2, 4              ; ptr += 4
            movd    %r1, %r5            ; copy &static_data
            addd    %r1, HEAP_LIMIT_OFS ; &static_data.heap_limit
            std     %r2, %r1            ; static_data->heap_limit = ptr
            addd    %r1, -12            ; &static_data.symtab_head
            ldd     %r0, %r1            ; r0 = static_data->symtab_head
            std     %r0, %r3            ; copy symtab_head to te->next
            std     %r3, %r1            ; static_data->symtab_head = te
            movd    %r0, %r3            ; copy te to return register
            ret

; ste_attach_payload
;   r0:  symbol  name
;   r1:  uint32_t payload
; returns
;   r0:  &entry.payload for the entry for 'name'
; Clobbers r2 and r3. The payload remains in r1.
ste_attach_payload:
            pushd   %ln                 ; save return address
            pushd   %r1                 ; save payload
            call    find_table_entry    ; r0 = entry for 'name'
            ldd     %r1, %r0            ; r1 = entry->next
            ord     %r1, 1              ; tag the entry as valid
            std     %r1, %r0            ; entry->next = tagged pointer
            addd    %r0, 4              ; r0 = &entry.payload
            popd    %r1                 ; r1 = payload
            std     %r1, %r0            ; entry->payload = payload
            popd    %ln
            ret

; ste_get_payload
;   r0:  table_entry entry: entry from which to get payload
; returns
;   r0:  uint32_t payload from that entry
; No registers are clobbered.
ste_get_payload:
            addd    %r0, 4
            ldd     %r0, %r0            ; entry->payload
            ret

;;; ********************************************************************************
;;; *************************** ASSEMBLER IMPLEMENTATION ***************************
;;; ********************************************************************************

;;; ********************************** FIRST PASS **********************************

assemble_fp:
            pushd   %ln
assemble_fp_L1:
            call    fpsm
            movd    %r0, %bp            ; r0 = &static_data
            addd    %r0, SRCLINENO_OFS  ; r0 = &static_data.src_lineno
            ldx     %r1, %r0            ; r1 = static_data->src_lineno
            addx    %r1, 1
            stx     %r1, %r0            ; static_data->src_lineno++
            movd    %r0, %bp            ; r0 = &static_data again
            addd    %r0, EOL_CHAR_OFS   ; ro = &static_data.eol_char
            ldh     %r0, %r0            ; r0 = static_data->eol_char
            testh   %r0, -1             ; test the char
            jnz     assemble_fp_L1      ; loop if it's not \NUL
            popd    %ln                 ; if it's \NUL, we're done.
            ret

;;; ********************************* SECOND PASS **********************************

assemble_sp:
            pushd   %ln
            ldd     %r0, %bp            ; r0 = static_data->asm_ip
            pushd   %r0                 ; save ip at end of program
            mov     %r0, SRCLINENO_OFS
            addd    %r0, %bp            ; r0 = &static_data.src_lineno
            ldx     %r0, %r0            ; r0 = static_data->src_lineno
            pushd   %r0                 ; save final lineno, in case can't find _start
            mov     %r0, RELOC_TAB_HEAD_OFS
            addd    %r0, %bp            ; r0 = &static_data.reloc_tab_head
            ldd     %r2, %r0            ; r2 = reloc_entry = static_data->reloc_tab_head
            testd   %r2, -1             ; test the pointer to see if it's null
            jz      assemble_sp_L2      ; skip the loop entirely if so
assemble_sp_L1:
            pushd   %r2                 ; save original value of reloc_entry
            ldd     %r1, %r2            ; r1 = arg 1 = reloc_entry->asm_ip
            std     %r1, %bp            ; static_data->asm_ip = reloc_entry->asm_ip
            addd    %r2, 12             ; &reloc_entry.src_lineno
            ldx     %r0, %r2            ; r0 = reloc_entry->src_lineno
            mov     %r3, SRCLINENO_OFS
            addd    %r3, %bp            ; r3 = &static_data.src_lineno
            stx     %r0, %r3            ; static_data->src_lineno = reloc_entry->src_lineno
            subd    %r2, 8              ; &reloc_entry.entry
            ldd     %r0, %r2            ; arg 0 = reloc_entry->entry
            call    assemble_sp_visit   ; handle this reloc table entry
            popd    %r2                 ; reload original value of reloc_entry
            addd    %r2, 8              ; &entry->next
            ldd     %r2, %r2            ; entry = entry->next
            testd   %r2, -1             ; is entry now NULL?
            jnz     assemble_sp_L1      ; if entry is not NULL, it's a valid entry. Loop.
assemble_sp_L2:
            popd    %r0                 ; restore final lineno
            mov     %r1, SRCLINENO_OFS
            addd    %r1, %bp            ; &static_data.src_lineno
            stx     %r0, %r1            ; static_data->src_lineno = saved original lineno
            popd    %r0                 ; restore ip at end of program
            std     %r0, %bp            ; static_data->asm_ip = ip at end of program
            popd    %ln                 ; restore return address
            ret

; assemble_sp_visit
;   r0: table_entry ste
;   r1: asm_ip
; no returns
; Clobbers whatever it feels like.
;
; Visit the instruction referenced by a relocation table entry.
assemble_sp_visit:
            pushd   %ln
            call    sp_get_symbol       ; arg 0 = target = sp_get_symbol(ste)
            ldh     %r2, %r1            ; opc = *asm_ip
            cmph    %r2, -3             ; test if opc is -3
            jne     assemble_sp_visit_L2; fall through if it is...
            addd    %r1, 1              ; asm_ip + 1
            ldh     %r2, %r1            ; r2 = reg = *(asm_ip+1)
            movd    %r1, %r0            ; arg 1 = target
            movh    %r0, %r2            ; arg 0 = reg
            movh    %r2, 1              ; arg 2 = true [tell assemble_long_mov to use nops]
            call    assemble_long_mov   ; tail-call (it won't be returning here), it returns off stack
assemble_sp_visit_L2:
            ; otherwise, if opc is >= 0, it's a control transfer.
            cmph    %r2, 0              ; compare opc to 0
            jge     assemble_sp_visit_tx; if >= 0, it's a control transfer
            ; if it's < 0, it's a pending value encode, negate it and call that.
            ; target is still in r0 from the call to sp_get_symbol
            movh    %r1, %r2            ; prepare for arg 1 to have -opc
            rsubh   %r1, 0              ; arg1 = -opc
            movd    %r2, %r5            ; arg2 = &static_data (that's encode_value's cc)
            call    encode_value_stkret ; tail-call the encode_value entrypoint that wants %ln on the stack.
assemble_sp_visit_tx:
            cmph    %r2, 15             ; opc >? 15
            ja      fp_call_L           ; if yes, this is a call
            jmp     fp_jump_L           ; otherwise, it's a jump
            ; those are both tail-calls. They will return via the %ln
            ; we put on top of the stack, to just above assemble_sp_L2.

; *********************** UTILITIES ***********************

; fp_get_symbol
;   r0: symbol name
;   r5: &static_data
; returns
;   r0: the entry for that symbol, or NULL if there wasn't one.
; Clobbers r1 and r3.
;
; If an entry for the name does not exist, one will be added. In this case, the
; entry will be NULL, and a relocation will be added to the relocation table
; to indicate that the instruction assembled at the current static_data->asm_ip
; needs to be revisited later.
fp_get_symbol:
            pushd   %ln
            pushd   %r2                 ; we promise to preserve this, so can't clobber
            call    find_table_entry    ; r0 = entry = find_table_entry(name)
                                        ; clobbers r1,r2,r3
            movd    %r2, %r0            ; copy entry so we can check validity
            ldd     %r2, %r2            ; entry->next, which is tagged with validity
            testh   %r2, 1              ; if that bit is on, the entry is valid
            popd    %r2                 ; unwind the stack, we aren't calling more functions
            popd    %ln                 ; final unwind
            retnz                       ; if that bit was on, nz is set, entry is in r0, return!
        ; entry is in r0, and has to stay until we save it. free use of r1 and r3
            mov     %r3, HEAP_LIMIT_OFS
            addd    %r3, %r5            ; &static_data.heap_limit
            ldd     %r1, %r3            ; reloc_entry = static_data->heap_limit
            addd    %r1, 4              ; &reloc_entry->ste
            std     %r0, %r1            ; reloc_entry->ste = entry
            ; entry is saved, now we have use of r0
            movd    %r0, %r1            ; copy static_data->heap_limit+4
            addd    %r0, 12             ; static_data->heap_limit+4 + 12
                                        ;   (incr. by sizeof(reloc_t), but we already added 4)
            std     %r0, %r3            ; static_data->heap_limit += 16
            addd    %r1, -4             ; &reloc_entry->inst
            ldd     %r0, %r5            ; r0 <- static_data->asm_ip
            std     %r0, %r1            ; reloc_entry->inst = static_data->asm_ip
            addd    %r1, 8              ; &reloc_entry->next
            mov     %r0, RELOC_TAB_HEAD_OFS
            addd    %r0, %r5            ; &static_data->reloc_tab_head
            ldd     %r3, %r0            ; static_data->reloc_tab_head
            std     %r3, %r1            ; reloc_entry->next = static_data->reloc_tab_head
            addd    %r1, -8             ; recover pointer to reloc_entry
            std     %r1, %r0            ; static_data->reloc_tab_head = reloc_entry
            addd    %r1, 12             ; &reloc_entry->lineno
            mov     %r0, SRCLINENO_OFS
            addd    %r0, %r5            ; &static_data->src_lineno
            ldx     %r0, %r0            ; static_data->src_lineno
            stx     %r0, %r1            ; reloc_entry->lineno = static_data->src_lineno
            ; finally, the entry is initialized. Return NULL.
            mov     %r0, 0
            ret

; sp_get_symbol
;   r0: table_entry entry
; returns
;   r0: payload from that entry
; No clobbers.
; This function crashes with an 'unknown symbol' error if the entry is
; invalid. This would happen if we called find_table_entry on the same symbol
; at some point, but then never attached a payload (found the defn site) later.
sp_get_symbol:
            pushd   %ln
            pushd   %r0                 ; save entry
            ldd     %r0, %r0            ; entry->next, tagged with validity
            testh   %r0, 1              ; if the tag bit is on, it's valid!
            jnz     sp_get_symbol_valid
            ; otherwise, crash :(
            popd    %r1                 ; reload entry to arg1 = r1
            call    die_unknown_symbol  ; crash. Since we're crashing, no need to recover %ln.
sp_get_symbol_valid:
            popd    %r0                 ; reload entry to return register
            call    ste_get_payload     ; r0 = entry->payload
            popd    %ln
            ret

;;; The relocation table:
;;; The static data maintains the relocation table top and bottom. It grows down,
;;; starting from the top of low memory. Each entry contains fields needed to
;;; revisit an instruction that was missing a symbol later. This includes the source
;;; line number, to emit during an error message if the symbol can't be found the
;;; second time around. The layout is as follows:
;;;              ┌──────────────┐
;;;     base+0   │    asm_ip    │
;;;              ├──────────────┤
;;;     base+4   │  ste *entry  │
;;;              ├──────────────┤
;;;     base+8   │  reloc *next │
;;;              ├──────────────┤
;;;     base+12  │  src_lineno  │
;;;              └──────────────┘


;;; ********************************* ASSEMBLERS ***********************************

; Placed here for jump range reasons, just a stub function to get out
; to 'die' with the right argument.
fp_die_out_range:
            call    die_out_of_range

; fp_0
; Same ABI as other assembler functions.
; all of the jmp tail-calls to finalize_encoding could be 'call's instead
; because finalize_encoding takes its return address off the stack.
; Handles instructions with no operands.
fp_0:
            cmph    %r2, 15             ; opc <=? 15
            ja      fp_0_encode_ret     ; if not, encode a return
            movh    %r0, 4              ; otherwise, enc_fst = 4
            sloh    %r0, 0              ; enc_fst <<= 5
            orh     %r0, %r2            ; enc_fst |= opc
            movh    %r1, 0              ; enc_snd = 0
            mov     %r2, 2              ; numbytes = 2
            jmp     finalize_encoding   ; tail-call
fp_0_encode_ret:
            mov     %r0, 7              ; regL = 7
            andh    %r2, 15             ; opc &= 15
            jmp     fp_RJ               ; tail-call


; fp_RJ
; Handles register-indirect jump instructions
fp_RJ:
            movh    %r1, %r0            ; enc_snd = reg
            sloh    %r1, 0              ; enc_snd <<= 5
            orh     %r1, %r2            ; enc_snd |= opc
            movh    %r0, 5              ; enc_fst = 5
            sloh    %r0, 15             ; enc_fst = enc_fst << 5 | 15
            mov     %r2, 2              ; numbytes = 2
            jmp     finalize_encoding   ; tail-call

; fp_call_L
; Handles labeled call instructions
fp_call_L:
            subd    %r0, %r1            ; disp = tgt - here
            mov     %r1, 2047           ; get 2047 for comparison
            cmpd    %r0, %r1            ; disp >? 2047
            jg      fp_die_out_range    ; if yes, die
            rsubd   %r1, -1             ; r1 = ~2047 = -2048
            cmpd    %r0, %r1            ; disp <? -2048
            jl      fp_die_out_range
            mov     %r3, %r0            ; save displacement in r3
            mov     %r1, 8              ; arg 1 = 8
            call    shr4                ; imm = (imm >> 4) & 0xFF
            mov     %r1, 4              ; arg 1 = 4
            call    shr4                ; imm = (imm >> 4) & 0xF
            addh    %r0, 8
            addh    %r0, 8              ; imm += 16
            mov     %r1, 5
            sloh    %r1, 0              ; r1 = 5 << 5
            orh     %r0, %r1            ; enc_fst = imm | (5 << 5)
            mov     %r1, %r3            ; put displacement back in arg 1
            mov     %r2, 2              ; numbytes = 2
            jmp     finalize_encoding   ; tail-call

; fp_jump_L
; Handles labeled jump instructions
fp_jump_L_stdcall:
            pushd   %ln
fp_jump_L:
            rsubd   %r1, %r0            ; disp = tgt - done
            mov     %r0, 255            ; get 255 for comparison
            cmpd    %r1, %r0            ; disp >? 255
            jg      fp_die_out_range    ; if yes, die
            rsubd   %r0, -1             ; r0 = ~255 = -256
            cmpd    %r1, %r0            ; disp <? -256
            jl      fp_die_out_range
            cmpx    %r1, 0              ; disp <? 0
            jge     fp_jump_L_skip_inc  ; if not, don't adjust the opcode
            addx    %r2, 8
            addx    %r2, 8              ; opc += 16
fp_jump_L_skip_inc:
            mov     %r0, 4              ; enc_fst = 4
            sloh    %r0, 0              ; enc_fst <<= 5
            orh     %r0, %r2            ; enc_fst |= opc
                                        ; enc_snd = disp is already in r1
            mov     %r2, 2              ; numbytes = 2
            jmp     finalize_encoding   ; tail-call

fp_RR:
            addh    %r1, %r1            ; regR <<= 1
            addh    %r1, %r1            ; regR <<= 1
            sloh    %r0, 0              ; regL <<= 5
            orh     %r1, %r0            ; enc_snd = regL (<< 5) | regR (<< 2)
fp_RX_shared:
            addh    %r3, %r3            ; size_bits << 1
            addh    %r3, %r3            ; size_bits << 2
            addh    %r3, %r3            ; size_bits << 3
            addh    %r3, %r3            ; size_bits << 4
            movh    %r0, %r3            ; enc_fst = size_bits << 4
            orh     %r0, %r2            ; enc_fst |= opc
            mov     %r2, 2              ; numbytes = 2
            jmp     finalize_encoding

;
fp_RI_stdcall:
            pushd   %ln
fp_RI:
            sloh    %r0, 0              ; regL <<= 5
            movz    %r7, 31
            andh    %r1, %r7            ; imm &= 31
            orh     %r1, %r0            ; enc_snd = regL (<< 5) | imm (& 31)
            addh    %r3, 4              ; size_bits += 4
            jmp     fp_RX_shared        ; tail-call to setup enc_fst and numbytes

; finalize_encoding
;   r0: first byte
;   r1: second byte
;   r2: number of bytes to advance the program counter by
;   r5: &static_data
;   top of stack: return address. For 'finalize_encoding_stdcall', this should be in r7.
; returns
;   r5: &static_data
; Does not clobber r3 or r4.
;
; This is the main workhorse of the assembler. It places the encoded
; (or partially encoded, if a label is unavailable) instruction in its place in
; user-program memory and bumps the program counter.
;
; **All complete paths through 'fpsm' return through this function** or
; through asm_directive, now.
;
; Placed somewhat centrally for jump range.
finalize_encoding_stdcall:
            pushd   %ln
finalize_encoding:
            ldd     %r7, %bp            ; r7 = iloc = static_data->asm_ip
            addd    %r2, %r7            ; r2 = iloc + numbytes
            std     %r2, %bp            ; static_data->asm_ip += numbytes
            sth     %r0, %r7            ; *iloc = first byte
            addd    %r7, 1              ; iloc + 1
            sth     %r1, %r7            ; *(iloc + 1) = second byte
            popd    %ln
            ret


; fp_R
; Handles instructions with one register operand.
fp_R:
            cmph    %r2, 12             ; opc == 12?
            jne     fp_R_push           ; if not, encode a push
            movh    %r1, 6              ; otherwise, encode a pop
            jmp     fp_RR               ; tail-call
fp_R_push:
            movh    %r1, %r0            ; regR = regL
            movh    %r0, 6              ; regL = 6
            jmp     fp_RR               ; tail-call

; fp_I
; Handles instructions with one immediate operand (push u5)
fp_I:
            movh    %r0, 6              ; regL = 6
            jmp     fp_RI               ; tail-call

fp_LM:
            testd   %r4, -1             ; test name
            mov     %r2, 0              ; arg 2 <- false [long_mov doesn't need nops]
            jz      assemble_long_mov   ; if it's null, dispatch immediately (tail call)
            movh    %r2, %r0            ; r2 = reg
            movd    %r0, %r4            ; arg 0 = name
            call    fp_get_symbol       ; lookup the symtab entry for name
                                        ; clobbers(r1, r3)
            testd   %r0, -1             ; test it
            jnz     fp_LM_have_entry    ; if it's not null, rearrange args and go
            movh    %r0, -3             ; otherwise, set up to defer
            movh    %r1, %r2            ; arg 1 = reg
            movx    %r2, 14             ; numbytes = 14
            jmp     finalize_encoding   ; tail-call
fp_LM_have_entry:
            call    ste_get_payload     ; r0 <- payload from entry in r0
            movd    %r1, %r0            ; arg 1 = imm
            movh    %r0, %r2            ; arg 0 = reg
            mov     %r2, 0              ; arg 2 = false [long move doesn't need nops]
            jmp     assemble_long_mov
        ; we used to tail fall-through to assemble_long_mov
        ; but since this version of the function is much bigger,
        ; it has to move out of the way. Now we tail-call.
        ; that jmp could be a call if needed.

; placement up here used to matter but doesn't anymore.
fp_LJ_good_payload:
            call    ste_get_payload     ; arg 0 = entry->payload
            mov     %r1, 30             ; get 30 for comparison
            cmph    %r2, %r1            ; opc == 30?
            ldd     %r1, %bp            ; arg 1 = static_data->asm_ip
            je      fp_call_L           ; if opc == 30, go to call_L
            jmp     fp_jump_L           ; otherwise, to jump_L

; fp_LJ
; Handles labeled jump instructions
fp_LJ:
            cmph    %r2, 15             ; opc >? 15
            jbe     fp_LJ_good_opc      ; if no, we have a jump which is valid
            mov     %r0, 30             ; get 30 for comparison
            cmph    %r2, %r0            ; opc == 30?
            je      fp_LJ_good_opc      ; if yes, opcode is good
            call    fpsm_reject         ; if no, reject
                                        ; inverting the je to do a conditional tail call
                                        ; is out of range by quite a margin.
fp_LJ_good_opc:
            movd    %r0, %r4            ; arg 0 = name
            call    fp_get_symbol       ; r0 = entry for name in symtab
                                        ; clobbers(r1, r3)
            testd   %r0, -1             ; test the entry pointer
            jnz     fp_LJ_good_payload  ; if it's not NULL, dispatch to {call/jump}_L
            movh    %r0, %r2            ; arg 0 = opc
            mov     %r1, -1             ; arg 1 = -1
            mov     %r2, 2              ; numbytes = 2
            jmp     finalize_encoding   ; tail-call

; assemble_long_mov
;   r0: dst register
;   r1: immediate value
;   r2: pass [0=>pass1, 1=>pass2]
;   r5: &static_data
;   top of stack: return address (will be popped)
; returns
;   r5: &static_data
;
; Assemble a long move into the code segment. Returns to the address on top of the stack.
assemble_long_mov:
        ; calling fp_RI will clobber r0-r3. Take care!
        ; this means r4 is our only register safe from clobbers.
        ; because our stack pointer needs to stay aligned for those calls,
        ; we push each piece of 5 bit data as a full 32-bit value.
        ; this way, we can save values across calls without worrying about
        ; where in the array we are.
            pushd   %r0                 ; cache all our arguments on the stack.
            pushd   %r2                 ; we will retrieve these as needed (painfully).
            pushd   %r1                 ; push imm last because it is also the last bit_group.

            movd    %r0, %r1            ; arg 0 = imm
            movz    %r1, 27             ; arg 1 = 27 (#bits to preserve)
            call    shr5
            pushd   %r0                 ; groups[5] = imm >> 5

            movz    %r1, 22
            call    shr5
            pushd   %r0                 ; groups[4] = groups[5] >> 5

            movz    %r1, 17
            call    shr5
            pushd   %r0                 ; groups[3] = groups[4] >> 5

            movz    %r1, 12
            call    shr5
            pushd   %r0                 ; groups[2] = groups[3] >> 5

            movz    %r1, 7
            call    shr5
            pushd   %r0                 ; groups[1] = groups[2] >> 5

            movz    %r1, 2
            call    shr5                ; r0 = groups[1] >> 5 (2 bits)
            xord    %r0, 2              ; this xor-sub sequence performs
            subd    %r0, 2              ; sign-extension from 2 bits!
            pushd   %r0                 ; groups[0] = sext(groups[1] >> 5, from 2)

            ; so now groups are at the top of the stack, so that groups[n] is at sp+4*n
            ; so to compare group to 6 such as the C code, we want to compare
            ; %r4 to 6*4 = 24 here.
            mov     %r4, 0              ; group = 0 [0*4], in r4 where it won't get clobbered.

            ; reload imm, it is at %sp + 24
            mov     %r0, 24
            addd    %r0, %sp            ; r0 = &imm
            ldd     %r0, %r0            ; r0 = imm
            cmpd    %r0, 0              ; compare imm against 0
            mov     %r0, 24             ; retrieve 28 in r0, for comparisons later.
            jge     alm_pos_check       ; go to the positive loop if its positive
                                        ; otherwise, to the negative loop

            ; we store groups[group+1] in %r3, then copy it down to %r2 and load the next one
            ; in the loop check. This trick is known as 'predictive commoning.'
            mov     %r3, %r4            ; copy group-idx to r3
            addd    %r3, %sp            ; &groups[group]
            ldd     %r3, %r3            ; groups[group]
            jmp     alm_neg_check
alm_neg_loop:
            addx    %r4, 4              ; group += 1
alm_neg_check:
            movd    %r2, %r3            ; copy-down the predictive group
            mov     %r3, %r4            ; copy group
            addx    %r3, 4              ; group + 1
            addd    %r3, %sp            ; &groups[group+1]
            ldd     %r3, %r3            ; groups[group+1]
            cmpx    %r4, %r0            ; compare group-idx against 24
            jae     alm_neg_mov         ; if it's not below, exit the loop
            movz    %r1, 0x1F           ; r1 = 1F, nothing magic here
            andh    %r2, %r1            ; groups[group] & 0x1F
            cmph    %r2, %r1            ; groups[group] & 0x1F ==? 0x1F
            jne     alm_neg_mov         ; exit the loop if not equal,
                                        ; that means the group is not all 1s
            mov     %r1, 0x10           ; but we also have to exit if the next group
                                        ; doesn't start with 1. prep to check that.
            testh   %r3, %r1            ; is the first bit of the next group on?
            jnz     alm_neg_loop        ; if yes, loop.
alm_neg_mov:
            ; r2 has groups[group], still.
            ; we have to recover reg from the stack though. It's at %sp+32.
            mov     %r0, 32
            addd    %r0, %sp            ; &reg
            ldd     %r0, %r0            ; arg 0 = reg
            mov     %r1, %r2            ; arg 1 = groups[group]. fp_RI will & with 31 for us.
            mov     %r2, 9              ; arg 2 = movs opcode
            mov     %r3, 2              ; arg 3 = dword size bits
            call    fp_RI_stdcall
            jmp     alm_check_pass      ; we're done skipping groups. Insert nops?

alm_pos_loop:
            ; the positive loop is simpler. It always loads groups[group]
            ; to make sure it is available outside the loop, but doesn't need commoning.
            addx    %r4, 4              ; group += 1
alm_pos_check:
            mov     %r2, %r4            ; copy group-idx
            addd    %r2, %sp            ; &groups[group]
            ldd     %r2, %r2            ; groups[group]
            cmpx    %r4, %r0            ; compare group-idx against 24
            jae     alm_pos_mov         ; if not below, exit the loop
            cmpd    %r2, 0              ; groups[group] ==? 0
            je      alm_pos_loop        ; if yes, loop
alm_pos_mov:
            ; restore reg from %sp+32 just like the neg_mov case. r2 has groups[group].
            mov     %r0, 36
            addd    %r0, %sp            ; &reg
            ldd     %r0, %r0            ; arg 0 = reg
            mov     %r1, %r2            ; arg 1 = groups[group]. fp_RI will & with 31
            mov     %r2, 8              ; arg 2 = movz opcode
            mov     %r3, 2              ; arg 3 = dword size bits
            call    fp_RI_stdcall

alm_check_pass:
            ; retrieve pass from the stack (%sp+28). If it's on, insert nops.
            ; fp_jump_L_stdcall clobbers r0-r2, but not r3 or r4.
            mov     %r0, 28
            addd    %r0, %sp            ; &pass
            ldd     %r0, %r0            ; pass
            testh   %r0, -1             ; if pass is zero, skip nops
            jz      alm_slo_check

            mov     %r3, 0              ; group is initially 0 and goes up by 4,
            jmp     alm_nop_check       ; so we have to match that for nop_count
alm_nop_loop:
            mov     %r0, 0
            mov     %r1, 0              ; arg 0 = arg 1 = 0. Jump disp will be 0.
            mov     %r2, 15             ; arg 2 = NEVER cond code. canonical nop
            call    fp_jump_L_stdcall
            addx    %r3, 4              ; nop_count++
alm_nop_check:
            cmpx    %r3, %r4            ; nop_count <? group
            jb      alm_nop_loop        ; loop if below

            jmp     alm_slo_check       ; enter the slo-making loop
alm_slo_loop:
            addx    %r4, 4              ; group += 1
            ; restore reg from %sp+32, groups[group] from %sp+r4
            mov     %r0, 32
            addd    %r0, %sp            ; &reg
            ldd     %r0, %r0            ; arg 0 = reg
            mov     %r1, %r4            ; r1 = group-idx
            addd    %r1, %sp            ; r1 = &groups[group]
            ldd     %r1, %r1            ; arg 1 = groups[group]
            mov     %r2, 12             ; arg 2 = slo opcode
            mov     %r3, 2              ; arg 3 = dword size bits
            call    fp_RI_stdcall
alm_slo_check:
            mov     %r0, 24
            cmpx    %r4, %r0            ; group-idx <? 24 [group <? 6]
            jb      alm_slo_loop        ; if yes, keep going.

            ; otherwise, we're finally done with this function. Unwind the stack
            ; (9 pushes) by adding 36 to %sp. Then pop our return address.
            addd    %sp, 12
            addd    %sp, 12
            addd    %sp, 12             ; %sp += 36. Same instr count as mov ?,36;add.
            popd    %ln
            ret

;;; ********************************* STATE MACHINE ********************************

; fpsm
; Short for "first pass state machine"
;   r5: pointer to static_data
; returns
;   r5: pointer to static_data
;   static_data.save_cur is the last read character
; Clobbers everything except r5 :)

; design remarks:
;   this function always either crashes with an error or returns through finalize_encoding.
;       It can also return through asm_directive, which behaves the same.
;   We put our return address on the stack and don't restore it; finalize_encoding
;   will do that if it gets there.
;   The different cases are implemented with a jump table.
;   The lexing functions all clobber at most r0 and r1, and update r5 coherently.
;   That gives us r2-r4 as allocated registers, as well as r7 as a volatile temp.

; register map:
;   r0: volatile
;   r1: volatile. Across loop iteration boundaries, holds current state.
;   r2: regL
;   r3: imm/regR (shared, see comments in the C code)
;   r4: symbolptr. Sometimes a reload slot for opcode when available.
;       cur also hides here if r5 is needed to call fp_get_symbol.
;   r5: cur, after possibly reading label. &static_data before then.
;   r6: stack pointer
;   r7: volatile
; stack map (starting at 0xFFFC which may not be the real address!)
;   0xFFFC   |   return address   |
;   ---------|--------------------|
;   0xFFF8   |    &static_data    |
;   ---------|--------------------|
;   0xFFF4   |      size_bits     |
;   ---------|--------------------|
;   0xFFF0   |        opcode      |  <--- %sp
;   ---------|--------------------|
fpsm:
            pushd   %ln
            pushd   %r5
            ldd     %r3, %r5            ; r3 = static_data->asm_ip
            ldh     %r5, STREAM         ; initialize reader
            call    cur_is_alpha        ; r0 = is_alpha(cur)
            testh   %r0, -1             ; test is_alpha(cur)
            jz      fpsm_0_notalpha     ; branch past name read if not name start
            call    read_name           ; r0 = pointer to read-in name
            movh    %r4, %r5            ; stash cur in r4
            ldd     %r5, %sp            ; temporarily reload &static_data
            movd    %r1, %r3            ; r1 = static_data->asm_ip
            call    ste_attach_payload  ; add this entry to the symbol table
            movh    %r5, %r4            ; restore cur to r5
            mov     %r0, 58             ; setup 58 == ':' for comparison
            call    match               ; cur == ':'?
            testh   %r0, -1             ; test result
            jne     fpsm_reject         ; reject with syntax error if cur != ':'
fpsm_0_notalpha:
            mov     %r0, 46             ; setup '.' for comparison
            cmph    %r5, %r0            ; cur ==? '.'
            je      fpsm_process_directive ; if yes, process a directive. That will return from fpsm.
            mov     %r1, 1              ; state = 1
            jmp     fpsm_iterate        ; step the loop
fpsm_process_directive:
            ldh     %r5, STREAM         ; cur = getchar(), step past '.'
            call    read_name           ; r0 = direc = read_name()
            movd    %r2, %r0            ; stash direc somewhere that skip_whitespace won't clobber it
            call    skip_whitespace     ; skip_whitespace()
            movd    %r0, %r2            ; arg 0 = direc
            popd    %r2                 ; arg 2 = &static_data, popping off our stack so that
                                        ; now our return address is on top.
            call    asm_directive       ; tail-call asm_directive. It returns to our caller.

fpsm_1:                                 ; switch case 1
            call    cur_is_eol          ; r0 = is_eol(cur)
            testh   %r0, -1             ; test result
            jnz     fpsm_1_accept       ; accept if is_eol(cur)
            mov     %r0, 46             ; setup '.' for comparison
            cmph    %r5, %r0            ; cur ==? '.'
            je      fpsm_process_directive ; if equal, process a directive instead.
            call    read_opcode         ; r0 = rop.opcode, r1 = rop.state
            movh    %r4, %r0            ; temporarily save the opcode in r4
            movh    %r3, %r1            ; temporarily save the target state in r3
            call    read_size           ; r0 = size_bits
            pushd   %r0                 ; put size_bits in their stack slot
            pushd   %r4                 ; put opcode into its stack slot
            movh    %r1, %r3            ; re-place the state in r1
            jmp     fpsm_iterate        ; break
fpsm_1_accept:
            popd    %r4                 ; restore static_data pointer
            addd    %r4, EOL_CHAR_OFS   ; &static_data.eol_char
            sth     %r5, %r4            ; static_data->eol_char = cur
            subd    %r4, EOL_CHAR_OFS   ; undo offset
            movd    %r5, %r4            ; move pointer back where it belongs
            popd    %ln
            ret

fpsm_2:
            mov     %r0, 37             ; r0 = '%' to check for register
            cmph    %r5, %r0            ; cur == '%'?
            jne     fpsm_2_imm          ; if not equal, try checking immediate
            call    read_register       ; if yes equal, read a register
            movh    %r2, %r0            ; regL = read_register()
            mov     %r1, 12             ; state = 12
            jmp     fpsm_iterate        ; break
fpsm_2_imm:
            call    cur_is_imm_start    ; r0 = is_imm_start(cur)
            testh   %r0, -1             ; test is_imm_start(cur)
            jz      fpsm_reject         ; if !is_imm_start(cur), this state rejects
            call    read_immediate      ; otherwise, read the immediate
            movz    %r1, 31             ; validate_u5 in %r0; see 'validate_u5' below
            cmpd    %r0, %r1            ; set 'be' condition if imm is valid
            ja      fpsm_invalid_imm    ; if not 'be' condition, imm is invalid. Die.
            movx    %r3, %r0            ; imm = read & validated immediate
            mov     %r1, 13             ; state = 13
            jmp     fpsm_iterate        ; break

fpsm_3:
            mov     %r0, 37             ; r0 = '%' to check for register
            cmph    %r5, %r0            ; cur == '%'?
            jne     fpsm_3_label        ; if not equal, try checking label
            call    read_register       ; if yes equal, read a register
            movh    %r2, %r0            ; regL = read_register()
            mov     %r1, 14             ; state = 14
            jmp     fpsm_iterate        ; break
fpsm_3_label:
            call    cur_is_alpha        ; r0 = is_alpha(cur)
            testh   %r0, -1             ; test is_alpha(cur)
            jz      fpsm_reject         ; if !is_alpha(cur), this state rejects
            call    read_name           ; r0 = read_name()
            movd    %r4, %r0            ; symbolptr = read_name()
            mov     %r1, 15             ; state = 15
            jmp     fpsm_iterate        ; break

fpsm_4:
            mov     %r0, 37             ; r0 = '%' to check for register
            cmph    %r5, %r0            ; cur == '%'?
            jne     fpsm_reject         ; if not a register, this state rejects
            call    read_register       ; r0 = read_register()
            movh    %r2, %r0            ; regL = read_register()
            mov     %r1, 12             ; state = 12
            jmp     fpsm_iterate        ; break

fpsm_5:
            mov     %r0, 37             ; r0 = '%' to check for register
            cmph    %r5, %r0            ; cur == '%'?
            jne     fpsm_reject         ; if not a register, this state rejects
            call    read_register       ; r0 = read_register()
            movh    %r2, %r0            ; regL = read_register()
            mov     %r1, 6              ; state = 6
fpsm_scan_comma:
            call    skip_whitespace     ; skip whitespace between reg and comma
            mov     %r0, 44             ; r0 = ',' to check
            call    match               ; r0 = (cur != ',')
            testh   %r0, -1             ; test (cur != ',')
            jnz     fpsm_reject         ; if it's not a comma, that's an error
            jmp     fpsm_iterate        ; break

fpsm_reject:
            mov     %r0, 0              ; r0 = INVALID_SYNTAX_CODE
            call    die
fpsm_invalid_imm:
            mov     %r0, 2              ; r0 = INVALID_IMMEDIATE_CODE
            call    die

    ; this is placed somewhat centrally to maximize the coverage of its jump range.
    ; The only jump _out_ is via a register, but several places need to jump _in_.
fpsm_iterate:
            call    skip_whitespace
            cmph    %r1, 10             ; compare state to 10
            ja      fpsm_eol            ; if bigger, go to the eol+accept check
            call    fpsm_iterate_2      ; put the address of the action table in r7
            ; all of these pointers are guaranteed to be > 0xFFFF8000,
            ; aka 16 bits is enough to represent them. We need to sign extend them manually.
fpsm_action_table:
            .word   fpsm_reject & 0xFFFF
            .word   fpsm_1 & 0xFFFF
            .word   fpsm_2 & 0xFFFF
            .word   fpsm_3 & 0xFFFF
            .word   fpsm_4 & 0xFFFF
            .word   fpsm_5 & 0xFFFF
            .word   fpsm_6 & 0xFFFF
            .word   fpsm_7 & 0xFFFF
            .word   fpsm_8 & 0xFFFF
            .word   fpsm_9 & 0xFFFF
fpsm_iterate_2:
            addh    %r1, %r1            ; state *= sizeof(word)
            addd    %r1, %r7            ; r1 = pointer to pointer switch case
            ldx     %r1, %r1            ; r1 = pointer to switch case (16 bit)
            movsx   %r1, %r1            ; r1 = sext16(r1)
            jmp     %r1                 ; follow the yellow brick road

fpsm_6:
            ldh     %r4, %sp            ; r4 = opc, bottom stack slot
            mov     %r0, 37             ; r0 = '%' to check for register
            cmph    %r5, %r0            ; cur == '%'?
            jne     fpsm_6_imm          ; if not a register, try checking immediate
            cmph    %r4, 12             ; opc == OPC_SLO?
            je      fpsm_reject         ; this state rejects OPC_SLO
            call    read_register       ; r0 = read_register()
            movh    %r3, %r0            ; regR = read_register()
            mov     %r1, 16             ; state = 16
            jmp     fpsm_iterate        ; break
fpsm_6_imm:
            call    cur_is_imm_start    ; r0 = is_imm_start(cur)
            test    %r0, -1             ; test is_imm_start(cur)
            jz      fpsm_6_symbol       ; if not, we still must check for .set symbols
            call    read_immediate      ; r0 = read_immediate()
fpsm_6_validate_imm:
            cmph    %r4, 10             ; opc >= 10?
            jae     fpsm_6_u5           ; if yes, validate unsigned
            cmph    %r4, 8              ; opc == 8?
            je      fpsm_6_u5           ; if yes, validate unsigned
fpsm_6_s5:
            call    validate_s5         ; r0 unchanged, flags set 'b' if valid
            jae     fpsm_invalid_imm    ; if not 'b' condition, imm is invalid. Die.
            jmp     fpsm_6_end          ; clean up
fpsm_6_u5:
            movz    %r1, 31             ; validate_u5 in %r0; see 'validate_u5' below
            cmpd    %r0, %r1            ; set 'be' condition if imm is valid
            ja      fpsm_invalid_imm    ; if not 'be' condition, imm is invalid. Die.
fpsm_6_end:
            movx    %r3, %r0            ; It's valid. Save it: imm = r0
            mov     %r1, 17             ; state = 17
            jmp     fpsm_iterate        ; break
fpsm_6_symbol:
            call    cur_is_alpha        ; r0 = is_alpha(cur)
            testh   %r0, -1             ; if it's not, this state is out of options and rejects
            jz      fpsm_reject
            call    read_name           ; r0 = read_name()
            movh    %r4, %r5            ; hide cur in %r4
            mov     %r5, 8              ; offset of stack slot for &static_data
            addd    %r5, %sp
            ldd     %r5, %r5            ; r5 = &static_data
            call    fp_get_symbol       ; clobbers r1 and r3. nothing in r3 (yet). r2 has regL
            movh    %r5, %r4            ; return cur to %r5
            call    sp_get_symbol       ; r0 = payload from entry if it's valid.
            jmp     fpsm_6_validate_imm ; validate that immediate.

fpsm_7:
            mov     %r0, 37             ; r0 = '%' to check for register
            cmph    %r5, %r0            ; cur == '%'?
            jne     fpsm_reject         ; if not register, this state rejects
            call    read_any_register   ; r0 = read_any_register()
            movh    %r2, %r0            ; regL = read_any_register()
            cmph    %r2, 8              ; regL <? 8
            mov     %r1, 8              ; state = 8
            jb      fpsm_scan_comma     ; if regL < 8, scan comma
            mov     %r1, 9              ; otherwise, state = 9
            jmp     fpsm_scan_comma     ; then scan comma

fpsm_8:
            mov     %r0, 37             ; r0 = '%' to check for register
            cmph    %r5, %r0            ; cur == '%'?
            jne     fpsm_8_imm          ; if not register, try immediate
            call    read_any_register   ; r0 = read_any_register()
            movh    %r3, %r0            ; regR = read_any_register()
            cmph    %r3, 8              ; regR <? 8
            jge     fpsm_8_ctrl_reg     ; if regR >= 8, it's a control reg
            mov     %r1, 16             ; state = 16
            jmp     fpsm_iterate        ; break
fpsm_8_ctrl_reg:
            subh    %r3, 8              ; imm = regR - 8
            addd    %sp, 4              ; pop opc off the stack
            pushd   14                  ; overwrite opc with 14
            mov     %r1, 17             ; state = 17
            jmp     fpsm_iterate        ; break
fpsm_8_imm:
            call    cur_is_imm_start    ; r0 = is_imm_start(cur)
            testh   %r0, -1             ; test is_imm_start(cur)
            jz      fpsm_8_label        ; if not an imm, try label
            call    read_immediate      ; r0 = read_immediate()
            call    validate_s5         ; set 'b' if r0 is a valid s5
            mov     %r1, 17             ; state = 17
            movd    %r3, %r0            ; imm = read_immediate()
            jb      fpsm_iterate        ; break, if imm is a valid s5
            ; otherwise, imm is a 32-bit number, and always valid.
            mov     %r4, 0              ; symbolptr = NULL
            mov     %r1, 18             ; state = 18
            jmp     fpsm_iterate        ; break
fpsm_8_label:
            call    cur_is_alpha        ; r0 = is_alpha(cur)
            testh   %r0, -1             ; test is_alpha(cur)
            jz      fpsm_reject         ; if !is_alpha(cur), finally this state rejects.
            call    read_name           ; r0 = read_name()
            movd    %r4, %r0            ; symbolptr = read_name()
            mov     %r1, 18             ; state = 18
            jmp     fpsm_iterate        ; break

fpsm_9:
            mov     %r0, 37             ; r0 = '%' to check for register
            cmph    %r5, %r0            ; r0 == '%'?
            jne     fpsm_reject         ; if not a register, this state rejects
            movh    %r3, %r2            ; imm = regL
            subh    %r3, 8              ; imm -= 8
            call    read_register       ; r0 = read_register()
            movh    %r2, %r0            ; r2 = read_register()
            addd    %sp, 4              ; pop opc off the stack
            pushd   15                  ; overwrite opc with 15
            mov     %r1, 17             ; state = 17
            jmp     fpsm_iterate

fpsm_eol:
            call    cur_is_eol          ; r0 = is_eol(cur)
            testh   %r0, -1             ; test is_eol(cur)
            jz      fpsm_reject         ; if it's not eol (somehow?) reject!
fpsm_accept:
            mov     %r7, 8              ; offset of &static_data on the stack
            addd    %r7, %sp            ; point at stack slot of &static_data
            ldd     %r7, %r7            ; r7 = &static_data
            addd    %r7, EOL_CHAR_OFS   ; r7 = &static_data.eol_char
            sth     %r5, %r7            ; static_data->eol_char = cur
            movh    %r5, %r1            ; r5 = state, temporarily
            movh    %r0, %r2            ; arg 0 = regL
            movx    %r1, %r3            ; arg 1 = regR/imm
            popd    %r2                 ; arg 2 = opcode
            popd    %r3                 ; arg 3 = size_bits
                                        ; arg 4 is already symbolptr
            call    fpsm_accept_exit    ; get the address of the table into r7
fpsm_accept_jump_table:
            ; to make the kernel assemble itself, comment out the &... that etc-as needs.
            .word   fp_0  & 0xFFFF
            .word   fp_R  & 0xFFFF
            .word   fp_I  & 0xFFFF
            .word   fp_RJ & 0xFFFF
            .word   fp_LJ & 0xFFFF
            .word   fp_RR & 0xFFFF
            .word   fp_RI & 0xFFFF
            .word   fp_LM & 0xFFFF
fpsm_accept_exit:
            subh    %r5, 11             ; offset = state - 11
            addh    %r5, %r5            ; offset *= sizeof(word)
            addd    %r7, %r5            ; r7 = pointer to address to jump to
            ldx     %r7, %r7            ; r7 = address to jump to (16 bit)
            movsx   %r7, %r7            ; r7 = full address to jump to (32-bit)
            popd    %r5                 ; r5 = &static_data. Hooray!
            jmp     %r7                 ; tail-call the assembling function
                                        ; with its return address on top-of-stack.

;;; stub functions for die, somewhat central since die is at the end
;;; but these are called from like, everywhere.
;;; fpsm_reject is also effectively a stub.
die_out_of_range:
            mov     %r0, 3              ; OUT_OF_RANGE_CODE
            call    die
die_missing_feature:
            mov     %r0, 5              ; missing feature code
            call    die
die_unknown_symbol:
            mov     %r0, 6              ; unknown symbol code
            call    die

; we need this basically everywhere, so put it centrally.
; strncmp
;   r0: const char *a
;   r1: const char *b
;   r2: int16_t     n
; returns:
;   r0: 0 if strings at *a and *b compare equal, nonzero otherwise
;   r1: b + however many characters were compared
;   r2: n - however many characters were compared
; clobbers: r0, r1, r2
; r3-r7 unchanged
;
; Compare the strings at *a and *b, terminating when they disagree,
; when they have both ended (nul-terminated), or after 'n' characters.
; If you give n as 0, it the first characters will still be compared.
; This saves one instruction byte in the implementation.
;
; A result of the way %r1 and %r2 are handled is that after the function
; returns, it is guaranteed that %r1 + %r2 will give the same result as
; it would have given before the strncmp call. This can be used to avoid
; saving the second argument to the stack.
strncmp:
            pushd   %r3             ; wind stack, giving two free registers
            pushd   %r4             ; which we will use to hold *a and *b
strncmp_L1:                         ; top of loop
            ldh     %r3, %r0        ; r3 = *a
            ldh     %r4, %r1        ; r4 = *b
            subh    %r4, %r3        ; subtract *a from *b
            jne     strncmp_L2      ; return if *a != *b
            testh   %r3, -1         ; test *a
            jz      strncmp_L2      ; also return if *a == 0 (note *b - *a still in %r4)

            addd    %r0, 1          ; ++a
            addd    %r1, 1          ; ++b
            subd    %r2, 1          ; --n
            ja      strncmp_L1      ; if n is > 0 (unsigned), loop
strncmp_L2:                         ; return label
            movh    %r0, %r4        ; return value is *b - *a
            popd    %r4             ; unwind stack
            popd    %r3
            ret

;;; ********************************* DIRECTIVES ***********************************

; encode_value
;   r0: value
;   r1: numbytes, must be 1, 2, 3, or 4.
;   r2: &static_data (hottest call site has cur in r5)
; returns:
;   nothing
; clobbers r0 and r1. &static_data will still be in r2.
encode_value:
            pushd   %ln
encode_value_stkret:
            ; use r7 as a scratch register, holding iloc
            ldd     %ln, %r2            ; iloc = static_data->asm_ip
            pushd   %r0                 ; put value on the stack so we can pop one byte at a time
encode_value_loop:
            poph    %r0                 ; pop 1 byte of the value
            sth     %r0, %ln            ; *iloc = *val
            addd    %ln, 1              ; iloc++
            subh    %r1, 1              ; numbytes--
            jnz     encode_value_loop   ; if numbytes is now 0, we're done. Owise loop
            addd    %sp, 3
            andd    %sp, -4             ; re-align the stack pointer
            std     %ln, %r2            ; static_data->asm_ip = iloc
            popd    %ln
            ret

; set_directive
;   r2: &static_data
;   r5: cur
; returns
;   r5: cur
; no clobbers

set_directive:
            pushd   %ln
            pushd   %r0                 ; skip_whitespace clobbers this
            pushd   %r1                 ; is_alpha clobbers this
            pushd   %r2                 ; ste_attach_payload clobbers this
            pushd   %r3                 ; ste_attach_payload clobbers this
            call    cur_is_alpha        ; r0 = boolean cur is alpha?
            testh   %r0, -1             ; if it is not (r0 == 0), reject
            jz      set_directive_reject
            call    read_name_with_sd   ; read a name, &static_data is still in r2
            pushd   %r0                 ; and immediately save it on the stack
            call    skip_whitespace     ; skip whitespace between name and value
            call    cur_is_imm_start    ; check syntax: next character starts imm?
            testh   %r0, -1             ; if it's not (r0 == 0), reject
            jz      set_directive_reject
            call    read_immediate      ; read a number
            pushd   %r0                 ; and immediately save it on the stack
            call    skip_whitespace     ; read to end-of-line (hopefully)
            call    cur_is_eol          ; check syntax: at the end of line?
            testh   %r0, -1             ; if not, reject
            jz      set_directive_reject

            popd    %r1                 ; pop the number we read to arg 1
            popd    %r0                 ; pop the name we read to arg 0
            call    ste_attach_payload  ; attach the value to that name
            ; we're done, unwind the stack and return
            popd    %r3
            popd    %r2
            popd    %r1
            popd    %r0
            popd    %ln
            ret
set_directive_reject:
            call    fpsm_reject

; value_directive
;   r0: byte_size
;   r2: &static_data
;   r5: cur
; returns
;   r2: still &static_data
;   r5: new cur
; clobbers whatever.
value_directive:
        ; in particular all the is_X clobber r1, read_immediate too.
        ; same story for read_name.
            pushd   %ln
            movh    %r4, %r0            ; save byte_size in %r4, which nothing clobbers.
            jmp value_directive_loop    ; enter loop without skipping whitespace
value_directive_skip_ws:
            call    skip_whitespace
value_directive_loop:
            call    cur_is_imm_start    ; can cur start an immediate?
            testh   %r0, -1             ; check result
            jz      value_directive_try_name ; if not, try reading a name
            call    read_immediate      ; read an immediate into r0 = arg 0
            movh    %r1, %r4            ; arg 1 = byte_size
            call    encode_value        ; arg 2 is still static_data
            jmp     value_directive_skip_ws
value_directive_try_name:
            call    cur_is_alpha        ; can cur start a name?
            testh   %r0, -1             ; check result
            jz      value_directive_try_eol ; if not, ensure we're at EOL
            call    read_name_with_sd   ; we do have &static_data in r2
            pushd   %r5                 ; save cur, fp_get_symbol needs static data in r5
            movd    %r5, %r2            ; setup for fp_get_symbol
            ; from this point until we loop, static_data is in r5 instead of r2!
            call    fp_get_symbol       ; clobbers %r1 and %r3, which we're not using
            testd   %r0, -1             ; is the entry NULL?
            jz      value_directive_no_entry ; if yes, prepare the relocation.
            call    ste_get_payload     ; arg 0 = entry->payload
            movh    %r1, %r4            ; arg 1 = byte_size
            movd    %r2, %r5            ; arg 2 = &static_data
            popd    %r5                 ; restore cur to r5
            call    encode_value
            jmp     value_directive_skip_ws
value_directive_no_entry:
            ; static_data is in r5 right now, which finalize_encoding wants.
            ; finalize_encoding clobbers its arguments (r0,r1,r2).
            movh    %r0, %r4            ; r0 = byte_size
            rsubh   %r0, 0              ; arg 0 = 0 - byte_size
            mov     %r1, 0              ; arg 1 = 0 [according to the C code, this value shouldn't matter]
            movh    %r2, %r4            ; arg 2 = byte_size
            call    finalize_encoding_stdcall
            movd    %r2, %r5            ; return &static_data to r2
            popd    %r5                 ; restore cur to r5 off the stack
            jmp     value_directive_skip_ws
value_directive_try_eol:
            call    cur_is_eol          ; is cur end-of-line?
            testh   %r0, -1             ; check result
            jnz     value_directive_ret ; if yes, return. yay!
            call    fpsm_reject         ; otherwise reject the program.
value_directive_ret:
            popd    %ln
            ret

; align_directive
;   r2: &static_data
;   r5: cur
; returns:
;   r2: still &static_data
;   r5: new cur
; clobbers anything else.
align_directive:
            pushd   %ln
            call    cur_is_num          ; can cur start a POSITIVE number?
            testh   %r0, -1
            jz      align_directive_reject ; if not, reject the program
            call    read_immediate      ; r0 = byte_size from read_immediate
            movd    %r3, %r0            ; move it to r3. Move the full 32-bit value
                                        ; to ensure we reject the program if it's large.
            call    skip_whitespace     ; skip whitespace after the number
            call    cur_is_eol          ; are we at end-of-line?
            testh   %r0, -1
            jz      align_directive_reject ; if not, reject the program.

            cmpd    %r3, 1              ; is byte_size 1?
            je      align_directive_ok  ; if yes, acceptable
            cmpd    %r3, 2
            je      align_directive_ok  ; 2 is also acceptable
            cmpd    %r3, 4
            je      align_directive_ok  ; and finally, so is 4.
align_directive_reject:
            call    fpsm_reject
align_directive_ok:
            ldd     %r0, %r2            ; r0 = ip = static_data->asm_ip
            ; align-up ip by doing:
            ; ip = (ip + byte_size - 1) & (-byte_size)
            addd    %r0, %r3            ; ip += byte_size
            addd    %r0, -1             ; ip -= 1
            rsubh   %r3, 0              ; -byte_size
            andd    %r0, %r3            ; ip &= -byte_size
            std     %r0, %r2            ; static_data->asm_ip = ip
            popd    %ln
            ret

; ascii_directive:
;   r0: add NUL terminator?
;   r2: &static_data
;   r5: cur [if syntax is correct, should be ", we will check that]
; returns:
;   r2: still &static_data
;   r5: new cur
; clobbers anything else.
; The c code has separate 'cur' and 'encode' variables, but if you notice,
; they can share r5 without problems.
ascii_directive:
            mov     %r1, 34             ; '"'
            cmph    %r5, %r1            ; is cur '"' ?
            jne     ascii_directive_reject ; if not, reject the program

            pushd   %ln
            mov     %r4, %r0            ; store add_terminator in r4 until we need to check it
            ldd     %r3, %r2            ; iloc = static_data->asm_ip
            jmp     ascii_directive_check ; enter the loop, don't assume that the string is empty.
ascii_directive_loop:
            call    cur_is_eol          ; is cur an EOL ?
            testh   %r0, -1
            jnz     ascii_directive_reject ; if YES, reject the program
            mov     %r1, 92             ; '\'
            cmph    %r5, %r1            ; cur ==? '\'
            jne     ascii_directive_enc ; if not, encode it directly
            ; otherwise, read the next char and unescape it
            ldh     %r5, STREAM         ; cur = getchar();
            cmph    %r5, %r1            ; new cur == '\' too?
            je      ascii_directive_enc ; if yes, encode a '\'
            mov     %r1, 110            ; 'n'
            cmph    %r5, %r1            ; cur ==? 'n'
            jne     ascii_directive_try_q ; if not, try a quote
            mov     %r5, 10             ; if yes, encode a '\n'
            jmp     ascii_directive_enc
ascii_directive_try_q:
            mov     %r1, 34             ; '"'
            cmph    %r5, %r1            ; cur ==? '"'
            je      ascii_directive_enc ; if yes, encode a '"'
            mov     %r1, 48             ; '0'
            cmph    %r5, %r1            ; cur ==? '0'
            jne     ascii_directive_reject ; if it's not, unknown escape! reject the program.
            mov     %r5, 0              ; but if it is, encode a 0.
ascii_directive_enc:
            sth     %r5, %r3            ; *iloc = encode
            addd    %r3, 1              ; iloc++
ascii_directive_check:
            ldh     %r5, STREAM         ; cur = getchar()
            mov     %r1, 34             ; '"'
            cmph    %r5, %r1            ; cur ==? '"'
            jne     ascii_directive_loop ; if not, string is still going, loop.

            ldh     %r5, STREAM         ; cur = getchar(), advance past the closing "
            call    skip_whitespace     ; read (hopefully) to EOL
            call    cur_is_eol          ; is cur the EOL?
            testh   %r0, -1
            jnz     ascii_directive_nul ; if yes, we can proceed to the terminator check
ascii_directive_reject:                 ; but if not, reject the program.
            call    fpsm_reject
ascii_directive_nul:
            testh   %r4, -1             ; should we add a terminator?
            jz      ascii_directive_done; if not, we can clean up.
            mov     %r1, 0
            sth     %r1, %r3            ; *iloc = 0
            addd    %r3, 1              ; iloc++
ascii_directive_done:
            popd    %ln
            ret

; asm_directive
; Generic dispatch for handling directives.
;   r0: char *directive_name
;   r2: &static_data
;   r5: cur
;   top of stack: return address
; returns:
;   r5: &static data. This is so that fpsm can tail-call this.
; Everything else can be clobbered.
asm_directive:
        ; this is way too hard to implement with a table, and even with the table
        ; we'd still just be doing a linear scan (in a loop). So instead we'll just
        ; write out that linear scan.
            pushd   %r0                 ; save directive_name. Easily retrieved with ldd
            movd    %r3, %r2            ; %r2 is needed for strncmp calls, save in r3
            call    asm_directive_with_strings
        ; what we can do is put all the strings one after the other right here.
        ; Note the invariant of strncmp: no matter how it returns, %r1+%r2 is the same
        ; both before and after. So when checking "set" and 3, for example, we can add
        ; %r2 back into %r1 afterwards and we have our pointer to "half".
        ; We use asciiz to ensure exact matches instead of just prefix matches.
            .asciiz  "set"
            .asciiz  "half"
            .asciiz  "word"
            .asciiz  "dword"
            .asciiz  "align"
            .asciiz  "asciiz"
            .asciiz  "ascii"
            .align  2                   ; re-align for instructions
asm_directive_with_strings:
            movd    %r1, %ln            ; now pointer to "set\0" is in r1
            mov     %r2, 4              ; compare 4 characters
            call    strncmp             ; r0 = 0 if strings are equal
            jne     asm_directive_half  ; if unequal, try half
            movd    %r2, %r3            ; restore &static_data
            call    set_directive
            jmp     asm_directive_end
asm_directive_half:
            ldd     %r0, %sp            ; r0 = directive_name
            addd    %r1, %r2            ; r1 = pointer to "half\0"
            mov     %r2, 5              ; compare 5 characters
            call    strncmp
            jne     asm_directive_word  ; if unequal, try word
            movd    %r2, %r3
            mov     %r0, 1
            call    value_directive
            jmp     asm_directive_end
asm_directive_word:
            ldd     %r0, %sp            ; r0 = directive_name
            addd    %r1, %r2            ; r1 = pointer to "word\0"
            mov     %r2, 5              ; compare 5 characters
            call    strncmp
            jne     asm_directive_dword ; if unequal, try dword
            movd    %r2, %r3
            mov     %r0, 2
            call    value_directive
            jmp     asm_directive_end
asm_directive_dword:
            ldd     %r0, %sp            ; r0 = directive_name
            addd    %r1, %r2            ; r1 = pointer to "dword\0"
            mov     %r2, 6              ; compare 6 characters
            call    strncmp
            jne     asm_directive_align ; if unequal, try align
            movd    %r2, %r3
            mov     %r0, 4
            call    value_directive
            jmp     asm_directive_end
asm_directive_align:
            ldd     %r0, %sp            ; r0 = directive_name
            addd    %r1, %r2            ; r1 = pointer to "align\0"
            mov     %r2, 6              ; compare 6 characters
            call    strncmp
            jne     asm_directive_asciiz; if unequal, try asciiz
            movd    %r2, %r3
            call    align_directive
            jmp     asm_directive_end
asm_directive_asciiz:
            ldd     %r0, %sp            ; r0 = directive_name
            addd    %r1, %r2            ; r1 = pointer to "asciiz\0"
            mov     %r2, 7              ; compare 7 characters
            call    strncmp
            jne     asm_directive_ascii ; if unequal, try ascii
            movd    %r2, %r3
            mov     %r0, 1              ; do include NUL terminator
            call    ascii_directive
            jmp     asm_directive_end
asm_directive_ascii:
            ldd     %r0, %sp            ; r0 = directive_name
            addd    %r1, %r2            ; r1 = pointer to "ascii\0"
            mov     %r2, 6              ; compare 6 characters
            call    strncmp
            jne     asm_directive_reject; if unequal, unknown directive. reject
            movd    %r2, %r3
            mov     %r0, 0              ; do not include NUL terminator
            call    ascii_directive
            jmp     asm_directive_end
asm_directive_reject:
            mov     %r0, 7              ; arg 0 = UNKNOWN_DIRECTIVE
            ldd     %r1, %sp            ; arg 1 = directive_name
            call    die                 ; die unknown directive
asm_directive_end:
            movd    %r0, %r2            ; &static_data
            addd    %r0, EOL_CHAR_OFS   ; &static_data->eol_char
            sth     %r5, %r0            ; static_data->eol_char = cur
            movd    %r5, %r2            ; return &static_data to r5

            addd    %sp, 4              ; pop directive_name
            popd    %ln
            ret

;;; ********************************************************************************
;;; ************************************ LEXER *************************************
;;; ********************************************************************************

; skip_whitespace
;   r5: cur
; returns
;   r5: cur
; Clobbers r0.
skip_whitespace:
            mov     %r0, 32             ; r0 = ' ' for comparison
            jmp     skip_whitespace_L2
skip_whitespace_L1:
            ldh     %r5, STREAM         ; cur = getchar()
skip_whitespace_L2:
            cmph    %r5, %r0            ; r5 ==? 32
            je      skip_whitespace_L1
            cmph    %r5, 9              ; r5 ==? '\t'
            je      skip_whitespace_L1

            mov     %r0, 59             ; r0 = ';'
            cmph    %r5, %r0
            retne                       ; return if cur != ';'
            pushd   %ln
skip_whitespace_L3:
            ldh     %r5, STREAM         ; cur = getchar()
            call    cur_is_eol          ; r0 = is_eol(cur)
            testh   %r0, -1             ; test is_eol(cur)
            jz      skip_whitespace_L3  ; loop as long as is_eol(cur) is false
            popd    %ln
            ret

; read_size
;   r5: cur
; returns
;   r0: size_bits for the previously lexed opcode
;   r5: cur
; Clobbers r1.
;
; Crashes with "invalid syntax" if a valid size_suffix? cannot be read.
read_size:
            pushd   %ln
            call    cur_is_alpha        ; r0 = is_alpha(cur)
            testh   %r0, -1             ; test is_alpha(cur)
            mov     %r0, 1              ; set return value for if !is_alpha(cur)
            jz      read_size_ret
            mov     %r1, 120            ; r1 = 'x'
            subh    %r5, %r1            ; cur = cur - 'x'
            je      read_size_guard
            subh    %r5, -16            ; cur = cur + ('x' - 'h')
            mov     %r0, 0              ; set return value for cur == 'h'
            je      read_size_guard
            addh    %r5, 4              ; cur = cur + ('h' - 'd')
            mov     %r0, 2              ; set return value for cur == 'd'
            jne     read_size_kill      ; not valid suffix if cur != 'd' at this point
read_size_guard:
            pushd   %r0                 ; spill return value
            ldh     %r5, STREAM         ; cur = getchar()
            call    cur_is_alphanum     ; r0 = is_alphanum(cur)
            testh   %r0, -1             ; test is_alphanum(cur)
            jnz     read_size_kill      ; crash if cur is alphanumeric
            popd    %r0                 ; reload return value
read_size_ret:
            popd    %ln
            ret
read_size_kill:
            mov     %r0, 0              ; r0 = INVALID_SYNTAX_CODE
            call    die

; It seems like this is only used by read_immediate.
; shl
;   r0: number to shift
;   r1: amount to shift left
; returns
;   r0: shifted number
;   r1: 0
; All other register are unchanged.
shl_L1:
            addd    %r0, %r0        ; x <<= 1
shl:
            subh    %r1, 1          ; --shamt
            jnn     shl_L1          ; exec loop if --shamt >= 0 === shamt > 0
            ret

; read_immediate
;   r5: cur
; returns
;   r0: int32_t the read immediate
;   r5: cur
; Additionally clobbers r1.
;
; Reads an immediate value from the input stream. Cur must initially be the
; first character of the token, either a number or '-'. Cur will be the first
; unused character afterwards.
read_immediate:
            pushd   %r2                 ; wind
            mov     %r0, 45             ; '-', this mov is 2 instructions
            mov     %r1, 48             ; '0', this mov is also 2 instructions
            rsubh   %r0, %r5            ; r0 = r5 - 45
            pushd   %r0                 ; save the result of this subtraction
            jne     read_immediate_radix; if cur was not '-', skip to hex check
            ldh     %r5, STREAM         ; otherwise, read the first number.
read_immediate_radix:
            movh    %r0, %r5            ; imm = cur
            subh    %r0, %r1            ; imm -= 48 so imm = cur - '0'
            ldh     %r5, STREAM         ; read next char
            jnz     read_immediate_dec_check ; if imm != 0, then old cur != '0', so we don't have hex.
            mov     %r2, 120            ; 'x'
            cmph    %r5, %r2            ; cur ==? 'x'
            jne     read_immediate_dec_check ; if cur != 'x', we don't have hex.
            ; otherwise, we do. We'll getchar() after the jump.
            mov     %r2, %r1            ; hex loop needs r1 to be free, but still wants 48 around.
            pushd   %ln                 ; the hex loop calls shl
            jmp     read_immediate_hex_check 
read_immediate_hex_letter:
            ; here, %r5 should be cur - 'A'
            addh    %r5, 10             ; adjust for 'A' being hex 10
            mov     %r1, 4
            call    shl
            addd    %r0, %r5            ; imm += cur - 'A' + 10
            jmp     read_immediate_hex_check ; continue            
read_immediate_hex_num:
            ; here, %r5 should be cur - '0'
            mov     %r1, 4              ; shift left 4 bits
            call    shl                 ; imm <<= 4
            addd    %r0, %r5            ; imm += cur - '0'
read_immediate_hex_check:
            ldh     %r5, STREAM         ; cur = getchar()
            subh    %r5, %r2            ; cur -= 48
            cmph    %r5, 10             ; cur - '0' <? 10
            jb      read_immediate_hex_num ; if yes, we have a hex number
            ; we have cur - '0', or cur - 48. We want cur - 'A', or cur - 65.
            subh    %r5, 12             ; cur - 60
            subh    %r5, 5              ; cur - 'A'
            cmph    %r5, 6              ; cur - 'A' <? 6
            jb      read_immediate_hex_letter ; if yes we have a hex letter
            popd    %ln                 ; otherwise we're done. Recover %ln
            mov     %r1, 65             ; Overwrite 48 with the amount to adjust cur by.
            jmp     read_immediate_negate 
read_immediate_dec_loop:
            addd    %r0, %r0            ; imm *= 2
            movd    %r2, %r0            ; immx2 = imm
            addd    %r0, %r0            ; imm *= 2 (x4 cumulative)
            addd    %r0, %r0            ; imm *= 2 (x8 cumulative)
            addd    %r0, %r2            ; imm = imm + immx2 (x10 cumulative)
            addd    %r0, %r5            ; imm = imm + cur - 48
            ldh     %r5, STREAM         ; r5 = getchar()
read_immediate_dec_check:
            subh    %r5, %r1            ; r5 = cur - 48
            cmph    %r5, 10             ; compare (cur - 48) to 10
            jb      read_immediate_dec_loop ; loop if 0 <= (cur - 48) < 10
read_immediate_negate:
            addh    %r5, %r1            ; r5 = cur (previously, r5 was adjusted and r1 held the adjustment)
            popd    %r1                 ; retrieve the comparison of initial cur to '-'
            popd    %r2                 ; unwind stack
            testh   %r1, -1             ; test the result of that comparison, zero means equal
            retnz                       ; if it wasn't equal, we're done
            rsubd   %r0, 0              ; otherwise, imm = -imm
            ret                         ; and now we're done.

; read_name
;   r5: cur, which must satisfy is_alpha.
; returns
;   r0: pointer to read name. The string is nul-terminated iff it is less than 16 characters.
;       The returned string *must* be copied if you want it to stick around through lexing
;       another token. Any lexer function may use the buffer.
;   r5: new cur
; Clobbers only r1. Other registers are preserved.
;
; The alternate entrypoint read_name_with_sd additionally takes a pointer
; to static_data in %r2. If you can arrange that, it's a bit better. It'll still be
; in %r2 when this returns if so.
;
; The read string will be null-terminated. It will appear after the last added
; table (symbol or relcoation) entry, in the correct place to add a new symbol table
; entry for that name without copying it.
read_name_with_sd:
            pushd   %r2
            jmp     read_name_have_sd
read_name:
            pushd   %r2
            mov     %r2, STATIC_DATA_PTR
read_name_have_sd:
            pushd   %ln
            pushd   %r3                 ; get a free register so we can save original buffer
            addd    %r2, HEAP_LIMIT_OFS ; &static_data->heap_limit
            ldd     %r2, %r2            ; static_data->heap_limit
            addd    %r2, 8              ; static_data->heap_limit + offsetof(table_entry_t, symbol)
            movd    %r3, %r2            ; save original buffer
read_name_L1:
            sth     %r5, %r2            ; *buffer = cur
            addd    %r2, 1              ; buffer++
            ldh     %r5, STREAM         ; cur = getchar()
            call    cur_is_name_char    ; r0 = is cur a valid name char?
            test    %r0, -1             ; check result
            jnz     read_name_L1        ; if cur is valid, loop

            mov     %r0, 0              ; r0 = \NUL
            sth     %r0, %r2            ; *buffer = \NUL
            movd    %r0, %r3            ; restore original buffer
            popd    %r3
            popd    %ln
            popd    %r2                 ; we wound in a weird order, undo that
            ret

; read_any_register
;   r5: cur, which should be '%'
; returns
;   r0: unsigned byte index of the register. >=8 means control register.
;       See the C code for the mapping.
;   r5: new cur
; Clobbers r1.
;
; This function can fairly easily be moved away from space-critical sections
; if needed, by leaving the lookup table and a call stub somewhere accessible
; and calling the body of the function further away. However, it needs access
; to strncmp, consume, and is_alphanum.
read_any_register:
            pushd   %ln
            call    read_any_register_actual ; put &register_table in %ln
register_table:
            ; we order this table to give priority to the register names that
            ; are used most often by object programs. I'm just guessing at the
            ; moment that this will favor S&F register names.
            ; To get the assembler to assemble itself, comment out the &...
            .ascii  "a0"
            .word   0 empty_str&0xFFFF
            .ascii  "a1"
            .word   1 empty_str&0xFFFF
            .ascii  "a2"
            .word   2 empty_str&0xFFFF
            .ascii  "s0"
            .word   3 empty_str&0xFFFF
            .ascii  "s1"
            .word   4 empty_str&0xFFFF
            .ascii  "bp"
            .word   5 empty_str&0xFFFF
            .ascii  "sp"
            .word   6 empty_str&0xFFFF
            .ascii  "ln"
            .word   7 empty_str&0xFFFF
            .ascii  "r0"
            .word   0 empty_str&0xFFFF
            .ascii  "r1"
            .word   1 empty_str&0xFFFF
            .ascii  "r2"
            .word   2 empty_str&0xFFFF
            .ascii  "r3"
            .word   3 empty_str&0xFFFF
            .ascii  "r4"
            .word   4 empty_str&0xFFFF
            .ascii  "r5"
            .word   5 empty_str&0xFFFF
            .ascii  "r6"
            .word   6 empty_str&0xFFFF
            .ascii  "r7"
            .word   7 empty_str&0xFFFF
            .ascii  "c1"
            .word   8 id_str&0xFFFF
            .ascii  "c2"
            .word   9 id_str&0xFFFF
            .ascii  "fe"
            .word   10 at_str&0xFFFF
read_any_register_actual:
            pushd   %r2
            pushd   %r3
            pushd   %r4                 ; wind the stack (%ln already pushed)
            mov     %r3, BUFFER_PTR     ; r3 = buffer
            ldh     %r0, STREAM
            sth     %r0, %r3            ; *buffer = getchar()
            addd    %r3, 1
            ldh     %r0, STREAM
            sth     %r0, %r3            ; *(buffer + 1) = getchar()
            subd    %r3, 1              ; r3 = buffer, once again
            movz    %r5, 18             ; i = 18
            movd    %r4, %r7            ; r7 previously held &register_table
read_any_register_L1:
            movd    %r0, %r3            ; arg0 = buffer
            movd    %r1, %r4            ; arg1 = register_table[18-i].name
            movd    %r2, 2              ; arg2 = 2
            call    strncmp             ; r0 = 0 iff string at buffer == string at name
            testh   %r0, -1             ; is r0 == 0?
            jz      read_any_register_L3; found match! break out of loop
            addd    %r4, 6              ; point r4 at next register table entry
            subh    %r5, 1              ; --i
            jge     read_any_register_L1; loop as long as i is still >= 0
read_any_register_L2:                   ; but if i < 0, there were no matches. Die.
            mov     %r0, 1              ; r0 = INVALID_REGISTER_CODE
            call    die
read_any_register_L3:
            ldh     %r5, STREAM         ; cur = getchar() [in the C code, this is above the loop]
            addd    %r4, 4              ; point r4 at entry.remainder_to_consume
            ; we don't need to sign-extend the result explicitly because ldx should already!
            ldx     %r1, %r4            ; r1 = entry->remainder_to_consume
            call    consume             ; r0 = 0 iff consume succeeds
            testh   %r0, -1             ; is r0 == 0?
            jnz     read_any_register_L2; call die(INVALID_REGISTER) if consume failed
            call    cur_is_alphanum     ; r0 = is_alphanum(cur)
            testh   %r0, -1             ; is r0 != 0?
            jnz     read_any_register_L2; call die(INVALID_REGISTER) if is_alphanum(cur)
            subd    %r4, 2              ; point r4 at entry.number
            ldx     %r0, %r4            ; return = entry->number
            popd    %r4
            popd    %r3
            popd    %r2                 ; unwind
            popd    %ln                 ; restore return address
            ret

; read_register, read_ctrl_register
;
; Same as 'read_any_register', but crashes if it reads a {/non}control register.
read_register:
            pushd   %ln
            call    read_any_register
            popd    %ln
            cmph    %r0, 8
            retl                        ; return reg if it's < 8
            jmp     read_any_register_L2; otherwise, call die(INVALID_REGISTER)
read_ctrl_register:
            pushd   %ld
            call    read_any_register
            popd    %ld
            cmph    %r0, 8
            retge                       ; return reg if it's >= 8
            jmp     read_any_register_L2; otherwise, call die as above

; consume
;   r1: pointer to C string to match against STREAM
;   r5: cur
; returns
;   r0: 0 iff the init of {cur,*STREAM} matches *r0
;   r5: new cur
; Clobbers r1
consume_L1:
            ; INLINE CALL TO match
            rsubh   %r0, %r5            ; r0 = *check - cur
            ldh     %r5, STREAM         ; cur = getchar()
            ; END INLINE CALL
            retnz                       ; if match failed, return result
            addd    %r1, 1              ; ++check
consume:
            ldh     %r0, %r1            ; r0 = *check
            testh   %r0, -1             ; *check == 0?
            jnz     consume_L1          ; loop if *check != 0
            ret                         ; otherwise, return *check === 0

; match
;   r0: character
;   r5: cur
; returns
;   r0: cur - c === 0 iff cur == c
;   r5: new cur
;   flags: set according to cur - c
; No clobbers.
match:
    rsubh   %r0, %r5                    ; r0 = cur - c
    ldh     %r5, STREAM                 ; cur = getchar()
    ret


; read_opcode
;   r5: cur
; returns
;   r0: opcode
;   r1: State to transition the parsing state machine to
;   r5: cur
; Nothing else is clobbered.
read_opcode:
            pushd   %ln
            pushd   %r2
            pushd   %r3
            pushd   %r4
    ; register map for this function:
    ; r0   |   r.opcode, or buffer
    ; r1   |   r.state   or table[ix].name
    ; r2   |   volatile temporary
    ; r3   |   size
    ; r4   |   count     or trigger
    ; r5   |   table pointer, cur when necessary
            mov     %r0, 0              ; r.opcode = 0
            mov     %r1, 3              ; r.state = STATE_TX
            mov     %r2, BUFFER_PTR     ; r2 = buffer
            sth     %r5, %r2            ; *buffer = cur
            movh    %r3, %r5            ; temporarily stash cur in r3
            ldh     %r5, STREAM         ; cur = getchar()
            addd    %r2, 1              ; ++buffer
            sth     %r5, %r2            ; *buffer = cur
            mov     %r4, 106            ; r4 = 'j' === 106
            cmph    %r3, %r4            ; check if original cur was 'j'
            mov     %r4, 0              ; trigger = HIT_J === 0
            je      read_opcode_cond    ; jump to the cond part if so
            mov     %r3, 2              ; size = 2
            mov     %r4, 2              ; count = 2
            mov     %r5, opcode_tables  ; r5 = pointer to opcode tables
                                        ; specifically, to table2[0].name
read_opcode_sloop:
            mov     %r0, BUFFER_PTR     ; arg 0 = buffer
            movd    %r1, %r5            ; arg 1 = &table{2/3}[ix].name
            mov     %r2, %r3            ; arg 2 = size
            call    strncmp             ; r0 = (0 iff hit table)
            testh   %r0, -1             ; test for hit
            jnz     read_opcode_sstep   ; if not a hit, go to next step
            subd    %r5, 1              ; r5 = &table{2/3}[ix].opcode
            ldh     %r0, %r5            ; r.opcode = table{2/3}[ix].opcode
            mov     %r1, 5              ; r.state = STATE_COMP
            ldh     %r5, STREAM         ; cur = getchar()
            jmp     read_opcode_unwind  ; return
read_opcode_sstep:
            addd    %r5, %r3            ; tableptr += size
            addd    %r5, 1              ; tableptr += 1 [shift past next opcode]
            subh    %r4, 1              ; --count
            jge     read_opcode_sloop   ; loop if count still >= 0
            cmph    %r3, 2              ; check if size was 2 on that iteration
            mov     %r4, 4              ; count = 4, size is "still" 3 (it's from the future)
            jne     read_opcode_big     ; if not, stop the short loop
            mov     %r3, 3              ; size = 3
            mov     %r4, 5              ; count = 5
            mov     %r0, BUFFER_PTR+2   ; r0 = buffer + 2 (probably 34, if trying to self-host)
            ldh     %r2, STREAM         ; r2 = getchar()
            sth     %r2, %r0            ; *(buffer + 2) = r2
            jmp     read_opcode_sloop   ; continue checking short opcodes

read_opcode_bstep:
            addd    %r5, %r3            ; tableptr += size
            addd    %r5, 3              ; tableptr += 3 [shift past opcode,state,trigger]
            subh    %r4, 1              ; --count
            jge     read_opcode_bloop   ; loop now, if count still >= 0
            popd    %r2                 ; reload spilled cur into %r2
            cmph    %r3, 3              ; was size still 3 on that iteration?
            jne     read_opcode_die     ; if not, we're out of things to check. Die.
                                        ; If yes, fallthrough and try size 4.
read_opcode_try4:
            ; at this point, cur is in r2. The pointer might not be in r5.
            mov     %r0, BUFFER_PTR+3   ; r0 = buffer + 3 (probably 35, if trying to self-host)
            sth     %r2, %r0            ; *(buffer + 3) = cur
            mov     %r3, 4              ; size = 4
            mov     %r4, 5              ; count = 5
            mov     %r5, opcode_table4_state
                                        ; fallthrough to top of loop from here
read_opcode_big:                        ; before jumping here, count was set to {4/5}
            ldh     %r2, STREAM         ; get another character...
            pushd   %r2                 ; and spill it, because we still need the table
            addd    %r5, 2              ; was pointed at state, move it to name
read_opcode_bloop:
            mov     %r0, BUFFER_PTR     ; arg 0 = buffer
            movd    %r1, %r5            ; arg 1 = &table{3/4}[ix].name
            mov     %r2, %r3            ; arg 2 = size
            call    strncmp             ; r0 = (0 iff hit table)
            testh   %r0, -1             ; test for hit
            jnz     read_opcode_bstep   ; if no hit, go to next iteration
            popd    %r2                 ; retrieve cur, which we spilled
            subd    %r5, 1              ; move pointer to trigger
            ldh     %r4, %r5            ; trigger = table[ix].trigger
            cmph    %r4, 2              ; trigger == HIT_MOV?
            jne     read_opcode_chkcond ; if it's not, try checking if it's HIT_COND
            movh    %r0, %r2            ; but if it is, check cur (which we reloaded to r2)
            call    is_not_opcode_suffix
            testh   %r0, -1             ; test !is_opcode_suffix(cur)
            jnz     read_opcode_try4    ; if holds, skip to trying length-4 names
read_opcode_chkcond:
            subd    %r5, 2              ; move pointer from trigger to opcode
            ldh     %r0, %r5            ; r.opcode = table[ix].opcode
            addd    %r5, 1              ; move pointer from opcode to state
            ldh     %r1, %r5            ; r.state  = table[ix].state
            movh    %r5, %r2            ; restore cur to r5 from r2 (where it was reloaded)
            cmph    %r4, 1              ; trigger == HIT_COND?
            jne     read_opcode_unwind  ; if no, go to stack unwind and return
read_opcode_cond:
                                        ; otherwise, we are in the cond section
            ; no matter how we get here, we have the following invariants:
            ; r0 has our opcode
            ; r1 has the target state
            ; r4 has the trigger
            ; r5 has cur
            pushx   %r1                 ; spill r.state  (two spills, so x is fine)
            pushx   %r0                 ; spill r.opcode
            mov     %r2, 2              ; i = 2
            mov     %r3, BUFFER_PTR     ; r3 = buffer
read_opcode_bfrcond:
            call    cur_is_not_opcode_suffix
            testh   %r0, -1             ; test !is_opcode_suffix(cur)
            jz      read_opcode_condtbl ; if it doesn't hold (cur is an opcode suffix)
                                        ;   then we can start checking the table
            sth     %r5, %r3            ; *buffer = cur
            ldh     %r5, STREAM         ; cur = getchar()
            addd    %r3, 1              ; ++buffer
            subh    %r2, 1              ; --i
            jg      read_opcode_bfrcond ; continue buffering if i > 0
read_opcode_condtbl:
            mov     %r2, 0              ; clear r2
            sth     %r2, %r3            ; *buffer = 0
            mov     %r3, cond_table_name ; get pointer to cond_table[0].name in r3
            mov     %r2, %r4            ; r2 = trigger
            addh    %r2, %r2            ; r2 = trigger * 2
            addh    %r2, %r2            ; r2 = trigger * 4
            addd    %r3, %r2            ; r3 = cond_table[trigger].name
            movz    %r2, 20
            rsubh   %r4, %r2            ; trigger = 20 - trigger
read_opcode_cndloop:
            mov     %r0, BUFFER_PTR     ; arg 0 = buffer
            movd    %r1, %r3            ; arg 1 = cond_table[ix].name
            mov     %r2, 3              ; arg 2 = 3
            call    strncmp             ; r0 = (0 iff hit table)
            testh   %r0, -1             ; test if hit
            jz      read_opcode_hitcond ; if we hit, go leave (finally)
            addd    %r3, 4              ; otherwise, move to next cond table entry
            subh    %r4, 1              ; --trigger
            jg      read_opcode_cndloop ; continue looping if trigger > 0
read_opcode_die:
            mov     %r0, 0
            call    die                 ; otherwise, we are out of options. Die.
read_opcode_hitcond:
            popx    %r0                 ; reload r.opcode (two spills, both pushx)
            popx    %r1                 ; reload r.state
            subd    %r3, 1              ; move back from name to opcode
            ldh     %r3, %r3            ; read in the opcode
            addh    %r0, %r3            ; r.opcode += cond_table[hit].opcode
read_opcode_unwind:
            popd    %r4
            popd    %r3
            popd    %r2
            popd    %ln
            ret


; validate_u5
; rather than calling this function, you should inline the following defn:
;           movz    %temp, 31
;           cmpd    %r0, %temp
; This sets the 'be' condition if the input int32_t is a valid u5, and unsets
; it otherwise.
; Each call to this function would take 1 instruction, and the function itself
; would be 3. So unless the function needs to be inlined more than twice, inlining
; it will be better (note: at the time of writing, it has 2 callsites).

; validate_s5
; This one is worth implementing as a function as it is larger and has 2 callsites.
;   r0: int32_t to check
; returns
;   r0: the same int32_t
;   flags: sets the 'b' condition if the immediate is valid, and unsets it otherwise.
;       Note that this is different from the validate_u5 code, which sets 'be'!
; data in registers is unchanged.
validate_s5:
            pushd   %r0
            pushd   %r1
            movz    %r1, 16
            addd    %r0, %r1            ; imm + 16
            addx    %r1, %r1            ; r1 = 32
            cmpd    %r0, %r1            ; compare (imm + 16) against 32
            popd    %r1                 ; if 0 <= (imm + 16) < 32, then imm
            popd    %r0                 ; is a valid s5 immediate. The compare
            ret                         ; will set the 'b' condition if so.

; validate_i16
;   r0: int32_t to check
; returns
;   flags: sets the 'z' condition if the immediate is valid, and unsets it otherwise.
; data in registers is unchanged.
;
; The definition to inline is:
;           movsx   %temp, %r0          ; temp = sign_extend(r0, 16)
;           cmpd    %r0, %temp          ; r0 =? sign_extend(r0, 16)

;;; ********************************************************************************
;;; ******************************** AD-HOC CTYPE.H ********************************
;;; ********************************************************************************

; is_alpha
;   r0: character
; returns
;   r0: boolean: is that character alphabetic?
; Clobbers r1.
cur_is_alpha:
            mov     %r0, %r5
is_alpha:
            mov     %r1, 65             ; r1 = 'A'
            cmph    %r0, %r1
            jb      is_alpha_ret_false  ; return false if r0 < 'A'
            addh    %r1, 15
            addh    %r1, 10             ; r1 = 'Z'
            cmph    %r0, %r1            ; c <=? 'Z'
            jbe     is_alpha_ret_true
            addh    %r1, 5              ; r1 = '_'
            cmph    %r0, %r1            ; c ==? '_'
            je      is_alpha_ret_true
            addh    %r1, 2              ; r1 = 'a'
            cmph    %r0, %r1            ; c <? 'a'
            jb      is_alpha_ret_false
            addh    %r1, 15
            addh    %r1, 10             ; r1 = 'z'
            cmph    %r0, %r1            ; c <=? 'z'
            jbe     is_alpha_ret_true   ; fall through to ret_true otherwise
is_eol_ret_false:
is_num_ret_false:
is_alpha_ret_false:
            mov     %r0, 0
            ret
is_eol_ret_true:
is_num_ret_true:
is_alpha_ret_true:
is_imm_start_ret_true:
            mov     %r0, 1
            ret

; is_imm_start
;   r0: character
; returns
;   r0: boolean: is that character numeric or '-'?
; Clobbers r1.
;
; is_num
;   r0: character
; returns
;   r0: boolean: is that character numeric?
;   r1: constant 48
; Clobbers r1.
;
; is_num_have_48
; Same as is_num, but is a shortcut entrypoint if %r1 already contains exactly 48.
cur_is_imm_start:
            mov     %r0, %r5
is_imm_start:
            mov     %r1, 45             ; '-' for comparison
            cmph    %r0, %r1            ; c ==? '-'
            je      is_imm_start_ret_true
            addh    %r1, 3              ; r1 = '0'
            jmp     is_num_have_48      ; this entrypoint is less common

cur_is_num:
            mov     %r0, %r5
is_num:
            mov     %r1, 48             ; '0' prep going in
is_num_have_48:
            subh    %r0, %r1            ; c = c - '0'
            cmph    %r0, 10             ; c <? '9'+1
            jb      is_num_ret_true
            jmp     is_num_ret_false

; is_alphanum
;   r0: character
; returns
;   r0: boolean: is that character alphabetic, a number, or '_'?
; Clobbers r1.
;
; is_name_char
; Equivalent to is_alphanum. Historical in the C code, I guess.
cur_is_alphanum:
cur_is_name_char:
            mov     %r0, %r5
is_alphanum:
is_name_char:
            pushd   %ln                 ; we call functions, save %ln
            pushd   %r0                 ; save c
            call    is_alpha            ; r0 = is_alpha(c)
            testh   %r0, 1              ; test is_alpha(c)
            popd    %r1                 ; r1 = c
            jnz     is_name_char_ret    ; return if is_alpha(c)
            movh    %r0, %r1            ; r0 = c
            call    is_num              ; r0 = is_num(c)
is_name_char_ret:
            popd    %ln
            ret

; is_eol
;   r0: character
; returns
;   r0: boolean: is that character either 10 or 0?
; Clobbers nothing.
cur_is_eol:
            mov     %r0, %r5
is_eol:
            cmph    %r0, 10             ; c ==? '\n'
            je      is_eol_ret_true
            cmph    %r0, 0              ; c ==? '\0'
            je      is_eol_ret_true
            jmp     is_eol_ret_false

; is_not_opcode_suffix
;   r0: character
; returns
;   r0: boolean: is that character NOT valid to appear after an opcode?
; Clobbers r1.
cur_is_not_opcode_suffix:
            mov     %r0, %r5
is_not_opcode_suffix:
            mov     %r1, %r0            ; swap registers
            mov     %r0, 120            ; r0 = 'x' = 120
            rsubh   %r0, %r1            ; r0 = c - 'x'
            retz                        ; if 0, c == 'x' which is valid, return 0
            subh    %r0, -16            ; r0 = (c - 'x') - ('h' - 'x') === c - 'h'
            retz                        ; same, but == 'h'
            addh    %r0, 4              ; r0 = (c - 'h') + ('h' - 'd') === c - 'd'
            retz                        ; same, but == 'd'
            mov     %r0, %r1            ; r0 = c
            jmp     is_alpha            ; tail-call is_alpha. Our return sense is inverted,
                                        ; so if is alpha returns yes, we return no. Perf!


;;; ********************************************************************************
;;; ******************************* SYSTEM UTILITIES *******************************
;;; ********************************************************************************

; die
;   r0: code indicating which message we should print
;       0: invalid syntax
;       1: invalid register
;       2: invalid immediate
;       3: out of range
;       4: out of memory
;       5: missing features
;       6: unknown symbol
;       7: unknown directive
;   r2: a symbol, if code is 6 or 7.    NOTE THIS IS R2
; returns
;   none; program execution will end.
;
; Due to the wide range of places where this function is used, it does not
; assume that a pointer to static_data is available.
die:
            call    die_actual          ; %r7 = &msg_header
msg_header:                             ; char **msg_header
            ; to get the assembler to assemble itself, comment out the &...
            .word   invalid_msg &0xFFFF
            .word   invalid_msg &0xFFFF
            .word   invalid_msg &0xFFFF
            .word   out_of_msg  &0xFFFF
            .word   out_of_msg  &0xFFFF
            .word   empty_msg   &0xFFFF
            .word   unknown_msg &0xFFFF
msg_body:                               ; char **msg_body
            .word   syntax_msg    &0xFFFF
            .word   register_msg  &0xFFFF
            .word   immediate_msg &0xFFFF
            .word   range_msg     &0xFFFF
            .word   memory_msg    &0xFFFF
            .word   missing_features_msg &0xFFFF
            .word   symbol_msg    &0xFFFF
            .word   directive_msg &0xFFFF
die_actual:
            movd    %r2, %r1            ; save name in r2 which is stable (r1 is not)
            movd    %r5, %r7            ; save &msg_header
            addh    %r0, %r0            ; ofs = code << 1
            addd    %r0, %r7            ; r0 = &(msg_header[code])
            movd    %r3, %r0            ; save &(msg_header[code]) for later
            ldx     %r0, %r0            ; r0 = msg_header[code] (ldx sign-extends so we get the right ptr)
            call    puts                ; puts(msg_header[code])
            movd    %r0, %r3            ; retrieve &msg_header[code]
            addd    %r0, 14             ; r0 = &msg_body[code]
            ldx     %r0, %r0            ; r0 = msg_body[code]   (ldx sign-extends so we get the right ptr)
            call    puts                ; puts(msg_body[code])   additionally r1 = 0
            subd    %r3, %r5            ; r3 = &msg_header[code] - msg_header, eqv. 2*code
            cmpx    %r3, 10             ; compare 2*code against 10
            jle     die_line            ; if 2*code <= 10, we're done and can print line and halt
            movd    %r0, %r2            ; move name to argument 0 (it was saved in r2 and is untouched)
            ; names are always null-terminated now, no need to do it ourselves.
            call    puts                ; puts(name)
die_line:
            call    die_line_with_msg
            .asciiz " at line "
            .align  2
die_line_with_msg:
            movd    %r0, %ln
            call    puts                ; print " at line "
            mov     %r0, BUFFER_PTR     ; arg 0 = buf
            mov     %r2, 0xC00A         ; &static_data.src_lineno
            ldx     %r2, %r2            ; arg 2 = static_data->src_lineno
            call    utoa                ; convert lineno to string in buffer
            mov     %r0, BUFFER_PTR     ; arg 0 = buf, again
            call    puts                ; print the line number
            hlt                         ; crash the kernel.

; udiv16
;   r0: dividend
;   r2: divisor   ; note NOT r1 !
; returns
;   r0: quotient
;   r1: remainder
;   r2: divisor
; No clobbers.
;
; Perform a 16-bit unsigned division, using a "fast" long division algorithm.
; The divisor is taken in r2 and is returned unchanged, making it easy
; to chain several divisions together "quickly."
; It might be easy to change to 32-bit division by changing what's in %r3?
; Look into that!
udiv16:
            pushd   %r3                 ; save r3
            mov     %r1, 0              ; initial partial remainder is 0
            mov     %r3, 16             ; number of iterations to perform
udiv16_loop:
            addx    %r1, %r1            ; shift the partial remainder one bit left
            addx    %r0, %r0            ; shift dividend left one bit thru carry
            jnc     udiv16_no_qbit      ; if no carry, skip moving bit into partial rem
            orx     %r1, 1              ; move carry into bottom bit of shifted partial rem
udiv16_no_qbit:
            sub     %r1, %r2            ; attempt subtraction from partial remainder
            jnc     udiv16_no_borrow    ; if that subtraction succeeded, set bit of quotient
            add     %r1, %r2            ; otherwise, restore partial remainder
            jmp     udiv16_step         ; and skip setting quotient bit
udiv16_no_borrow:
            orx     %r0, 1              ; set bottom bit of the dividend (growing quotient)
udiv16_step:
            subh    %r3, 1              ; decrement counter
            ja      udiv16_loop         ; continue as long as counter remains > 0
            popd    %r3                 ; otherwise we're done. Restore r3
            ret

; itoa
; utoa
;   r0: char *buffer
;   r1: ignored (for now), should be base
;   r2: the number to convert to a string, int16_t or uint16_t
; returns nothing meaningful
; Standard calling conventions
;
; Convert an integer to a string, storing the resulting string to the buffer.
; If you call 'itoa', the integer is treated as an int16_t. If you call 'utoa',
; the integer is treated as a uint16_t.
itoa:
            testx   %r2, -1             ; test the input number for sign
            jnn     utoa                ; if it's already positive, go straight to utoa
            mov     %r1, 45             ; otherwise, prepare a minus sign '-'
            sth     %r1, %r0            ; to put in the buffer
            addd    %r0, 1              ; buf++
            rsubx   %r2, 0              ; d = -d
utoa:
            pushd   %ln
            pushd   %r4                 ; wind
            pushd   %r0                 ; save original value of buffer
            mov     %r4, 48             ; stash '0' for quick access
            mov     %r3, %r0            ; p = buf
            mov     %r0, %r2            ; dividend = d
            mov     %r2, 10             ; divisor = base = 10
itoa_loop:
            call    udiv16              ; r0 = quotient, r1 = remainder, r2 still 10
            addh    %r1, %r4            ; chr = remainder + '0'
            sth     %r1, %r3            ; *p = chr
            addd    %r3, 1              ; p++
            testx   %r0, -1             ; test quotient for zero
            jnz     itoa_loop           ; loop as long as quotient is not yet zero
            sth     %r0, %r3            ; *p = 0, terminate the string
                                        ; now we need to reverse the buffer
            subd    %r3, 1              ; p2 = p - 1
            popd    %r0                 ; p1 = buf
            popd    %r4
            popd    %ln                 ; fully unwind the stack to prepare for
                                        ; quick exit from the reverse loop
            jmp     itoa_rev_check      ; enter loop at check
itoa_rev_loop:
            ldh     %r2, %r0            ; tmp = *p1
            ldh     %r1, %r3            ; r1 = *p2
            sth     %r1, %r0            ; *p1 = *p2
            sth     %r2, %r3            ; *p2 = tmp
            addd    %r0, 1              ; p1++
            subd    %r3, 1              ; p2--
itoa_rev_check:
            cmpd    %r0, %r3            ; p1 <? p2
            jb      itoa_rev_loop       ; loop if yes
            ret                         ; otherwise we're done, return.

; puts
;   r0: const char *str
; returns:
;   r0: pointer to str's nul terminator
;
; r1 is clobbered. When 'puts' returns, r1 is 0.
;
; Print a nul-terminated string to the console device at MMIO address OUTPUT.
puts_L1:
            sth     %r1, OUTPUT         ; putchar(*str)
            addd    %r0, 1              ; ++str
puts:
            ldh     %r1, %r0            ; r1 = *str
            testh   %r1, -1             ; test *str
            jnz     puts_L1             ; loop if *str != 0
            ret                         ; return if *str == 0

syscall_exit:
            pushd   %r1                     ; save status
            call    syscall_exit_with_msg   ; get msg into ln
            .asciiz "Program exited with status "
            .align  2
syscall_exit_with_msg:
            movd    %r0, %r7            ; arg 0 = msg
            call    puts                ; print the msg
            popd    %r2                 ; arg 2 = status
            mov     %r0, 0xC020         ; arg 0 = runtime buffer after kernel data
            movd    %r4, %r0            ; save buffer addr
            call    utoa                ; write str(code) into buffer
            movd    %r0, %r4            ; arg 0 = buffer again
            call    puts                ; print the code
            hlt                         ; terminate

syscall_putuint:
syscall_putsint:
            pushd   %r2                 ; wind stack to save all user registers that we would clobber
            pushd   %r3
            pushd   %r4
            cmph    %r0, 2              ; compare 2*service_no to 2. If it's 2, print unsigned.
            movx    %r2, %r1            ; arg 2 = number
            mov     %r0, 0xC020         ; arg 0 = runtime buffer after kernel data
            movd    %r4, %r0            ; and save this address
            jne     syscall_do_signed   ; if service no is not 2, use itoa
            call    utoa                ; otherwise use utoa
            jmp     syscall_have_a
syscall_do_signed:
            call    itoa
syscall_have_a:                         ; now the buffer has the rep of the number to print
            movd    %r0, %r4            ; get its address back
            call    puts                ; and print the number
            popd    %r4
            popd    %r3
            popd    %r2                 ; unwind
            jmp     syscall_return

syscall_puts:
            movd    %r0, %r1            ; arg 0 = message
            call    puts                ; print it
            jmp     syscall_return

syscall_sbrk:
            mov     %r7, STATIC_DATA_PTR ; r7 = &static_data.break
            ldd     %r0, %r7            ; r0 = static_data->break
            addd    %r1, %r0            ; r1 = static_data->break + numbytes
            addd    %r1, 3
            andd    %r1, -4             ; dword align the new break
            std     %r1, %r7            ; record the new break
            jmp     syscall_return

syscall_return:
            ; at this point, we know our return address is at the top of OUR stack
            ; and that we need to restore the user's stack pointer from 0xC00A.
            ; We can do whatever we want with r1, but the other registers
            ; have to stay unchanged, including r0 which holds a return value.
            popd    %ln                 ; restore our return address
            mov     %sp, 0xC00A         ; &static_data->user_sp
            ldd     %sp, %sp            ; %sp = static_data->user_sp
            ret


invalid_msg:
            .ascii  "invalid "
empty_str:
empty_msg:                  ; share the NUL-terminator to get empty string
            .half   0

out_of_msg:
            .asciiz "out of "

syntax_msg:
            .asciiz "syntax"

register_msg:
            .asciiz "register"

immediate_msg:
            .asciiz "immediate"

range_msg:
            .asciiz "range"

memory_msg:
            .asciiz "memory"

unknown_msg:
            .asciiz "unknown "

symbol_msg:
            .asciiz "symbol "

directive_msg:
            .asciiz "directive "

completed_assembly_msg:
            .asciiz "assembly complete!\n"

exit_with_status_msg:
            .asciiz "program exited with status "

id_str:
            .asciiz "id"
at_str:
            .asciiz "at"

opcode_table2:
            .half   4
opcode_tables:                  ; pointer directly to 'name'
            .ascii  "or"
            .half   10
            .ascii  "ld"
            .half   11
            .ascii  "st"
opcode_table3short:
            .half   0
            .ascii  "add"
            .half   1
            .ascii  "sub"
            .half   3
            .ascii  "cmp"
            .half   5
            .ascii  "xor"
            .half   6
            .ascii  "and"
            .half   12
            .ascii  "slo"
opcode_table3:
            .half   9   7   2
            .ascii  "mov"
            .half   12  4   3
            .ascii  "pop"
            .half   14  11  3
            .ascii  "hlt"
            .half   15  11  3
            .ascii  "nop"
            .half   16  11  1
            .ascii  "ret"
opcode_table4:
            .half   2
opcode_table4_state:
            .half   5   3
            .ascii  "rsub"
            .half   7   5   3
            .ascii  "test"
            .half   8   5   3
            .ascii  "movz"
            .half   9   5   3
            .ascii  "movs"
            .half   13  2   3
            .ascii  "push"
            .half   16  3   1
            .ascii  "call"
cond_table:
            .half   14
cond_table_name:
            .asciiz "mp"
            .half   0
            .asciiz "z\0"
            .half   0
            .asciiz "e\0"
            .half   1
            .asciiz "nz"
            .half   1
            .asciiz "ne"
            .half   2
            .asciiz "n\0"
            .half   3
            .asciiz "nn"
            .half   4
            .asciiz "c\0"
            .half   4
            .asciiz "b\0"
            .half   5
            .asciiz "nc"
            .half   5
            .asciiz "ae"
            .half   6
            .asciiz "o\0"
            .half   7
            .asciiz "no"
            .half   8
            .asciiz "be"
            .half   9
            .asciiz "a\0"
            .half   10
            .asciiz "l\0"
            .half   11
            .asciiz "ge"
            .half   12
            .asciiz "le"
            .half   13
            .asciiz "g\0"
            .half   14
            .asciiz "\0\0"
