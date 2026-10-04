.MODEL MEDIUM,C
.DATA
PUBLIC asm_word
asm_word DW 1234h
.CODE
PUBLIC asm_mix
asm_mix PROC FAR
    push bp
    mov bp, sp
    mov ax, WORD PTR [bp+6]
    xor ax, asm_word
    pop bp
    retf
asm_mix ENDP
END
