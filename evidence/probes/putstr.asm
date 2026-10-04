.MODEL MEDIUM,C
.CODE
PUBLIC root_puts
root_puts PROC NEAR
    push ax
    push dx
    push si
    mov si, dx
    mov ah, 2
write_loop:
    mov dl, BYTE PTR [si]
    or dl, dl
    jz write_done
    int 21h
    inc si
    jmp short write_loop
write_done:
    pop si
    pop dx
    pop ax
    ret
root_puts ENDP
END
