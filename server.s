.intel_syntax noprefix
.global _start
.global find_nth_from

.section .data

.equ EXIT_SUCCESS, 0

.equ SYS_read, 0
.equ SYS_write, 1
.equ SYS_open, 2
.equ SYS_close, 3
.equ SYS_socket, 41
.equ SYS_accept, 43
.equ SYS_bind, 49
.equ SYS_listen, 50
.equ SYS_fork, 57
.equ SYS_exit, 60

.equ PORT, 80
.equ ADDRESS, 0x00000000
.equ AF_INET, 2
.equ SOCK_STREAM, 1

.equ O_RDONLY, 0
.equ O_WRONLY, 1
.equ O_CREAT, 64

.equ PERMS, 0777

.equ BUFFSIZE, 0x1000

OK_response:
.asciz "HTTP/1.0 200 OK\r\n\r\n"

.section .text

/*
  Helper function to find the nth occurrence of a character
  in a string starting from a specified index, noninclusive
  
  Args:
    rdi - string address
    sil - search character
    rdx - starting index
    rcx - n
  Returns:
    rax - index of character, or -1 if not found
*/

find_nth_from:
    push rbp
    mov rbp, rsp
    mov eax, -1
    nloop:
    search:
	inc edx
	cmp byte ptr [rdi+rdx], 0
	je endsearch
	cmp byte ptr [rdi+rdx], sil
	cmove eax, edx
	jne search
    loop nloop
    endsearch:
    mov rsp, rbp
    pop rbp
    ret


/*
  Creates an IPv4 socket and connects it to the local socket
  address and port specified.
 
  Args:
    edi - network address (4 byte integer)
    si - port (2 byte integer)
  Returns:
    rax - socket file descriptor, or -1 on error
*/
create_socket:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    mov dword ptr [rbp-0x4], edi
    mov word ptr [rbp-0xa], si

    mov rdx, 0
    mov rsi, SOCK_STREAM
    mov rdi, AF_INET
    mov rax, SYS_socket
    syscall
    mov dword ptr [rbp-0x8], eax

    mov word ptr [rbp-0x20], AF_INET # address family: 2 bytes
    mov ax, word ptr [rbp-0xa]
    mov word ptr [rbp-0x1e], ax 
    mov cl, byte ptr [rbp-0x1e]
    xchg cl, byte ptr [rbp-0x1d]
    xchg byte ptr [rbp-0x1e], cl # port in network byte order, 2 bytes
    mov eax, dword ptr [rbp-0x4]
    bswap eax
    mov dword ptr [rbp-0x1c], eax # address, 4 bytes
    mov qword ptr [rbp-0x18], 0x0 # padding
    
    mov rdx, 0x10
    lea rsi, [rbp-0x20]
    mov edi, dword ptr [rbp-0x8]
    mov rax, SYS_bind
    syscall

    mov eax, dword ptr [rbp-0x8]
    mov rsp, rbp
    pop rbp
    ret

/*
  Identifies the HTTP request method. If GET, returns 0. If POST, returns 1.
  Assumes that all responses will be valid

  Args:
    rdi - starting address of request

  Returns:
    rax - 0 if GET, 1 if POST
*/
identify_request:
    push rbp
    mov rbp, rsp

    mov rax, 0x0

    cmp byte ptr [rdi], 'P
    jne end_identify_request
    inc rax

    end_identify_request:
    mov rsp, rbp
    pop rbp
    ret

/*
  Handles GET requests. Loads content from specified file to
  given address and returns number of bytes written.

  Args:
    rdi - Address of request string. Will be overwritten by
          response.
  Returns:
    rax - number of bytes written to given address
*/
handle_get:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10   # address of buffer: rbp-0x8, 8b
		    # file_fd: rbp-0xc, 4b
		    # file_len: rbp-0x10, 4b
    mov qword ptr [rbp-0x8], rdi

    mov rcx, 0x1
    mov rdx, 0x0
    mov rsi, '/
    mov rdi, qword ptr [rbp-0x8]
    call find_nth_from
    mov rbx, rax

    # Search read buffer for end of file name
    # and place NULL character there
    mov rcx, 0x1
    mov rdx, 0x0
    mov edx, eax
    mov rsi, ' '
    mov rdi, qword ptr [rbp-0x8]
    call find_nth_from
    add rax, qword ptr [rbp-0x8]
    mov byte ptr [rax], 0

    # Open file specified in the request
    mov rdx, 0x0
    mov rsi, O_RDONLY
    mov rdi, qword ptr [rbp-0x8]
    add rdi, rbx
    mov rax, SYS_open
    syscall
    mov dword ptr [rbp-0xc], eax

    /* pwn.college needs two separate write calls, one
      for start line and another for the body, so moving
      this functionality to the _start function

      TODO change back

    # Overwrite response to buffer
    lea rsi, [rip+OK_response]
    mov rdi, qword ptr [rbp-0x8]
    mov rcx, 19
    copy_startline:
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    loop copy_startline
    */

    # Read file specified in the request and close
    mov rdx, BUFFSIZE # BUFFSIZE-19, TODO change back after challenge
    mov rsi, qword ptr [rbp-0x8]
    mov edi, dword ptr [rbp-0xc]
    mov rax, SYS_read
    syscall
    mov dword ptr [rbp-0x10], eax

    mov edi, dword ptr [rbp-0xc]
    mov rax, SYS_close
    syscall

    mov eax, dword ptr [rbp-0x10]
    # add rax, 19 TODO change back after challenge


    mov rsp, rbp
    pop rbp
    ret

handle_post:
    push rbp
    mov rbp, rsp
    sub rsp, 0x110   # address of buffer: rbp-0x8, 8b
		    # file_fd: rbp-0xc, 4b
		    # response_len: rbp-0x10, 4b
		    # file_name: rbp-0x110, 256b
    mov qword ptr [rbp-0x8], rdi
    mov dword ptr [rbp-0x10], esi

    mov rcx, 0x1
    mov rdx, 0x0
    mov rsi, '/
    mov rdi, qword ptr [rbp-0x8]
    call find_nth_from
    mov rbx, rax

    # Search read buffer for end of file name
    # and copy name to file_name buffer
    mov rcx, 0x1
    mov edx, eax
    mov rsi, ' '
    mov rdi, qword ptr [rbp-0x8]
    call find_nth_from

    mov rsi, [rbp-0x8]
    add rsi, rbx
    lea rdi, [rbp-0x110]
    copy_file_name:
	mov al, byte ptr [rsi]
	mov byte ptr [rdi], al
	inc rsi
	inc rdi
	cmp byte ptr [rsi], ' '
	jne copy_file_name
    mov byte ptr [rdi], 0
	
    # Open file specified in the request
    mov rdx, PERMS
    mov rsi, O_WRONLY
    or rsi, O_CREAT
    lea rdi, [rbp-0x110]
    mov rax, SYS_open
    syscall
    mov dword ptr [rbp-0xc], eax

    /* Extract body */
    mov rcx, 0x8
    mov rdx, 0x0
    mov rsi, '\n
    mov rdi, qword ptr [rbp-0x8]
    call find_nth_from
    inc rax


    /*  TODO Write file specified in the request and close */
    mov edx, dword ptr [rbp-0x10]
    sub rdx, rax
    mov rsi, qword ptr [rbp-0x8]
    add rsi, rax
    mov edi, dword ptr [rbp-0xc]
    mov rax, SYS_write
    syscall
    mov dword ptr [rbp-0x10], eax

    mov edi, dword ptr [rbp-0xc]
    mov rax, SYS_close
    syscall

    # Overwrite response to buffer
    lea rsi, [rip+OK_response]
    mov rdi, qword ptr [rbp-0x8]
    mov rcx, 19
    copy_startline:
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    loop copy_startline

    mov rax, 19


    mov rsp, rbp
    pop rbp
    ret




_start:
    
    mov rbp, rsp
    sub rsp, BUFFSIZE+0x10  # passive_sock: rbp-BUFFSIZE-0x4, 4b
			    # accepted_sock: rbp-BUFFSIZE-0x8, 4b
			    # response_len: rbp-BUFFSIZE-0xc, 4b
			    # request_len: rbp-BUFFSIZE-0x10, 4b
			    # readbuf: rbp-BUFFSIZE, BUFFSIZEb

    mov rsi, 0
    mov si, PORT
    mov edi, ADDRESS
    call create_socket
    mov [rbp-BUFFSIZE-0x4], eax

    listen:
    mov rsi, 0
    mov edi, dword ptr [rbp-BUFFSIZE-0x4]
    mov rax, SYS_listen
    syscall

    requestloop:
	accept:
	mov rdx, 0x0
	mov rsi, 0x0
	mov edi, dword ptr [rbp-BUFFSIZE-0x4]
	mov rax, SYS_accept
	syscall
	mov dword ptr [rbp-BUFFSIZE-0x8], eax

	fork:
	mov rax, SYS_fork
	syscall
	cmp rax, 0
	je child
	mov edi, dword ptr [rbp-BUFFSIZE-0x8]
	mov rax, SYS_close
	syscall
	jmp requestloop


    # child process: handles requests
    child:
	# close listening socket
	mov edi, dword ptr [rbp-BUFFSIZE-0x4]
	mov rax, SYS_close
	syscall

	# read BUFFSIZE bytes from active socket
	mov rdx, BUFFSIZE
	lea rsi, [rbp-BUFFSIZE]
	mov edi, dword ptr [rbp-BUFFSIZE-0x8]
	mov rax, SYS_read
	syscall
	mov dword ptr [rbp-BUFFSIZE-0x10], eax

	lea rdi, [rbp-BUFFSIZE]
	call identify_request
	cmp rax, 0x0
	je if_get

	cmp rax, 0x1
	je if_post

	if_get:
	    lea rdi, [rbp-BUFFSIZE]
	    call handle_get
	    mov dword ptr [rbp-BUFFSIZE-0xc], eax

	    /* TODO move back to handle_get */
	    mov rdx, 19
	    lea rsi, [rip+OK_response]
	    mov edi, dword ptr [rbp-BUFFSIZE-0x8]
	    mov rax, SYS_write
	    syscall

	    jmp write_response

	if_post:
	    mov esi, dword ptr [rbp-BUFFSIZE-0x10]
	    lea rdi, [rbp-BUFFSIZE]
	    call handle_post
	    mov dword ptr [rbp-BUFFSIZE-0xc], eax
	    jmp write_response
	

	write_response:
	# Write response to socket and close
	mov edx, dword ptr [rbp-BUFFSIZE-0xc]
	lea rsi, [rbp-BUFFSIZE]
	mov edi, dword ptr [rbp-BUFFSIZE-0x8]
	mov rax, SYS_write
	syscall

	
	close_socket:
	mov edi, dword ptr [rbp-BUFFSIZE-0x8]
	mov rax, SYS_close
	syscall

	exit:
	mov rdi, 0
	mov rax, 60
	syscall

