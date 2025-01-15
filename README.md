# Web Server in x86_64 Assembly

A basic HTTP/1.0 web server written in x86_64 Assembly. Developed on Ubuntu 20.04.


This was originally a project for [pwn.college](https://pwn.college), an educational cybersecurity platform. Though this was first written just to complete the challenges there, I plan on eventually making this fully compliant with the HTTP/1.0 specification, and maybe even beyond.

To run, first generate the executable using the GNU assembler and linker:

```
as -o server.o server.s && ld -o server server.o
```

Then run the server with

```
sudo ./server
```

The URL path will access the server file with the same path.
