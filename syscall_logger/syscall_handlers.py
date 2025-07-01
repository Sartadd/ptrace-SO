# syscall_logger/syscall_handlers.py

import os
import struct
import socket
import errno
from datetime import datetime

from syscall_logger.ptrace_utils import read_string, read_data_at_address
from syscall_logger.syscall_table import SYSCALL_NAMES

# --- Funções Auxiliares para Decodificação ---

def decode_open_flags(flags):
    """Decodifica flags de abertura de arquivo (O_*) em uma string legível."""
    flag_names = []
    if flags & os.O_RDONLY: flag_names.append("O_RDONLY")
    if flags & os.O_WRONLY: flag_names.append("O_WRONLY")
    if flags & os.O_RDWR: flag_names.append("O_RDWR")
    if flags & os.O_CREAT: flag_names.append("O_CREAT")
    if flags & os.O_EXCL: flag_names.append("O_EXCL")
    if flags & os.O_NOCTTY: flag_names.append("O_NOCTTY")
    if flags & os.O_TRUNC: flag_names.append("O_TRUNC")
    if flags & os.O_APPEND: flag_names.append("O_APPEND")
    if flags & os.O_NONBLOCK: flag_names.append("O_NONBLOCK")
    if flags & os.O_DSYNC: flag_names.append("O_DSYNC")
    if flags & os.O_SYNC: flag_names.append("O_SYNC")
    if flags & getattr(os, 'O_RSYNC', 0): flag_names.append("O_RSYNC") # Not always present
    if flags & getattr(os, 'O_DIRECT', 0): flag_names.append("O_DIRECT")
    if flags & getattr(os, 'O_LARGEFILE', 0): flag_names.append("O_LARGEFILE")
    if flags & getattr(os, 'O_DIRECTORY', 0): flag_names.append("O_DIRECTORY")
    if flags & getattr(os, 'O_NOFOLLOW', 0): flag_names.append("O_NOFOLLOW")
    if flags & getattr(os, 'O_CLOEXEC', 0): flag_names.append("O_CLOEXEC")
    if flags & getattr(os, 'O_TMPFILE', 0): flag_names.append("O_TMPFILE")
    # Add more flags as needed

    if not flag_names:
        return f"0x{flags:x}"
    return "|".join(flag_names)

def decode_mode_t(mode):
    """Decodifica modos de permissão de arquivo (mode_t) em uma string octal."""
    return f"0o{mode:o}"

def decode_socket_domain(domain):
    """Decodifica o domínio de um socket (AF_*) em uma string legível."""
    domains = {
        socket.AF_UNSPEC: "AF_UNSPEC",
        socket.AF_UNIX: "AF_UNIX",
        socket.AF_INET: "AF_INET",
        socket.AF_INET6: "AF_INET6",
        socket.AF_NETLINK: "AF_NETLINK",
        # Adicione mais domínios conforme necessário
    }
    return domains.get(domain, str(domain))

def decode_socket_type(sock_type):
    """Decodifica o tipo de um socket (SOCK_*) em uma string legível."""
    types = []
    if sock_type & socket.SOCK_STREAM: types.append("SOCK_STREAM")
    if sock_type & socket.SOCK_DGRAM: types.append("SOCK_DGRAM")
    if sock_type & socket.SOCK_RAW: types.append("SOCK_RAW")
    if sock_type & socket.SOCK_SEQPACKET: types.append("SOCK_SEQPACKET")
    if sock_type & socket.SOCK_RDM: types.append("SOCK_RDM")
    if sock_type & socket.SOCK_NONBLOCK: types.append("SOCK_NONBLOCK")
    if sock_type & socket.SOCK_CLOEXEC: types.append("SOCK_CLOEXEC")
    # Adicione mais tipos

    if not types:
        return f"0x{sock_type:x}"
    return "|".join(types)

def decode_sockaddr(process, address, length):
    """
    Lê e decodifica uma estrutura sockaddr da memória do tracee.
    Suporta AF_INET e AF_UNIX.
    """
    if not address:
        return "NULL"

    # Assume que sa_family é os 2 primeiros bytes
    family_bytes = read_data_at_address(process, address, 2)
    if not family_bytes:
        return f"0x{address:x} (read error)"
    sa_family = struct.unpack("<H", family_bytes)[0] # <H para unsigned short little-endian

    if sa_family == socket.AF_INET:
        # struct sockaddr_in (16 bytes em Linux de 64 bits)
        # sin_family (2 bytes), sin_port (2 bytes), sin_addr (4 bytes), sin_zero (8 bytes)
        sa_in_bytes = read_data_at_address(process, address, 16)
        if not sa_in_bytes or len(sa_in_bytes) < 8: # Basic check for minimum size
            return f"0x{address:x} (read error/too short for AF_INET)"
        
        # Unpack the relevant parts: H=family, H=port, L=address (unsigned int)
        try:
            _, port_raw, ip_raw = struct.unpack("<HHLL", sa_in_bytes[:8]) # Only unpack first 8 bytes for family, port, addr
            port = socket.ntohs(port_raw)
            ip_address = socket.inet_ntoa(struct.pack("<L", ip_raw))
            return f"{{sa_family={decode_socket_domain(sa_family)}, sin_port={port}, sin_addr='{ip_address}'}}"
        except struct.error:
            return f"0x{address:x} (unpack error for AF_INET)"
    elif sa_family == socket.AF_UNIX:
        # struct sockaddr_un (sun_path é tipicamente 108 bytes em Linux)
        # sun_family (2 bytes) + sun_path (108 bytes) = 110 bytes
        # Read the entire structure to get the path
        path_offset = 2 # offset of sun_path after sun_family
        path = read_string(process, address + path_offset)
        return f"{{sa_family={decode_socket_domain(sa_family)}, sun_path='{path if path else '<read error>'}'}}"
    else:
        return f"{{sa_family={decode_socket_domain(sa_family)}, addr=0x{address:x}, len={length}}}"

# --- Função Principal de Formatação de Argumentos ---

def format_syscall_args(process, syscall_num, args):
    """
    Formata os argumentos de uma syscall para uma string legível.
    `process` é a instância de ptrace.Process.
    `args` é uma lista de valores inteiros dos argumentos.
    """
    try:
        # Dicionário para armazenar argumentos decodificados
        decoded_args = []

        # Usamos o número da syscall para determinar como decodificar os argumentos
        # Esta parte é um switch-case gigante e precisa ser expandida para cada syscall
        if syscall_num == SYSCALL_NAMES.get('open', -1) or \
           syscall_num == SYSCALL_NAMES.get('openat', -1):
            # open(const char *pathname, int flags, mode_t mode)
            # openat(int dirfd, const char *pathname, int flags, mode_t mode)
            
            # Para open, o primeiro argumento é o pathname (ponteiro para string)
            # Para openat, o segundo argumento é o pathname
            pathname_arg_idx = 0 if syscall_num == SYSCALL_NAMES.get('open', -1) else 1
            pathname = read_string(process, args[pathname_arg_idx])
            
            if syscall_num == SYSCALL_NAMES.get('open', -1):
                decoded_args.append(f'"{pathname if pathname is not None else "NULL"}"')
                decoded_args.append(decode_open_flags(args[1])) # flags
                decoded_args.append(decode_mode_t(args[2]))     # mode
            else: # openat
                decoded_args.append(str(args[0])) # dirfd
                decoded_args.append(f'"{pathname if pathname is not None else "NULL"}"')
                decoded_args.append(decode_open_flags(args[2])) # flags
                decoded_args.append(decode_mode_t(args[3]))     # mode

        elif syscall_num == SYSCALL_NAMES.get('read', -1) or \
             syscall_num == SYSCALL_NAMES.get('write', -1):
            # read(int fd, void *buf, size_t count)
            # write(int fd, const void *buf, size_t count)
            decoded_args.append(str(args[0])) # fd
            decoded_args.append(f"0x{args[1]:x}") # buf (endereço, não lemos o conteúdo aqui)
            decoded_args.append(str(args[2])) # count

        elif syscall_num == SYSCALL_NAMES.get('close', -1):
            # close(int fd)
            decoded_args.append(str(args[0])) # fd

        elif syscall_num == SYSCALL_NAMES.get('execve', -1):
            # execve(const char *pathname, char *const argv[], char *const envp[])
            pathname = read_string(process, args[0])
            decoded_args.append(f'"{pathname if pathname is not None else "NULL"}"')
            decoded_args.append(f"0x{args[1]:x}") # argv pointer
            decoded_args.append(f"0x{args[2]:x}") # envp pointer

        elif syscall_num == SYSCALL_NAMES.get('socket', -1):
            # socket(int domain, int type, int protocol)
            decoded_args.append(decode_socket_domain(args[0]))
            decoded_args.append(decode_socket_type(args[1]))
            decoded_args.append(str(args[2])) # protocol

        elif syscall_num == SYSCALL_NAMES.get('connect', -1) or \
             syscall_num == SYSCALL_NAMES.get('bind', -1):
            # connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
            # bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
            addr_str = decode_sockaddr(process, args[1], args[2])
            decoded_args.append(str(args[0])) # sockfd
            decoded_args.append(addr_str)
            decoded_args.append(str(args[2])) # addrlen

        # ... Adicione mais syscalls aqui para decodificação específica ...

        else:
            # Para syscalls não decodificadas, mostra os argumentos como hexadecimais
            decoded_args = [f"0x{arg:x}" for arg in args if arg is not None]

        return ", ".join(decoded_args)
    except Exception as e:
        return f"<ERROR_DECODING: {e}>"