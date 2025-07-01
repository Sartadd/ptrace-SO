# syscall_logger/ptrace_utils.py

import struct
from ptrace.ptrace_struct import ptrace_struct
from ptrace.tools import x86_64_arg_regs # Registradores de argumentos para x86-64

# Tamanho de um 'word' na arquitetura atual (geralmente 8 bytes para x86-64)
# Isso pode ser lido de sys.maxsize ou os.sysconf, mas para PEEKDATA, 8 bytes é comum
WORD_SIZE = 8

def read_string(process, address):
    """
    Lê uma string terminada em nulo da memória do processo traceado.
    Retorna a string decodificada ou None em caso de erro.
    """
    if address == 0:
        return None

    data = b""
    offset = 0
    while True:
        try:
            # PTRACE_PEEKDATA retorna um word (8 bytes em x86-64)
            word = process.readWord(address + offset)
            # Converte o word para bytes
            current_bytes = struct.pack("<Q", word) # <Q para unsigned long long little-endian
            data += current_bytes

            if b'\0' in current_bytes:
                # String terminada em nulo encontrada
                break
            offset += WORD_SIZE
        except Exception as e:
            # print(f"Erro ao ler string em 0x{address + offset:x}: {e}", file=sys.stderr)
            return None # Retorna None em caso de erro de leitura

    try:
        # Decodifica os bytes até o primeiro nulo
        return data.split(b'\0', 1)[0].decode('utf-8', errors='replace')
    except UnicodeDecodeError:
        return data.split(b'\0', 1)[0].decode('latin-1', errors='replace') # Fallback
    except Exception as e:
        # print(f"Erro ao decodificar string: {e}", file=sys.stderr)
        return None

def read_data_at_address(process, address, size):
    """
    Lê uma quantidade específica de bytes da memória do processo traceado.
    Retorna bytes ou None em caso de erro.
    """
    if address == 0 or size == 0:
        return b""

    data = b""
    try:
        for offset in range(0, size, WORD_SIZE):
            word = process.readWord(address + offset)
            current_bytes = struct.pack("<Q", word)
            data += current_bytes
        return data[:size] # Retorna apenas o número exato de bytes solicitado
    except Exception as e:
        # print(f"Erro ao ler dados em 0x{address:x} (size={size}): {e}", file=sys.stderr)
        return None

def get_syscall_args(process, registers):
    """
    Retorna os argumentos da syscall do processo dado seus registradores.
    Adapta-se para arquitetura x86-64.
    """
    # x86_64_arg_regs contém a ordem dos registradores para os argumentos
    # [RDI, RSI, RDX, R10, R8, R9]
    args = []
    for reg_name in x86_64_arg_regs:
        args.append(getattr(registers, reg_name))
    return args

def get_syscall_num(registers):
    """
    Retorna o número da syscall do registrador RAX (orig_rax para entrada).
    """
    return registers.orig_rax

def get_syscall_return_value(registers):
    """
    Retorna o valor de retorno da syscall do registrador RAX.
    """
    return registers.rax