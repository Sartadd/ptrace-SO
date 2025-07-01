# syscall_logger/main.py

import argparse
import sys
import os
import json
import time
import errno
from datetime import datetime

# Importa classes e funções da biblioteca python-ptrace
from ptrace.syscall import SYSCALL_BEFORE, SYSCALL_AFTER
from ptrace import PtraceError
from ptrace.debugger import PtraceDebugger, Application
from ptrace.tools import locateProgram

# Importa módulos internos
from syscall_logger.syscall_table import get_syscall_name
from syscall_logger.syscall_handlers import format_syscall_args
from syscall_logger.ptrace_utils import get_syscall_args, get_syscall_num, get_syscall_return_value

class SyscallLogger(Application):
    """
    Classe principal do logger de syscalls, estende ptrace.debugger.Application.
    """
    def __init__(self, output_file=sys.stdout, output_format="text"):
        super().__init__()
        self.output_file = output_file
        self.output_format = output_format
        self.debugger = PtraceDebugger()
        self.logged_entries = [] # Para formato JSON, coletar antes de escrever

    def quit(self):
        """Chamado quando a aplicação termina."""
        self.debugger.quit()
        if self.output_format == "json":
            # Escreve o array JSON completo no final
            json.dump(self.logged_entries, self.output_file, indent=2)
        if self.output_file != sys.stdout:
            self.output_file.close()

    def process_exited(self, process):
        """Chamado quando um processo monitorado termina."""
        # print(f"[*] Processo {process.pid} terminou.", file=sys.stderr)
        pass

    def process_syscall(self, process, syscall_state):
        """
        Chamado quando uma syscall é interceptada.
        syscall_state: SYSCALL_BEFORE (entrada) ou SYSCALL_AFTER (saída).
        """
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] # ms precision

        if syscall_state == SYSCALL_BEFORE:
            # Captura os registradores na entrada da syscall
            registers = process.getregs()
            syscall_num = get_syscall_num(registers)
            syscall_name = get_syscall_name(syscall_num)
            
            # Guarda os argumentos no processo para uso na saída
            process.syscall_entry_args = get_syscall_args(process, registers)
            process.syscall_entry_name = syscall_name
            process.syscall_entry_num = syscall_num
            process.syscall_entry_time = current_time

        elif syscall_state == SYSCALL_AFTER:
            # Captura os registradores na saída da syscall
            registers = process.getregs()
            syscall_num = get_syscall_num(registers) # Still the same syscall num
            syscall_name = process.syscall_entry_name # Get name from entry state
            
            # Obtém o valor de retorno e o erro (se houver)
            return_value = get_syscall_return_value(registers)
            error_code = 0
            if return_value < 0:
                # Em Linux, o valor de retorno negativo de uma syscall falha é -errno
                error_code = -return_value 
                # Ajusta return_value para ser 0 ou um valor positivo para falhas
                # se quisermos exibir o erro separadamente.
                # Ou mantemos o negativo e apenas indicamos o erro_code.
                
            # Recupera os argumentos da entrada da syscall
            args = getattr(process, 'syscall_entry_args', [])
            
            # Decodifica os argumentos
            decoded_args_str = format_syscall_args(process, syscall_num, args)

            # Prepara a entrada de log
            log_entry = {
                "timestamp": process.syscall_entry_time,
                "pid": process.pid,
                "syscall_name": syscall_name,
                "arguments": decoded_args_str,
                "return_value": hex(return_value), # Formata como hexadecimal
                "error_code": error_code,
                "error_name": errno.errorcode.get(error_code, "") if error_code else ""
            }

            self._write_log_entry(log_entry)

    def _write_log_entry(self, entry):
        """Escreve a entrada de log no formato especificado."""
        if self.output_format == "text":
            error_info = f" ({entry['error_name']})" if entry['error_code'] else ""
            self.output_file.write(
                f"[{entry['timestamp']}] PID {entry['pid']}: {entry['syscall_name']}({entry['arguments']}) = {entry['return_value']}{error_info}\n"
            )
        elif self.output_format == "csv":
            # Escapa aspas duplas dentro das strings para CSV
            escaped_args = entry['arguments'].replace('"', '""')
            self.output_file.write(
                f'"{entry['timestamp']}",{entry['pid']},"{entry['syscall_name']}","{escaped_args}",{entry['return_value']},{entry['error_code']}\n'
            )
        elif self.output_format == "json":
            # Para JSON, coletamos as entradas e as despejamos de uma vez no final
            self.logged_entries.append(entry)
        self.output_file.flush()

    def _run(self, args):
        """Método interno para iniciar o monitoramento."""
        if args.pid:
            try:
                process = self.debugger.attach(args.pid)
                process.setoptions(PtraceDebugger.PTRACE_O_TRACEEXIT | PtraceDebugger.PTRACE_O_TRACESYSGOOD)
                print(f"[*] Anexando ao processo PID {args.pid}...", file=sys.stderr)
            except PtraceError as e:
                print(f"Erro ao anexar ao PID {args.pid}: {e}", file=sys.stderr)
                sys.exit(1)
            
        elif args.command:
            try:
                # locateProgram para encontrar o caminho completo do executável
                executable_path = locateProgram(args.command[0])
                if not executable_path:
                    print(f"Erro: Comando '{args.command[0]}' não encontrado.", file=sys.stderr)
                    sys.exit(1)

                process = self.debugger.trace(args.command, executable_path)
                process.setoptions(PtraceDebugger.PTRACE_O_TRACEEXIT | PtraceDebugger.PTRACE_O_TRACESYSGOOD | \
                                   PtraceDebugger.PTRACE_O_TRACEFORK | PtraceDebugger.PTRACE_O_TRACEVFORK | \
                                   PtraceDebugger.PTRACE_O_TRACECLONE | PtraceDebugger.PTRACE_O_TRACEEXEC)
                print(f"[*] Iniciando e monitorando comando: '{' '.join(args.command)}' (PID {process.pid})...", file=sys.stderr)
            except PtraceError as e:
                print(f"Erro ao iniciar comando '{' '.join(args.command)}': {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print("Erro: Nenhum PID ou comando especificado para monitorar.", file=sys.stderr)
            sys.exit(1)

        # Escreve o cabeçalho CSV se o formato for CSV
        if self.output_format == "csv":
            self.output_file.write("Timestamp,PID,SyscallName,Arguments,ReturnValue,ErrorCode,ErrorName\n")
            self.output_file.flush()
            
        try:
            self.debugger.run() # Inicia o loop de monitoramento
        except PtraceError as e:
            print(f"Erro durante o monitoramento: {e}", file=sys.stderr)
        except KeyboardInterrupt:
            print("\n[*] Monitoramento interrompido pelo usuário.", file=sys.stderr)
        finally:
            self.quit() # Garante que os recursos sejam liberados

def main():
    parser = argparse.ArgumentParser(
        description="Logger de Chamadas de Sistema em Python usando ptrace.",
        epilog="Exemplos: \n  sudo python3 main.py 12345\n  sudo python3 main.py --format csv --output log.csv /bin/ls -la"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "pid", nargs="?", type=int,
        help="PID do processo a ser monitorado."
    )
    group.add_argument(
        "command", nargs=argparse.REMAINDER,
        help="Comando a ser executado e monitorado (ex: /bin/ls -la)."
    )
    parser.add_argument(
        "--output", "-o", type=str,
        help="Caminho para o arquivo de saída. Padrão: stdout.",
        default=None
    )
    parser.add_argument(
        "--format", "-f", type=str, choices=["text", "csv", "json"],
        help="Formato de saída do log. Padrão: text.",
        default="text"
    )

    args = parser.parse_args()

    output_file = sys.stdout
    if args.output:
        try:
            output_file = open(args.output, "w")
        except IOError as e:
            print(f"Erro: Não foi possível abrir o arquivo de saída '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)

    # Verifica permissões: ptrace geralmente requer root
    if os.geteuid() != 0:
        print("Aviso: ptrace geralmente requer privilégios de root (execute com 'sudo').", file=sys.stderr)

    logger_app = SyscallLogger(output_file=output_file, output_format=args.format)
    logger_app._run(args)

if __name__ == "__main__":
    main()