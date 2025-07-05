import socket
import threading
import os
import datetime
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import subprocess
try:
    import nmap
except ImportError:
    messagebox.showerror("Dependência Faltando", 
                         "A biblioteca 'python-nmap' não foi encontrada.\n"
                         "Por favor, instale-a com o comando: pip install python-nmap")
    exit()

# --- Classe Principal da Aplicação ---
class PortScannerApp:
    # Constante para o diretório de logs. Altere aqui se necessário.
    LOG_DIRECTORY = r"C:\Logs\Scan_log"

    def __init__(self, master):
        self.master = master
        self._setup_ui()

    def _setup_ui(self):
        self.master.title("Scanner de Portas Avançado (TCP, Nmap)")
        self.master.geometry("700x600")
        self.master.minsize(600, 500)

        # --- Variáveis de Controle ---
        self.launch_wireshark_var = tk.BooleanVar(value=False)
        self.nmap_scan_options = {
            "Scan SYN Stealth (Rápido, Admin)": "-sS -n",
            "Scan TCP Connect (Lento, Sem Admin)": "-sT -n",
            "Scan Intenso (Versão, SO, Scripts, Admin)": "-sV -sC -O -n",
            "Scan UDP (Muito Lento, Admin)": "-sU -n",
            "Scan Simples (Socket Básico)": "socket_scan"
        }

        # --- Estilos e Cores ---
        style = ttk.Style(self.master)
        style.theme_use('clam') # Um tema moderno
        
        # --- Widgets da UI ---
        self._create_input_frame()
        self._create_scan_options_frame()
        
        self.scan_button = ttk.Button(self.master, text="Escanear Agora", command=self.iniciar_scan_thread, style="Accent.TButton")
        self.scan_button.pack(pady=(5, 10))
        
        self._create_results_and_status_bar()
        self._configure_text_tags()

    def _create_input_frame(self):
        input_frame = ttk.Frame(self.master, padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Alvo (IP ou Host):").pack(side=tk.LEFT, padx=(0, 5))
        self.entry_ip = ttk.Entry(input_frame, width=25)
        self.entry_ip.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry_ip.insert(0, "127.0.0.1")

        ttk.Label(input_frame, text="Portas (ex: 1-1024):").pack(side=tk.LEFT, padx=(15, 5))
        self.entry_ports = ttk.Entry(input_frame, width=20)
        self.entry_ports.pack(side=tk.LEFT)
        self.entry_ports.insert(0, "1-1024")

    def _create_scan_options_frame(self):
        options_frame = ttk.LabelFrame(self.master, text="Opções de Scan", padding=10)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(options_frame, text="Método de Scan:").pack(anchor=tk.W)
        self.scan_method_combo = ttk.Combobox(options_frame, values=list(self.nmap_scan_options.keys()), state="readonly")
        self.scan_method_combo.pack(fill=tk.X, pady=(2, 10))
        self.scan_method_combo.current(0)
        
        ttk.Checkbutton(options_frame, text="Abrir Wireshark para capturar tráfego (se instalado)", 
                        variable=self.launch_wireshark_var).pack(anchor=tk.W)

    def _create_results_and_status_bar(self):
        results_frame = ttk.Frame(self.master, padding=(10, 0, 10, 0))
        results_frame.pack(fill=tk.BOTH, expand=True)

        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, width=70, height=20, relief=tk.SOLID, borderwidth=1)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.configure(state='disabled')

        self.status_var = tk.StringVar(value="Ocioso")
        status_bar = ttk.Label(self.master, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _configure_text_tags(self):
        self.results_text.tag_config('INFO', foreground='blue')
        self.results_text.tag_config('OPEN', foreground='#009900', font=('Helvetica', '9', 'bold'))
        self.results_text.tag_config('FILTERED', foreground='#FF8C00')
        self.results_text.tag_config('DETAIL', foreground='gray50')
        self.results_text.tag_config('ERROR', foreground='red')

    def update_status(self, message):
        self.master.after(0, self.status_var.set, message)

    def adicionar_log_gui(self, mensagem, tag=''):
        self.master.after(0, self._adicionar_log_gui_thread_safe, mensagem, tag)

    def _adicionar_log_gui_thread_safe(self, mensagem, tag):
        self.results_text.configure(state='normal')
        if tag:
            self.results_text.insert(tk.END, mensagem + "\n", tag)
        else:
            self.results_text.insert(tk.END, mensagem + "\n")
        self.results_text.configure(state='disabled')
        self.results_text.see(tk.END)

    def launch_wireshark(self):
        wireshark_paths = [r"C:\Program Files\Wireshark\Wireshark.exe", r"/usr/bin/wireshark", r"/usr/local/bin/wireshark"]
        path_encontrado = next((path for path in wireshark_paths if os.path.exists(path)), None)
        if not path_encontrado:
            self.adicionar_log_gui("[AVISO] Executável do Wireshark não encontrado.", 'ERROR')
            return
        try:
            self.adicionar_log_gui("Iniciando o Wireshark para captura de tráfego...", 'INFO')
            subprocess.Popen([path_encontrado])
        except Exception as e:
            self.adicionar_log_gui(f"[ERRO] Falha ao iniciar o Wireshark: {e}", 'ERROR')

    def iniciar_scan_thread(self):
        self.scan_button.config(state=tk.DISABLED)
        self.results_text.configure(state='normal')
        self.results_text.delete('1.0', tk.END)
        self.results_text.configure(state='disabled')

        if self.launch_wireshark_var.get():
            self.launch_wireshark()

        scan_thread = threading.Thread(target=self.executar_scan_dispatcher)
        scan_thread.daemon = True
        scan_thread.start()

    def executar_scan_dispatcher(self):
        self.update_status("Iniciando validação...")
        alvo = self.entry_ip.get()
        faixa_portas_str = self.entry_ports.get()
        selected_method = self.scan_method_combo.get()

        try:
            porta_inicio, porta_fim = map(int, faixa_portas_str.split('-'))
            if not (0 < porta_inicio <= porta_fim <= 65535): raise ValueError
        except ValueError:
            messagebox.showerror("Erro de Entrada", "Formato de portas inválido. Use 'inicio-fim'.")
            self.update_status("Erro de validação")
            self.master.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            return

        if self.nmap_scan_options[selected_method] == "socket_scan":
            self.executar_scan_socket(alvo, porta_inicio, porta_fim)
        else:
            nmap_args = self.nmap_scan_options[selected_method]
            self.executar_scan_nmap(alvo, faixa_portas_str, nmap_args)
        
        self.update_status("Ocioso")
        self.master.after(0, lambda: self.scan_button.config(state=tk.NORMAL))

    def executar_scan_nmap(self, alvo, faixa_portas, arguments):
        self.adicionar_log_gui(f"Iniciando Nmap em {alvo} com args: '{arguments}'...", 'INFO')
        self.update_status(f"Escaneando {alvo} (Nmap)...")
        
        scan_results_for_log = []
        try:
            nm = nmap.PortScanner()
            nm.scan(alvo, faixa_portas, arguments=arguments)
            
            if not nm.all_hosts():
                self.adicionar_log_gui(f"Host {alvo} parece estar offline ou não respondeu ao scan.", 'ERROR')
            else:
                for host in nm.all_hosts():
                    self.adicionar_log_gui(f"\nHost: {host} ({nm[host].hostname()})", 'INFO')
                    self.adicionar_log_gui(f"Estado: {nm[host].state()}", 'INFO')
                    
                    for proto in nm[host].all_protocols():
                        lport = sorted(nm[host][proto].keys())
                        for port in lport:
                            info = nm[host][proto][port]
                            estado = info['state'].upper()
                            tag = estado if estado in ['OPEN', 'FILTERED'] else ''
                            self.adicionar_log_gui(f"  Porta {port}/{proto}: {estado}", tag)

                            # Coleta de detalhes para GUI e log
                            service = info.get('name', 'n/a')
                            product = info.get('product', '')
                            version = info.get('version', '')
                            extrainfo = info.get('extrainfo', '')
                            details = f"    Serviço: {service} | Produto: {product} | Versão: {version} {extrainfo}".strip()
                            self.adicionar_log_gui(details, 'DETAIL')
                            
                            scan_results_for_log.append({
                                'port': port, 'proto': proto, 'state': estado,
                                'service': service, 'product': product, 'version': version
                            })
            self.adicionar_log_gui("\nEscaneamento com Nmap concluído.", 'INFO')
            self.salvar_log_detalhado(alvo, faixa_portas, scan_results_for_log)
        
        except nmap.nmap.PortScannerError:
            erro_msg = "Erro ao executar Nmap. Verifique se ele está no PATH e se você tem privilégios de admin."
            self.adicionar_log_gui(f"ERRO: {erro_msg}", 'ERROR')
            messagebox.showerror("Erro do Nmap", erro_msg)
        except Exception as e:
            self.adicionar_log_gui(f"Erro inesperado com Nmap: {e}", 'ERROR')

    def executar_scan_socket(self, alvo_ip, porta_inicio, porta_fim):
        self.update_status(f"Escaneando {alvo_ip} (Socket)...")
        self.adicionar_log_gui(f"Iniciando escaneamento SIMPLES em {alvo_ip}...", 'INFO')
        portas_abertas = []
        for porta in range(porta_inicio, porta_fim + 1):
            if not self.scan_button.cget('state') == 'disabled': break # Permite cancelar
            self.update_status(f"Verificando porta {porta}...")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    if sock.connect_ex((alvo_ip, porta)) == 0:
                        self.adicionar_log_gui(f"  Porta {porta}/tcp: ABERTA", 'OPEN')
                        portas_abertas.append({'port': porta, 'state': 'ABERTA'})
            except socket.gaierror:
                self.adicionar_log_gui(f"Hostname {alvo_ip} não pôde ser resolvido.", 'ERROR')
                break
            except socket.error as e:
                self.adicionar_log_gui(f"Erro de socket na porta {porta}: {e}", 'ERROR')

        self.adicionar_log_gui("\nEscaneamento simples concluído.", 'INFO')
        self.salvar_log_detalhado(alvo_ip, f"{porta_inicio}-{porta_fim}", portas_abertas)


    def salvar_log_detalhado(self, ip_alvo, faixa_portas, results):
        self.update_status("Salvando relatório...")
        try:
            os.makedirs(self.LOG_DIRECTORY, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
            nome_arquivo = os.path.join(self.LOG_DIRECTORY, f"scan_log_{ip_alvo.replace('.', '_')}_{timestamp}.txt")

            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                f.write("--- Relatório Detalhado de Escaneamento de Portas ---\n")
                f.write(f"Data/Hora: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                f.write(f"Alvo: {ip_alvo}\n")
                f.write(f"Faixa de Portas Verificada: {faixa_portas}\n")
                f.write(f"Método de Scan: {self.scan_method_combo.get()}\n")
                f.write("-" * 60 + "\n\n")

                if results:
                    f.write(f"{'PORTA':<8} {'ESTADO':<10} {'SERVIÇO':<20} {'VERSÃO DO PRODUTO'}\n")
                    f.write(f"{'='*8} {'='*10} {'='*20} {'='*30}\n")
                    for r in results:
                        line = (f"{str(r.get('port', 'N/A'))+'/'+r.get('proto', 'tcp'):<8} "
                                f"{r.get('state', 'N/A'):<10} "
                                f"{r.get('service', 'n/a'):<20} "
                                f"{r.get('product', '')} {r.get('version', '')}".strip())
                        f.write(line + "\n")
                else:
                    f.write("Nenhuma porta aberta ou informação relevante encontrada na faixa especificada.\n")

            self.adicionar_log_gui(f"Relatório detalhado salvo em: {nome_arquivo}", 'INFO')
        except PermissionError:
            erro_msg = f"Permissão negada para escrever em '{self.LOG_DIRECTORY}'. Execute como admin."
            self.adicionar_log_gui(f"ERRO: {erro_msg}", 'ERROR')
            messagebox.showerror("Erro de Permissão", erro_msg)
        except Exception as e:
            erro_msg = f"Erro inesperado ao salvar o log: {e}"
            self.adicionar_log_gui(f"ERRO: {erro_msg}", 'ERROR')
            messagebox.showerror("Erro ao Salvar Log", erro_msg)

# --- Bloco Principal para Iniciar a Aplicação ---
if __name__ == "__main__":
    root = tk.Tk()
    # Adiciona um estilo para o botão de destaque
    s = ttk.Style()
    s.configure("Accent.TButton", foreground="white", background="#0078D7", font=('Helvetica', 10, 'bold'))
    app = PortScannerApp(root)
    root.mainloop()