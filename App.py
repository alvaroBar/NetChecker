import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter import filedialog
import csv
import re
import time
import threading

# Importa a classe controladora
try:
    from TestOrchestrator import TestOrchestrator
except ImportError:
    messagebox.showerror("Erro Crítico",
                         "Não foi possível encontrar o arquivo 'TestOrchestrator.py'.\nCertifique-se de que todos os arquivos estão na mesma pasta.")
    exit()


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Ferramenta de Diagnóstico de Switch v14.7 (Uso de IP + Logs PoE)")
        self.root.geometry("850x800")

        # --- Carregar Dados ---
        self.all_schools_data = self.load_schools()
        self.school_map = {school['nome_escola']: school for school in self.all_schools_data}
        self.all_school_names = sorted(list(self.school_map.keys()))
        self.selected_school_name = None

        # --- Inicializar o Controlador ---
        self.orchestrator = TestOrchestrator(self)

        # --- Construir a Interface ---
        control_frame = ttk.LabelFrame(root, text="Controles de Teste")
        control_frame.pack(padx=10, pady=10, fill="x", side=tk.TOP)

        cred_frame = ttk.Frame(control_frame)
        cred_frame.pack(pady=5, padx=5, fill="x")

        ttk.Label(cred_frame, text="Buscar Escola:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.school_search_entry = ttk.Entry(cred_frame, width=40)
        self.school_search_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.school_search_entry.bind("<KeyRelease>", self._on_school_filter_change)

        list_frame = ttk.Frame(cred_frame)
        list_frame.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.school_listbox = tk.Listbox(list_frame, height=4, width=40, exportselection=False)
        self.school_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.school_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.school_listbox.config(yscrollcommand=scrollbar.set)
        self.school_listbox.bind("<<ListboxSelect>>", self._on_school_select)

        # --- Lógica de População Inicial Corrigida ---
        self._populate_school_listbox(self.all_school_names)
        if self.all_school_names:
            self.school_listbox.selection_set(0)
            # Chama o evento de seleção UMA VEZ no início para preencher o campo
            self._on_school_select(None)
            # Define o foco para a lista, para que a seleção inicial seja visível
            self.school_listbox.focus_set()

        ttk.Label(cred_frame, text="Usuário (Switch):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.user_entry = ttk.Entry(cred_frame, width=30)
        self.user_entry.insert(0, "admin")
        self.user_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        ttk.Label(cred_frame, text="Senha (Switch):").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.pass_entry = ttk.Entry(cred_frame, show="*", width=30)
        self.pass_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        cred_frame.columnconfigure(1, weight=1)

        tests_frame = ttk.LabelFrame(control_frame, text="Testes a Executar")
        tests_frame.pack(fill="x", padx=5, pady=10)

        self.test_vars = {
            "ping_operadora": tk.BooleanVar(value=True),
            "classify_clients": tk.BooleanVar(value=True),
            "neighbors": tk.BooleanVar(value=True),
            "clients": tk.BooleanVar(value=True),
            "ip_usage": tk.BooleanVar(value=True), # <--- ADICIONADO
            "health": tk.BooleanVar(value=True),
            "port_errors": tk.BooleanVar(value=True),
            "vlans": tk.BooleanVar(value=True),
            "loop_protection": tk.BooleanVar(value=True),
            "active_loops": tk.BooleanVar(value=True),
            "poe": tk.BooleanVar(value=True),
            "dhcp_logs": tk.BooleanVar(value=True),
        }

        check_frame = ttk.Frame(tests_frame)
        check_frame.pack(fill='x', padx=5)
        col1_frame = ttk.Frame(check_frame);
        col1_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10)
        col2_frame = ttk.Frame(check_frame);
        col2_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10)
        col3_frame = ttk.Frame(check_frame);
        col3_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10)

        ttk.Checkbutton(col1_frame, text="Ping Switch Operadora (.1)", variable=self.test_vars["ping_operadora"]).pack(
            anchor="w")
        ttk.Checkbutton(col1_frame, text="Classificar Conexão", variable=self.test_vars["classify_clients"]).pack(
            anchor="w")
        ttk.Checkbutton(col1_frame, text="Ping Vizinhos", variable=self.test_vars["neighbors"]).pack(anchor="w")
        ttk.Checkbutton(col1_frame, text="Ping Clientes (Cabo)", variable=self.test_vars["clients"]).pack(anchor="w")

        ttk.Checkbutton(col2_frame, text="Uso de IP (Rede/Máscara)", variable=self.test_vars["ip_usage"]).pack(anchor="w") # <--- ADICIONADO
        ttk.Checkbutton(col2_frame, text="Saúde (CPU/Mem)", variable=self.test_vars["health"]).pack(anchor="w")
        ttk.Checkbutton(col2_frame, text="Erros Portas", variable=self.test_vars["port_errors"]).pack(anchor="w")
        ttk.Checkbutton(col2_frame, text="VLANs", variable=self.test_vars["vlans"]).pack(anchor="w")
        ttk.Checkbutton(col2_frame, text="Status PoE", variable=self.test_vars["poe"]).pack(anchor="w")

        ttk.Checkbutton(col3_frame, text="Proteção Loop", variable=self.test_vars["loop_protection"]).pack(anchor="w")
        ttk.Checkbutton(col3_frame, text="Loops Ativos", variable=self.test_vars["active_loops"]).pack(anchor="w")
        ttk.Checkbutton(col3_frame, text="Logs (DHCP/PoE)", variable=self.test_vars["dhcp_logs"]).pack(anchor="w") # Texto atualizado

        btn_frame = ttk.Frame(tests_frame)
        btn_frame.pack(fill='x', pady=(5, 0), padx=5)
        ttk.Button(btn_frame, text="Marcar Todos", command=self.select_all_tests).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Desmarcar Todos", command=self.deselect_all_tests).pack(side=tk.LEFT, padx=5)

        self.start_button = ttk.Button(control_frame, text="Iniciar Testes Selecionados",
                                       command=self.orchestrator.run_test_in_thread)
        self.start_button.pack(pady=10)

        bottom_frame = ttk.Frame(root)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(0, 10))
        save_button = ttk.Button(bottom_frame, text="Salvar Log em Arquivo TXT", command=self.save_log_to_file)
        save_button.pack()

        results_frame = ttk.LabelFrame(root, text="Resultados")
        results_frame.pack(padx=10, pady=10, expand=True, fill="both", side=tk.TOP)
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, width=100, height=40,
                                                      font=("Courier New", 9))
        self.results_text.pack(padx=5, pady=5, expand=True, fill="both")

    def _populate_school_listbox(self, names):
        self.school_listbox.delete(0, tk.END)
        for name in names:
            self.school_listbox.insert(tk.END, name)

    def _on_school_filter_change(self, event):
        """Filtra a lista sem atualizar o campo de busca."""
        search_term = self.school_search_entry.get().lower()
        if not search_term:
            filtered_names = self.all_school_names
        else:
            filtered_names = [name for name in self.all_school_names if search_term in name.lower()]

        # Salva o nome que estava selecionado
        current_selection = self.selected_school_name

        self._populate_school_listbox(filtered_names)

        # Tenta re-selecionar o item que estava selecionado
        if current_selection in filtered_names:
            new_index = filtered_names.index(current_selection)
            self.school_listbox.selection_set(new_index)
        elif filtered_names:  # Se a seleção anterior sumiu, seleciona o primeiro
            self.school_listbox.selection_set(0)
            self._on_school_select(None)  # Atualiza a seleção interna

    def _on_school_select(self, event):
        """Atualiza a seleção e o campo de busca."""
        selection = self.school_listbox.curselection()
        if selection:
            index = selection[0]
            self.selected_school_name = self.school_listbox.get(index)

            # Só atualiza o campo de busca se o evento for um clique
            # ou se for a chamada inicial (event is None)
            if event is not None or self.school_search_entry.get() == "":
                current_filter = self.school_search_entry.get()
                if current_filter != self.selected_school_name:
                    self.school_search_entry.delete(0, tk.END)
                    self.school_search_entry.insert(0, self.selected_school_name)
        else:
            # Isso pode acontecer se a lista filtrada ficar vazia
            self.selected_school_name = None

    def load_schools(self):
        try:
            with open('escolas.csv', 'r', encoding='utf-8') as f:
                return list(csv.DictReader(f))
        except FileNotFoundError:
            messagebox.showerror("Erro Crítico", "Arquivo 'escolas.csv' não encontrado!")
            self.root.quit()
            return []

    def update_results(self, message):
        self.root.after(0, self._update_text, message)

    def _update_text(self, message):
        self.results_text.insert(tk.END, message)
        self.results_text.see(tk.END)

    def lock_buttons(self):
        self.start_button.config(state="disabled")

    def unlock_buttons(self):
        self.root.after(0, self._unlock_buttons_threadsafe)

    def _unlock_buttons_threadsafe(self):
        self.start_button.config(state="enabled")

    def select_all_tests(self):
        for var in self.test_vars.values(): var.set(True)

    def deselect_all_tests(self):
        for var in self.test_vars.values(): var.set(False)

    def save_log_to_file(self):
        log_content = self.results_text.get("1.0", tk.END)
        if not log_content.strip():
            messagebox.showwarning("Aviso", "Não há resultados para salvar.")
            return

        default_filename = "log_diagnostico.txt"
        if self.selected_school_name:
            safe_school_name = re.sub(r'[\\/*?:"<>|]', "", self.selected_school_name)
            timestamp = time.strftime("%Y%m%d_%H%M%S")  # Esta linha agora usa o módulo 'time'
            default_filename = f"log_{safe_school_name}_{timestamp}.txt"

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivos de Texto", "*.txt"), ("Todos os Arquivos", "*.*")],
            initialfile=default_filename,
            title="Salvar Log Como..."
        )

        if not filepath: return

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(log_content)
            messagebox.showinfo("Sucesso", f"Log salvo com sucesso em:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Erro ao Salvar", f"Não foi possível salvar o arquivo.\nDetalhes: {e}")

    def _skipped_summary(self, test_name):
        return f"⚪ {test_name}: NÃO EXECUTADO (desmarcado pelo usuário)\n\n"

    # --- FUNÇÃO DE RESUMO MODIFICADA (DUPLICADA DO ORCHESTRATOR) ---
    def generate_and_display_summary(self, data, tests_selected):
        summary = "\n\n==================== RESUMO DO DIAGNÓSTICO ====================\n\n"

        skipped_summary = self._skipped_summary

        executed_lines = []
        skipped_lines = []

        if not data.get('connection'):
            summary += f"❌ Conexão com o Switch da Escola: FALHA\n\n"
            operadora_ping = data.get('operadora_ping', {})
            if not operadora_ping.get('skipped', True) and operadora_ping.get('local'):
                op_ip = operadora_ping.get('ip', 'N/A')
                op_status = operadora_ping.get('status', 'Falha')
                op_icon = "✅" if op_status == "Sucesso" else "❌"
                executed_lines.append(f"{op_icon} Ping LOCAL para Switch Operadora ({op_ip}): {op_status.upper()}")
            elif not operadora_ping.get('skipped'):
                skipped_lines.append(skipped_summary("Ping Switch Operadora (.1)"))

            for test_name, data_dict in data.items():
                if data_dict == {'skipped': True} and test_name != 'operadora_ping':
                    friendly_names = {
                        'neighbors': 'Teste de Vizinhança',
                        'clients': 'Teste de Clientes',
                        'ip_usage': 'Verificação de Uso de IP', # <--- ADICIONADO
                        'health_status': 'Saúde do Switch',
                        'port_errors': 'Verificação de Erros nas Portas',
                        'vlan_status': 'Verificação de VLANs',
                        'poe_status': 'Status do PoE',
                        'loopback': 'Proteção Contra Loops',
                        'active_loop': 'Verificação de Loops Ativos',
                        'dhcp_logs': 'Verificação de Logs DHCP',
                        'poe_log_errors': 'Verificação de Logs PoE' # <--- ADICIONADO
                    }
                    skipped_lines.append(skipped_summary(friendly_names.get(test_name, test_name)))

            if executed_lines:
                summary += "--- TESTES EXECUTADOS ---\n\n"
                summary += "\n\n".join(executed_lines)

            if skipped_lines:
                summary += "\n\n--- TESTES NÃO EXECUTADOS ---\n\n"
                summary += "".join(skipped_lines)

            summary += "\n===============================================================\n"
            self.update_results(summary)
            return

        summary += f"✅ Conexão com o Switch da Escola: SUCESSO\n"
        summary += f"   - Modelo do Switch Identificado: {data.get('model', 'N/A').upper()}\n\n"

        if all(val == {'skipped': True} for key, val in data.items() if key not in ['connection', 'model']):
            summary += "⚪ Nenhum teste foi selecionado para execução.\n\n"
            self.update_results(summary)
            return

        operadora_ping = data.get('operadora_ping', {})
        if operadora_ping.get('skipped'):
            skipped_lines.append(skipped_summary("Ping Switch Operadora (.1)"))
        else:
            op_ip = operadora_ping.get('ip', 'N/A')
            op_status = operadora_ping.get('status', 'Falha')
            op_icon = "✅" if op_status == "Sucesso" else "❌"
            executed_lines.append(f"{op_icon} Ping Switch Operadora ({op_ip}): {op_status.upper()}")

        # --- BLOCO NOVO: USO DE IP ---
        ip_usage_data = data.get('ip_usage', {})
        if ip_usage_data.get('skipped'):
            skipped_lines.append(skipped_summary("Verificação de Uso de IP"))
        elif ip_usage_data.get('total'):
            used, total, mask = ip_usage_data['used'], ip_usage_data['total'], ip_usage_data['mask']
            percent = (used / total) * 100 if total > 0 else 0
            icon = "⚠️" if percent > 85 else "✅" # Alerta se uso for > 85%
            executed_lines.append(f"{icon} Utilização de IP: {used} de {total} IPs em uso ({percent:.1f}%)")
            executed_lines.append(f"   - Máscara de Rede: {mask}")
        else:
            executed_lines.append(f"⚠️ Utilização de IP: {ip_usage_data.get('used', 0)} IPs contados (Não foi possível obter máscara/total).")


        health_status = data.get('health_status', {})
        if health_status.get('skipped'):
            skipped_lines.append(skipped_summary("Saúde do Switch"))
        elif 'cpu' in health_status and 'memory' in health_status:
            cpu, mem = health_status['cpu'], health_status['memory']
            cpu_icon = "⚠️" if cpu > 75 else "✅"
            mem_icon = "⚠️" if mem > 75 else "✅"
            executed_lines.append(f"{cpu_icon} Saúde do Switch (CPU): {cpu}%")
            executed_lines.append(f"{mem_icon} Saúde do Switch (Memória): {mem}%")
        else:
            executed_lines.append(f"⚠️ Saúde do Switch: Não foi possível verificar.")

        poe_status = data.get('poe_status', {})
        if poe_status.get('skipped'):
            skipped_lines.append(skipped_summary("Status do PoE"))
        elif poe_status and 'limit' in poe_status and 'consumption' in poe_status:
            limit, consumption = poe_status['limit'], poe_status['consumption']
            if limit > 0:
                usage_percent = (consumption / limit) * 100
                icon = "⚠️" if usage_percent > 80 else "✅"
                executed_lines.append(
                    f"{icon} Consumo de Energia (PoE): {consumption:.2f}W de {limit:.2f}W utilizados ({usage_percent:.1f}%).")
            else:
                executed_lines.append(f"✅ Consumo de Energia (PoE): {consumption:.2f}W utilizados.")
        else:
            executed_lines.append(f"⚠️ Consumo de Energia (PoE): Não foi possível verificar.")

        port_errors_data = data.get('port_errors', {})
        if port_errors_data.get('skipped'):
            skipped_lines.append(skipped_summary("Verificação de Erros nas Portas"))
        else:
            port_error_status = port_errors_data.get('status', 'Não verificado')
            ports_with_errors = port_errors_data.get('ports', [])
            if "ERROS ENCONTRADOS" in port_error_status:
                executed_lines.append(f"❌ Verificação de Erros nas Portas: ENCONTRADOS!")
                executed_lines.append(f"   - Portas com erros: {', '.join(ports_with_errors)}")
            elif "Nenhum erro" in port_error_status:
                executed_lines.append(f"✅ Verificação de Erros nas Portas: Nenhum erro encontrado.")
            else:
                executed_lines.append(f"⚠️ Verificação de Erros nas Portas: {port_error_status}.")

        vlan_data = data.get('vlan_status', {})
        if vlan_data.get('skipped'):
            skipped_lines.append(skipped_summary("Verificação de VLANs"))
        else:
            vlan_status_msg = vlan_data.get('status', 'Não verificado')
            vlan_list = vlan_data.get('vlans', [])
            if vlan_list:
                vlan_ids = ", ".join([v['id'] for v in vlan_list])
                executed_lines.append(f"✅ Verificação de VLANs: {vlan_status_msg}")
                executed_lines.append(f"   - IDs Encontrados: {vlan_ids}")
            else:
                executed_lines.append(f"⚠️ Verificação de VLANs: {vlan_status_msg}.")

        neighbors_data = data.get('neighbors', {})
        if neighbors_data.get('skipped'):
            skipped_lines.append(skipped_summary("Teste de Vizinhança"))
        elif not neighbors_data.get('found'):
            executed_lines.append(f"⚠️ Teste de Vizinhança: Nenhum dispositivo de infraestrutura foi encontrado.")
        else:
            success_count = sum(1 for status in neighbors_data['results'].values() if status == 'Sucesso')
            total_count = len(neighbors_data['results'])
            icon = "✅" if success_count == total_count else "⚠️"
            executed_lines.append(f"{icon} Teste de Vizinhança: {success_count}/{total_count} pings bem-sucedidos.")
            for ip, status in neighbors_data['results'].items():
                executed_lines.append(f"   - IP: {ip} -> {status}")

        clients_data = data.get('clients', {})
        if clients_data.get('skipped'):
            skipped_lines.append(skipped_summary("Teste de Clientes"))
        elif not clients_data.get('found'):
            client_type_msg = 'Via Cabo' if self.test_vars["classify_clients"].get() else ''
            executed_lines.append(f"⚠️ Teste de Clientes: Nenhum cliente ({client_type_msg}) foi testado.")
        else:
            success_count = sum(1 for res in clients_data['results'].values() if res['status'] == 'Sucesso')
            total_count = len(clients_data['results'])
            icon = "✅" if success_count == total_count else "⚠️"
            executed_lines.append(f"{icon} Teste de Clientes: {success_count}/{total_count} pings bem-sucedidos.")
            for dev in clients_data['found']:
                ip = dev['ip']
                conn_type = dev.get('type', 'Desconhecido')
                result = clients_data['results'].get(ip, {}).get('status', 'N/A')
                executed_lines.append(f"   - IP: {ip} ({conn_type}) -> {result}")

        loopback_status = data.get('loopback')
        if isinstance(loopback_status, dict) and loopback_status.get('skipped'):
            skipped_lines.append(skipped_summary("Proteção Contra Loops"))
        elif loopback_status == 'Ativado':
            executed_lines.append(f"✅ Proteção Contra Loops (Funcionalidade): ATIVADO")
        else:
            executed_lines.append(f"⚠️ Proteção Contra Loops (Funcionalidade): {str(loopback_status).upper()}")

        active_loop_data = data.get('active_loop', {})
        if active_loop_data.get('skipped'):
            skipped_lines.append(skipped_summary("Verificação de Loops Ativos"))
        else:
            loop_status_msg = active_loop_data.get('status', 'Não verificado')
            blocked_ports = active_loop_data.get('ports', [])
            if "LOOP DETECTADO" in loop_status_msg:
                executed_lines.append(f"❌ ALERTA DE LOOP ATIVO: ENCONTRADO!")
                executed_lines.append(f"   - O switch bloqueou as seguintes portas: {', '.join(blocked_ports)}")
            else:
                executed_lines.append(f"✅ Verificação de Loops Ativos: Nenhum loop encontrado no momento.")

        # --- BLOCO DE LOGS DHCP (MODIFICADO) ---
        dhcp_logs_data = data.get('dhcp_logs', {})
        if dhcp_logs_data.get('skipped'):
            skipped_lines.append(skipped_summary("Verificação de Logs (DHCP/PoE)"))
        else:
            log_status_msg = dhcp_logs_data.get('status', 'Não verificado')
            log_lines = dhcp_logs_data.get('lines', [])
            if "ERROS DHCP ENCONTRADOS" in log_status_msg:
                executed_lines.append(f"❌ Verificação de Logs DHCP: ERROS ENCONTRADOS!")
                executed_lines.append(f"   - Exemplo: {log_lines[0] if log_lines else 'N/A'}")
            elif "Nenhum erro" in log_status_msg:
                executed_lines.append(f"✅ Verificação de Logs DHCP: Nenhum erro encontrado nos logs recentes.")
            else:
                executed_lines.append(f"⚠️ Verificação de Logs DHCP: {log_status_msg}.")

        # --- BLOCO NOVO: LOGS POE ---
        poe_logs_data = data.get('poe_log_errors', {})
        if poe_logs_data.get('skipped'):
            # Já tratado pelo skip do DHCP
            pass
        else:
            poe_log_status_msg = poe_logs_data.get('status', 'Não verificado')
            poe_log_lines = poe_logs_data.get('lines', [])
            if "ERROS PoE ENCONTRADOS" in poe_log_status_msg:
                executed_lines.append(f"❌ Verificação de Logs PoE: ERROS ENCONTRADOS!")
                executed_lines.append(f"   - Exemplo: {poe_log_lines[0] if poe_log_lines else 'N/A'}")
            elif "Nenhum erro" in poe_log_status_msg:
                executed_lines.append(f"✅ Verificação de Logs PoE: Nenhum erro encontrado nos logs recentes.")
            else:
                executed_lines.append(f"⚠️ Verificação de Logs PoE: {poe_log_status_msg}.")


        # --- Agora, constrói a string final do sumário ---
        if executed_lines:
            summary += "--- TESTES EXECUTADOS ---\n\n"
            summary += "\n\n".join(executed_lines)  # Adiciona espaço entre cada bloco de teste

        if skipped_lines:
            summary += "\n\n--- TESTES NÃO EXECUTADOS ---\n\n"
            summary += "".join(skipped_lines)  # skipped_summary já inclui \n\n

        summary += "\n===============================================================\n"
        self.update_results(summary)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()