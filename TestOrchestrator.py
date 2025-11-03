import os
import threading
import traceback
import random
import platform
import re
import time
from tkinter import messagebox
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# Importa o Model
from SwitchTester import SwitchTester


class TestOrchestrator:
    def __init__(self, view):
        """
        Inicializa o controlador.
        :param view: A instância da classe App (a interface gráfica).
        """
        self.view = view  # Referência à instância da App (GUI)

    def _run_local_ping(self, target_ip):
        """Executa um ping a partir da máquina local."""
        self.view.update_results(f"    - Executando ping local para {target_ip}...\n")
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = f"ping {param} 1 {target_ip}"
        response = os.system(
            command + " > NUL 2>&1" if platform.system().lower() == 'windows' else command + " > /dev/null 2>&1")
        if response == 0:
            self.view.update_results(f"      - Resultado: Sucesso\n")
            return "Sucesso"
        else:
            self.view.update_results(f"      - Resultado: Falha\n")
            return "Falha"

    def run_test_in_thread(self):
        """Pega os dados da GUI e inicia o teste em uma nova thread."""
        if not self.view.selected_school_name:
            messagebox.showwarning("Aviso", "Por favor, selecione uma escola na lista.")
            return

        school_info = self.view.school_map.get(self.view.selected_school_name)
        if not school_info:
            messagebox.showerror("Erro",
                                 f"Não foi possível encontrar os dados para a escola: {self.view.selected_school_name}")
            return

        credentials = {
            "username": self.view.user_entry.get(),
            "password": self.view.pass_entry.get()
        }
        tests_selected = {key: var.get() for key, var in self.view.test_vars.items()}

        self.view.lock_buttons()
        self.view.results_text.delete(1.0, "end")

        threading.Thread(
            target=self._run_test_logic,
            args=(school_info, credentials, tests_selected),
            daemon=True
        ).start()

    def _run_test_logic(self, school_info, credentials, tests_selected):
        """Contém toda a lógica de execução do teste."""
        tester = None
        summary_data = {}
        try:
            username = credentials["username"]
            password = credentials["password"]

            if not any(tests_selected.values()):
                self.view.update_results("\nNenhum teste foi selecionado. Encerrando.\n")
                self._generate_and_display_summary({'connection': True, 'model': 'N/A (testes ignorados)'},
                                                   tests_selected)
                return

            if not username or not password:
                self.view.update_results("ERRO: Por favor, insira o usuário e senha do Switch.\n")
                return

            nome_escola = school_info['nome_escola']
            ip_switch = school_info['ip_switch_referencia']
            self.view.update_results(f"--- INICIANDO TESTES NO SWITCH: {nome_escola} ({ip_switch}) ---\n\n")

            self.view.update_results("PASSO 1: Conectando e identificando o switch...\n")
            tester = SwitchTester(host=ip_switch, username=username, password=password,
                                  update_callback=self.view.update_results)
            connected, model = tester.connect_and_identify()
            summary_data['connection'] = connected
            summary_data['model'] = model

            if not connected:
                self.view.update_results(
                    f"\n[FALHA GERAL] Não foi possível conectar ao switch da escola ({ip_switch}).\n")
                if tests_selected['ping_operadora']:
                    self.view.update_results(
                        "\nPASSO 2 (Fallback): Tentando ping local para Switch da Operadora (.1)...\n")
                    ip_parts = ip_switch.split('.')
                    if len(ip_parts) == 4:
                        operadora_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
                        status = self._run_local_ping(operadora_ip)
                        summary_data['operadora_ping'] = {'ip': operadora_ip, 'status': status, 'local': True}
                    else:
                        summary_data['operadora_ping'] = {'ip': 'N/A', 'status': 'IP inválido', 'local': True}
                    self.view.update_results("\n")
                else:
                    summary_data['operadora_ping'] = {'skipped': True}
                for test_key in tests_selected:
                    if test_key != 'ping_operadora' and test_key not in summary_data:
                        summary_data[test_key] = {'skipped': True}

            else:
                self.view.update_results(f"\n[INFO] Modelo final para os testes: {model.upper()}\n\n")

                step = 2

                if tests_selected['ping_operadora']:
                    self.view.update_results(f"PASSO {step}: Testando Ping (do Switch) para Operadora (.1)...\n");
                    step += 1
                    ip_parts = ip_switch.split('.')
                    if len(ip_parts) == 4:
                        operadora_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
                        status = tester.run_ping(operadora_ip)
                        summary_data['operadora_ping'] = {'ip': operadora_ip, 'status': status, 'local': False}
                    else:
                        summary_data['operadora_ping'] = {'ip': 'N/A', 'status': 'IP inválido', 'local': False}
                    self.view.update_results("\n")
                else:
                    summary_data['operadora_ping'] = {'skipped': True}

                all_devices, neighbors_found, clients_found = [], [], []
                # Executa a descoberta de dispositivos (baseada em IP/ARP) se *qualquer* teste de ping estiver selecionado
                if tests_selected['neighbors'] or tests_selected['clients'] or tests_selected['classify_clients']:
                    if tests_selected['classify_clients']:
                        self.view.update_results(
                            f"PASSO {step}: Mapeando e classificando dispositivos (para PING)...\n");
                        step += 1
                        all_devices = tester.discover_and_classify_devices()
                    else:
                        self.view.update_results(
                            f"PASSO {step}: Buscando dispositivos na rede (via ARP para PING)...\n");
                        step += 1
                        all_devices = tester.discover_all_devices_from_arp()

                    neighbors_found = [dev for dev in all_devices if dev['ip'].endswith(('.1', '.4', '.5'))]
                    if tests_selected['classify_clients'] and tests_selected['clients']:
                        clients_found = [dev for dev in all_devices if
                                         not dev['ip'].endswith(('.1', '.4', '.5')) and dev['type'] == 'Via Cabo']
                    elif tests_selected['clients']:
                        clients_found = [dev for dev in all_devices if not dev['ip'].endswith(('.1', '.4', '.5'))]
                    else:
                        clients_found = []

                    self.view.update_results(
                        f"  - Total de {len(all_devices)} dispositivos (baseados em IP/ARP) encontrados para ping.\n\n")

                # --- PASSO USO DE IP (MODIFICADO) ---
                if tests_selected['ip_usage']:
                    self.view.update_results(f"PASSO {step}: Verificando Uso de IP (Contagem de MACs)...\n");
                    step += 1
                    # 1. Busca o total de IPs pela máscara
                    network_info = tester.get_network_info()

                    # 2. Busca os IPs em uso pela contagem da tabela MAC
                    used_hosts = tester.get_mac_address_count()

                    summary_data['ip_usage'] = {
                        'used': used_hosts,
                        'total': network_info.get('total_hosts'),
                        'mask': network_info.get('mask')
                    }
                    self.view.update_results("\n")
                else:
                    summary_data['ip_usage'] = {'skipped': True}
                # --- FIM DA MODIFICAÇÃO ---

                if tests_selected['neighbors']:
                    self.view.update_results(f"PASSO {step}: Testando Vizinhos (Infraestrutura)...\n");
                    step += 1
                    neighbors_to_test = random.sample(neighbors_found, min(len(neighbors_found), 3))
                    summary_data['neighbors'] = {'found': [n['ip'] for n in neighbors_to_test], 'results': {}}
                    if not neighbors_to_test:
                        self.view.update_results("  Nenhum vizinho (baseado em ARP) encontrado para pingar.\n\n")
                    else:
                        for dev in neighbors_to_test:
                            status = tester.run_ping(dev['ip'])
                            summary_data['neighbors']['results'][dev['ip']] = status
                        self.view.update_results("\n")
                else:
                    summary_data['neighbors'] = {'skipped': True}

                if tests_selected['clients']:
                    self.view.update_results(f"PASSO {step}: Testando Clientes (Dispositivos Finais)...\n");
                    step += 1
                    clients_to_test = random.sample(clients_found, min(len(clients_found), 3))
                    summary_data['clients'] = {'found': clients_to_test, 'results': {}}
                    client_type_msg = 'Via Cabo' if tests_selected['classify_clients'] else 'Desconhecido'
                    if not clients_to_test:
                        self.view.update_results(
                            f"  Nenhum cliente (baseado em ARP, tipo: {client_type_msg}) encontrado para pingar.\n\n")
                    else:
                        for dev in clients_to_test:
                            status = tester.run_ping(dev['ip'])
                            summary_data['clients']['results'][dev['ip']] = {'status': status, 'type': dev['type']}
                        self.view.update_results("\n")
                else:
                    summary_data['clients'] = {'skipped': True}

                if tests_selected['health']:
                    self.view.update_results(f"PASSO {step}: Verificando Saúde do Switch (CPU/Memória)...\n");
                    step += 1
                    summary_data['health_status'] = tester.check_health()
                    self.view.update_results("\n")
                else:
                    summary_data['health_status'] = {'skipped': True}

                if tests_selected['port_errors']:
                    self.view.update_results(f"PASSO {step}: Verificando Erros nas Portas...\n");
                    step += 1
                    status, ports = tester.check_port_errors()
                    summary_data['port_errors'] = {'status': status, 'ports': ports}
                    self.view.update_results("\n")
                else:
                    summary_data['port_errors'] = {'skipped': True}

                if tests_selected['vlans']:
                    self.view.update_results(f"PASSO {step}: Verificando Configuração de VLANs...\n");
                    step += 1
                    status, vlist = tester.check_vlan_status()
                    summary_data['vlan_status'] = {'status': status, 'vlans': vlist}
                    self.view.update_results("\n")
                else:
                    summary_data['vlan_status'] = {'skipped': True}

                if tests_selected['poe']:
                    self.view.update_results(f"PASSO {step}: Verificando status do PoE...\n");
                    step += 1
                    summary_data['poe_status'] = tester.check_poe_status()
                    self.view.update_results("\n")
                else:
                    summary_data['poe_status'] = {'skipped': True}

                if tests_selected['loop_protection']:
                    self.view.update_results(
                        f"PASSO {step}: Verificando se a proteção contra loop está habilitada...\n");
                    step += 1
                    summary_data['loopback'] = tester.check_loopback_detection()
                    self.view.update_results("\n")
                else:
                    summary_data['loopback'] = {'skipped': True}

                if tests_selected['active_loops']:
                    self.view.update_results(f"PASSO {step}: Verificando se há loops ATIVOS na rede...\n");
                    step += 1
                    status, ports = tester.check_for_active_loops()
                    summary_data['active_loop'] = {'status': status, 'ports': ports}
                    self.view.update_results("\n")
                else:
                    summary_data['active_loop'] = {'skipped': True}

                if tests_selected['dhcp_logs']:
                    self.view.update_results(f"PASSO {step}: Verificando Logs por erros (DHCP, PoE, etc.)...\n");
                    step += 1
                    log_results = tester.check_system_logs()

                    summary_data['dhcp_logs'] = log_results.get('dhcp', {'status': 'Falha na verificação', 'lines': []})
                    if summary_data['dhcp_logs']['lines']:
                        self.view.update_results("      [ERROS DE DHCP ENCONTRADOS NOS LOGS]\n")
                        for line in summary_data['dhcp_logs']['lines'][:3]: self.view.update_results(
                            f"        - {line}\n")

                    summary_data['poe_log_errors'] = log_results.get('poe',
                                                                     {'status': 'Falha na verificação', 'lines': []})
                    if summary_data['poe_log_errors']['lines']:
                        self.view.update_results("      [ERROS DE PoE ENCONTRADOS NOS LOGS]\n")
                        for line in summary_data['poe_log_errors']['lines'][:3]: self.view.update_results(
                            f"        - {line}\n")

                    if not summary_data['dhcp_logs']['lines'] and not summary_data['poe_log_errors']['lines']:
                        self.view.update_results(
                            "      [INFO] Nenhum erro crítico de DHCP ou PoE encontrado nos logs.\n")

                    self.view.update_results("\n")
                else:
                    summary_data['dhcp_logs'] = {'skipped': True}
                    summary_data['poe_log_errors'] = {'skipped': True}

                self.view.update_results(f"PASSO {step}: Encerrando a conexão...\n")
                tester.disconnect()
                self.view.update_results("  [OK] Conexão SSH encerrada.\n")

            self.view.update_results("\n--- TESTE DO SWITCH CONCLUÍDO ---\n")
            self._generate_and_display_summary(summary_data, tests_selected)

        except Exception:
            self.view.update_results(f"\n\n[ERRO CRÍTICO INESPERADO NA ROTINA DE TESTE]\n")
            self.view.update_results(f"Detalhes: {traceback.format_exc()}\n")
            if tester and tester.connection:
                try:
                    tester.disconnect()
                except:
                    pass
                self.view.update_results("\n  [INFO] Conexão com o switch foi encerrada devido ao erro.\n")
        finally:
            self.view.unlock_buttons()

    def _skipped_summary(self, test_name):
        return f"⚪ {test_name}: NÃO EXECUTADO (desmarcado pelo usuário)\n\n"

    def _generate_and_display_summary(self, data, tests_selected):
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
                        'ip_usage': 'Verificação de Uso de IP',
                        'health_status': 'Saúde do Switch',
                        'port_errors': 'Verificação de Erros nas Portas',
                        'vlan_status': 'Verificação de VLANs',
                        'poe_status': 'Status do PoE',
                        'loopback': 'Proteção Contra Loops',
                        'active_loop': 'Verificação de Loops Ativos',
                        'dhcp_logs': 'Verificação de Logs DHCP',
                        'poe_log_errors': 'Verificação de Logs PoE'
                    }
                    skipped_lines.append(skipped_summary(friendly_names.get(test_name, test_name)))

            if executed_lines:
                summary += "--- TESTES EXECUTADOS ---\n\n"
                summary += "\n\n".join(executed_lines)

            if skipped_lines:
                summary += "\n\n--- TESTES NÃO EXECUTADOS ---\n\n"
                summary += "".join(skipped_lines)

            summary += "\n===============================================================\n"
            self.view.update_results(summary)
            return

        summary += f"✅ Conexão com o Switch da Escola: SUCESSO\n"
        summary += f"   - Modelo do Switch Identificado: {data.get('model', 'N/A').upper()}\n\n"

        if all(val == {'skipped': True} for key, val in data.items() if key not in ['connection', 'model']):
            summary += "⚪ Nenhum teste foi selecionado para execução.\n\n"
            self.view.update_results(summary)
            return

        summary += "--- TESTES EXECUTADOS ---\n\n"

        operadora_ping = data.get('operadora_ping', {})
        if operadora_ping.get('skipped'):
            skipped_lines.append(skipped_summary("Ping Switch Operadora (.1)"))
        else:
            op_ip = operadora_ping.get('ip', 'N/A')
            op_status = operadora_ping.get('status', 'Falha')
            op_icon = "✅" if op_status == "Sucesso" else "❌"
            executed_lines.append(f"{op_icon} Ping Switch Operadora ({op_ip}): {op_status.upper()}")

        ip_usage_data = data.get('ip_usage', {})
        if ip_usage_data.get('skipped'):
            skipped_lines.append(skipped_summary("Verificação de Uso de IP"))
        elif ip_usage_data.get('total') is not None and ip_usage_data.get('total') > 0:
            used, total, mask = ip_usage_data['used'], ip_usage_data['total'], ip_usage_data['mask']
            percent = (used / total) * 100
            icon = "⚠️" if percent > 85 else "✅"
            executed_lines.append(f"{icon} Utilização de IP: {used} de {total} IPs em uso ({percent:.1f}%)")
            executed_lines.append(f"   - Máscara de Rede: {mask}")
        else:
            executed_lines.append(
                f"⚠️ Utilização de IP: {ip_usage_data.get('used', 0)} IPs (MACs) contados. (Não foi possível obter máscara/total).")

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
            executed_lines.append(
                f"⚠️ Teste de Vizinhança: Nenhum dispositivo de infraestrutura (baseado em ARP) foi encontrado.")
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
            client_type_msg = 'Via Cabo' if tests_selected["classify_clients"] else ''
            executed_lines.append(
                f"⚠️ Teste de Clientes: Nenhum cliente (baseado em ARP{', ' + client_type_msg if client_type_msg else ''}) foi testado.")
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

        poe_logs_data = data.get('poe_log_errors', {})
        if poe_logs_data.get('skipped'):
            pass
        else:
            poe_log_status_msg = poe_logs_data.get('status', 'Não verificado')
            poe_log_lines = poe_logs_data.get('lines', [])
            if "ERROS PoE ENCONTRADOS" in poe_log_status_msg:
                executed_lines.append(f"❌ Verificação de Logs PoE: ERROS ENCONTRADOS!")
                executed_lines.append(f"   - Problema detectado: {poe_log_lines[0] if poe_log_lines else 'N/A'}")
            elif "Nenhum erro" in poe_log_status_msg:
                executed_lines.append(f"✅ Verificação de Logs PoE: Nenhum erro encontrado nos logs recentes.")
            else:
                executed_lines.append(f"⚠️ Verificação de Logs PoE: {poe_log_status_msg}.")

        if executed_lines:
            summary += "\n\n".join(executed_lines)

        if skipped_lines:
            summary += "\n\n--- TESTES NÃO EXECUTADOS ---\n\n"
            summary += "".join(skipped_lines)

        summary += "\n===============================================================\n"
        self.view.update_results(summary)