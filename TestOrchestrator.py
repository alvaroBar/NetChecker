import os
import threading
import traceback
import random
import platform
import re
import time
from tkinter import messagebox

# Removida importação circular do App

# Importa o Model
try:
    from SwitchTester import SwitchTester
except ImportError:
    messagebox.showerror("Erro Crítico",
                         "Não foi possível encontrar o arquivo 'SwitchTester.py'.\nCertifique-se de que todos os arquivos estão na mesma pasta.")
    exit()


class TestOrchestrator:
    def __init__(self, view):
        """
        Inicializa o controlador.
        :param view: A instância da classe App (a interface gráfica).
        """
        self.view = view  # Referência à instância da App (GUI)

    def _run_local_ping(self, target_ip):
        """
        Executa um ping a partir da máquina local (PC rodando o software).
        """
        self.view.update_results(f"    - Executando ping LOCAL (do PC) para {target_ip}...\n")

        # Define os parâmetros baseados no SO
        param = '-n' if platform.system().lower() == 'windows' else '-c'

        # Monta o comando de ping (1 pacote apenas para teste rápido)
        command = f"ping {param} 1 {target_ip}"

        # Executa o comando escondendo a saída do terminal (redirecionando para NULL)
        # Retorna 0 se sucesso, outro valor se erro
        response = os.system(
            command + " > NUL 2>&1" if platform.system().lower() == 'windows' else command + " > /dev/null 2>&1"
        )

        if response == 0:
            self.view.update_results(f"      - Resultado: SUCESSO (O vizinho respondeu)\n")
            return "Sucesso"
        else:
            self.view.update_results(f"      - Resultado: FALHA (Sem resposta)\n")
            return "Falha"

    def run_test_in_thread(self):
        """Pega os dados da GUI e inicia o teste em uma nova thread."""
        if not self.view.selected_school_name:
            messagebox.showwarning("Aviso", "Por favor, selecione uma escola na lista.")
            return

        # Modificado para verificar o switch selecionado na GUI
        if not self.view.selected_switch_info:
            messagebox.showwarning("Aviso", "Por favor, selecione um switch da escola para testar.")
            return

        school_name = self.view.selected_school_name
        switch_ip = self.view.selected_switch_info['ip']

        # Coleta os dados da GUI antes de iniciar a thread
        credentials = {
            "username": self.view.user_entry.get(),
            "password": self.view.pass_entry.get()
        }
        tests_selected = {key: var.get() for key, var in self.view.test_vars.items()}

        self.view.lock_buttons()
        self.view.results_text.delete("1.0", "end")

        # Inicia a thread com os dados coletados
        threading.Thread(
            target=self._run_test_logic,
            args=(school_name, switch_ip, credentials, tests_selected),
            daemon=True
        ).start()

    def _run_test_logic(self, nome_escola, ip_switch, credentials, tests_selected):
        """Contém toda a lógica de execução do teste."""
        tester = None
        summary_data = {}
        try:
            username = credentials["username"]
            password = credentials["password"]

            # Verifica se algum teste foi selecionado
            if not any(tests_selected.values()):
                self.view.update_results("\nNenhum teste foi selecionado. Encerrando.\n")
                self.view.generate_and_display_summary(
                    {'connection': True, 'model': 'N/A (testes ignorados)'})
                return

            if not username or not password:
                self.view.update_results("ERRO: Por favor, insira o usuário e senha do Switch.\n")
                return

            self.view.update_results(f"--- INICIANDO TESTES NO SWITCH: {nome_escola} ({ip_switch}) ---\n\n")

            self.view.update_results("PASSO 1: Conectando e identificando o switch...\n")

            # Instancia o testador
            tester = SwitchTester(host=ip_switch, username=username, password=password,
                                  update_callback=self.view.update_results)

            # Tenta conectar
            connected, model = tester.connect_and_identify()
            summary_data['connection'] = connected
            summary_data['model'] = model

            # ==============================================================================
            # CENÁRIO 1: FALHA NA CONEXÃO (Executa Ping Local de Fallback)
            # ==============================================================================
            if not connected:
                self.view.update_results(
                    f"\n[FALHA GERAL] Não foi possível conectar ao switch da escola ({ip_switch}).\n")

                # Se o usuário marcou o teste de ping da operadora, fazemos via PC local
                if tests_selected['ping_operadora']:
                    self.view.update_results(
                        "\nPASSO 2 (Fallback): Tentando ping local (do PC) para o Vizinho/Gateway (.1)...\n")

                    try:
                        ip_parts = ip_switch.split('.')
                        if len(ip_parts) >= 3:
                            # Reconstrói o IP mudando o final para .1
                            operadora_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"

                            # Chama a função de ping local que usa o CMD do Windows/Linux
                            status = self._run_local_ping(operadora_ip)

                            # Marca como 'local': True para o relatório saber a diferença
                            summary_data['operadora_ping'] = {'ip': operadora_ip, 'status': status, 'local': True}
                        else:
                            self.view.update_results("      - IP inválido para calcular o gateway.\n")
                            summary_data['operadora_ping'] = {'ip': 'N/A', 'status': 'IP inválido', 'local': True}
                    except Exception as e:
                        summary_data['operadora_ping'] = {'ip': 'Erro', 'status': f'Erro: {str(e)}', 'local': True}

                    self.view.update_results("\n")
                else:
                    summary_data['operadora_ping'] = {'skipped': True}

                # Marca todos os outros testes como pulados (skipped) pois dependem do SSH
                for test_key in tests_selected:
                    if test_key != 'ping_operadora' and test_key not in summary_data:
                        summary_data[test_key] = {'skipped': True}

            # ==============================================================================
            # CENÁRIO 2: CONEXÃO BEM SUCEDIDA (Executa testes via Switch)
            # ==============================================================================
            else:
                self.view.update_results(f"\n[INFO] Modelo final para os testes: {model.upper()}\n\n")

                step = 2

                # 1. Ping Operadora (Via Switch)
                if tests_selected['ping_operadora']:
                    self.view.update_results(f"PASSO {step}: Testando Ping (do Switch) para Operadora (.1)...\n")
                    step += 1
                    ip_parts = ip_switch.split('.')
                    if len(ip_parts) >= 3:
                        operadora_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
                        status = tester.run_ping(operadora_ip)
                        summary_data['operadora_ping'] = {'ip': operadora_ip, 'status': status, 'local': False}
                    else:
                        summary_data['operadora_ping'] = {'ip': 'N/A', 'status': 'IP inválido', 'local': False}
                    self.view.update_results("\n")
                else:
                    summary_data['operadora_ping'] = {'skipped': True}

                # 2. Descoberta de Dispositivos (ARP / Neighbors)
                all_devices, neighbors_found, clients_found = [], [], []
                if tests_selected['neighbors'] or tests_selected['clients'] or tests_selected['classify_clients']:
                    if tests_selected['classify_clients']:
                        self.view.update_results(f"PASSO {step}: Mapeando e classificando dispositivos na rede...\n")
                        step += 1
                        all_devices = tester.discover_and_classify_devices()
                    else:
                        self.view.update_results(
                            f"PASSO {step}: Buscando todos os dispositivos na rede (via ARP)...\n")
                        step += 1
                        all_devices = tester.discover_all_devices_from_arp()

                    # Separa Vizinhos (final .1, .4, .5) de Clientes Comuns
                    neighbors_found = [dev for dev in all_devices if dev['ip'].endswith(('.1', '.4', '.5'))]

                    if tests_selected['classify_clients'] and tests_selected['clients']:
                        clients_found = [dev for dev in all_devices if
                                         not dev['ip'].endswith(('.1', '.4', '.5')) and dev['type'] == 'Via Cabo']
                    elif tests_selected['clients']:
                        clients_found = [dev for dev in all_devices if not dev['ip'].endswith(('.1', '.4', '.5'))]
                    else:
                        clients_found = []

                    self.view.update_results(
                        f"  - Total de {len(all_devices)} dispositivos encontrados e classificados.\n\n")

                # 3. Teste de Vizinhos
                if tests_selected['neighbors']:
                    self.view.update_results(f"PASSO {step}: Testando Vizinhos (Infraestrutura)...\n")
                    step += 1
                    neighbors_to_test = random.sample(neighbors_found, min(len(neighbors_found), 3))
                    summary_data['neighbors'] = {'found': [n['ip'] for n in neighbors_to_test], 'results': {}}
                    if not neighbors_to_test:
                        self.view.update_results("  Nenhum vizinho encontrado para pingar.\n\n")
                    else:
                        for dev in neighbors_to_test:
                            status = tester.run_ping(dev['ip'])
                            summary_data['neighbors']['results'][dev['ip']] = status
                        self.view.update_results("\n")
                else:
                    summary_data['neighbors'] = {'skipped': True}

                # 4. Teste de Clientes
                if tests_selected['clients']:
                    self.view.update_results(f"PASSO {step}: Testando Clientes (Dispositivos Finais)...\n")
                    step += 1
                    clients_to_test = random.sample(clients_found, min(len(clients_found), 3))
                    summary_data['clients'] = {'found': clients_to_test, 'results': {}}
                    client_type_msg = 'Via Cabo' if tests_selected['classify_clients'] else 'Desconhecido'
                    if not clients_to_test:
                        self.view.update_results(f"  Nenhum cliente ({client_type_msg}) encontrado para pingar.\n\n")
                    else:
                        for dev in clients_to_test:
                            status = tester.run_ping(dev['ip'])
                            summary_data['clients']['results'][dev['ip']] = {'status': status, 'type': dev['type']}
                        self.view.update_results("\n")
                else:
                    summary_data['clients'] = {'skipped': True}

                # 5. Saúde (CPU/Memória)
                if tests_selected['health']:
                    self.view.update_results(f"PASSO {step}: Verificando Saúde do Switch (CPU/Memória)...\n")
                    step += 1
                    summary_data['health_status'] = tester.check_health()
                    self.view.update_results("\n")
                else:
                    summary_data['health_status'] = {'skipped': True}

                # 6. Erros de Porta
                if tests_selected['port_errors']:
                    self.view.update_results(f"PASSO {step}: Verificando Erros nas Portas...\n")
                    step += 1
                    status, ports = tester.check_port_errors()
                    summary_data['port_errors'] = {'status': status, 'ports': ports}
                    self.view.update_results("\n")
                else:
                    summary_data['port_errors'] = {'skipped': True}

                # 7. VLANs
                if tests_selected['vlans']:
                    self.view.update_results(f"PASSO {step}: Verificando Configuração de VLANs...\n")
                    step += 1
                    status, vlist = tester.check_vlan_status()
                    summary_data['vlan_status'] = {'status': status, 'vlans': vlist}
                    self.view.update_results("\n")
                else:
                    summary_data['vlan_status'] = {'skipped': True}

                # 8. PoE
                if tests_selected['poe']:
                    self.view.update_results(f"PASSO {step}: Verificando status do PoE...\n")
                    step += 1
                    summary_data['poe_status'] = tester.check_poe_status()
                    self.view.update_results("\n")
                else:
                    summary_data['poe_status'] = {'skipped': True}

                # 9. Proteção de Loop (Configuração)
                if tests_selected['loop_protection']:
                    self.view.update_results(
                        f"PASSO {step}: Verificando se a proteção contra loop está habilitada...\n")
                    step += 1
                    summary_data['loopback'] = tester.check_loopback_detection()
                    self.view.update_results("\n")
                else:
                    summary_data['loopback'] = {'skipped': True}

                # 10. Loops Ativos (Status)
                if tests_selected['active_loops']:
                    self.view.update_results(f"PASSO {step}: Verificando se há loops ATIVOS na rede...\n")
                    step += 1
                    status, ports = tester.check_for_active_loops()
                    summary_data['active_loop'] = {'status': status, 'ports': ports}
                    self.view.update_results("\n")
                else:
                    summary_data['active_loop'] = {'skipped': True}

                # 11. Logs DHCP
                if tests_selected['dhcp_logs']:
                    self.view.update_results(f"PASSO {step}: Verificando Logs por erros de DHCP...\n")
                    step += 1
                    log_status, log_lines = tester.check_dhcp_logs()
                    summary_data['dhcp_logs'] = {'status': log_status, 'lines': log_lines}
                    if log_lines:
                        self.view.update_results("      [ERROS ENCONTRADOS NOS LOGS]\n")
                        for line in log_lines[:5]: self.view.update_results(f"        - {line}\n")
                    self.view.update_results("\n")
                else:
                    summary_data['dhcp_logs'] = {'skipped': True}

                # Finalização da conexão
                self.view.update_results(f"PASSO {step}: Encerrando a conexão...\n")
                tester.disconnect()
                self.view.update_results("  [OK] Conexão SSH encerrada.\n")

            # Fim do Try - Gera o relatório
            self.view.update_results("\n--- TESTE DO SWITCH CONCLUÍDO ---\n")
            self.view.generate_and_display_summary(summary_data)

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
            # Garante que os botões sejam sempre reativados
            self.view.unlock_buttons()