import re
import time
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

class SwitchTester:
    COMMANDS = {
        'tplink': {
            'identify_cmd': ['show system-info'],
            'identify_keyword': 'TP-Link',
            'all_devices': ['show arp'],
            'loopback': ['show loopback-detection global'],
            'loop_status': ['show loopback-detection interface'],
            'cpu_util': ['show cpu-utilization'],
            'mem_util': ['show memory-utilization'],
            'port_errors': ['show interface counters'],
            'vlan_status': ['show vlan'],
            'lldp_neighbors': ['show lldp neighbor'],
            'mac_table': ['show mac address-table'],
            'poe_status': ['show power inline'],
            'ip_bindings': ['show ip source binding', 'show arp'],
            'logs': ['show logging buffer'],
        },
        'edgecore': {
            'identify_cmd': ['show system'],
            'identify_keyword': 'ECS2100',
            'all_devices': ['show arp'],
            'loopback': ['show loop-detection'],
            'loop_status': [],
            'cpu_util': [],
            'mem_util': [],
            'port_errors': ['show interface counters'],
            'vlan_status': ['show vlan'],
            'lldp_neighbors': ['show lldp neighbors'],
            'mac_table': ['show mac address-table'],
            'poe_status': [],
            'ip_bindings': ['show ip source binding', 'show arp'],
            'logs': ['show log'],
        },
        'unknown': {
            'identify_cmd': ['show version'],
            'all_devices': ['show arp'],
            'loopback': [],
            'loop_status': [],
            'cpu_util': [],
            'mem_util': [],
            'port_errors': [],
            'vlan_status': [],
            'lldp_neighbors': [],
            'mac_table': [],
            'poe_status': [],
            'ip_bindings': [],
            'logs': [],
        }
    }

    def __init__(self, host, username, password, update_callback=None):
        self.host_ip = host
        self.username = username
        self.password = password
        self.model = 'unknown'
        self.connection = None
        self.update_callback = update_callback

    def _log(self, message):
        if self.update_callback:
             self.update_callback(message)

    def connect_and_identify(self):
        """
        Tenta conectar ao switch usando múltiplos métodos:
        SSH Padrão, SSH Legado (fallback), Telnet Específico (EdgeCore) e Telnet Genérico (fallback).
        """
        base_device_config = {
            'host': self.host_ip,
            'username': self.username,
            'password': self.password,
            'secret': self.password,  # Usado para o comando 'enable'
            'conn_timeout': 15,
            'global_delay_factor': 2,
        }

        connection_protocol = None

        # --- TENTATIVA 1: SSH PADRÃO ---
        self._log(f"  - Tentativa 1: Conexão SSH padrão (perfil: tplink_jetstream)...\n")
        ssh_params = base_device_config.copy()
        ssh_params['device_type'] = 'tplink_jetstream'

        try:
            self.connection = ConnectHandler(**ssh_params)
            connection_protocol = 'ssh'

        except Exception as e_ssh:
            error_str = str(e_ssh).lower()

            if "no acceptable host key" in error_str or "incompatible ssh peer" in error_str:
                # --- TENTATIVA 2: SSH LEGADO ---
                self._log("  [AVISO] SSH padrão falhou (incompatibilidade de criptografia).\n")
                self._log("  - Tentativa 2: Conexão SSH Legada (perfil: generic)...\n")
                try:
                    legacy_params = base_device_config.copy()
                    legacy_params['device_type'] = 'generic'
                    legacy_params['disabled_algorithms'] = dict(pubkeys=[], kex=[])
                    self.connection = ConnectHandler(**legacy_params)
                    connection_protocol = 'ssh'

                except Exception as e_legacy:
                    self._log(f"  [AVISO] SSH Legado também falhou. Partindo para Telnet.\n    Detalhes: {e_legacy}\n")
                    self.connection = None

            else:
                self._log(f"  [AVISO] SSH padrão falhou. Partindo para Telnet.\n    Detalhes: {e_ssh}\n")
                self.connection = None

        # --- TENTATIVA 3: TELNET (EDGECORE) ---
        # Adicionamos esta nova tentativa específica para o EdgeCore
        if self.connection is None:
            self._log(f"  - Tentativa 3: Conexão Telnet (perfil: edgecore_ecs_telnet)...\n")
            try:
                telnet_params = base_device_config.copy()
                telnet_params['device_type'] = 'edgecore_ecs_telnet'
                self.connection = ConnectHandler(**telnet_params)
                connection_protocol = 'telnet'

            except Exception as e_edgecore_telnet:
                self._log(f"  [AVISO] Telnet (EdgeCore) falhou. Partindo para Telnet genérico.\n    Detalhes: {e_edgecore_telnet}\n")
                self.connection = None # Garante que está Nulo para a próxima tentativa

        # --- TENTATIVA 4: TELNET (Genérico) ---
        # Esta era a sua TENTATIVA 3, agora é a 4 (fallback)
        if self.connection is None:
            self._log(f"  - Tentativa 4: Conexão Telnet (perfil: generic_telnet)...\n")
            try:
                telnet_params = base_device_config.copy()
                telnet_params['device_type'] = 'generic_telnet'
                telnet_params['global_cmd_verify'] = False
                self.connection = ConnectHandler(**telnet_params)
                connection_protocol = 'telnet'

            except Exception as e_telnet:
                self._log(f"  [ERRO] Conexão Telnet genérica também falhou.\n    Detalhes: {e_telnet}\n")
                self._log("\n[FALHA GERAL] Não foi possível conectar ao switch via SSH ou Telnet.\n")
                return False, self.model

        self._log(f"  [OK] Conexão estabelecida com sucesso.\n")

        if connection_protocol == 'ssh':
            # --- LÓGICA PARA TPLINK (SSH) ---
            try:
                self._log("  - Executando comando 'enable' (método SSH)...\n")
                self.connection.enable()
                self._log("  - Modo privilegiado ativado.\n")
                time.sleep(0.5)
            except Exception as e:
                self._log(f"  [ERRO] Falha ao entrar no modo privilegiado SSH.\n     Detalhes: {e}\n")
                if self.connection: self.connection.disconnect()
                return False, self.model

        elif connection_protocol == 'telnet':
            # --- LÓGICA PARA EDGECORE (TELNET) ---
            # Correto: Pula o 'enable' pois o log do PuTTY mostrou login direto em '#'.
            self._log("  [AVISO] Conexão via Telnet. Pulando 'enable' (login direto para '#').\n")
            pass

        # --- INÍCIO DA CORREÇÃO DE PAGINAÇÃO ---
        # Removemos a verificação 'if connection_protocol == 'ssh'
        # O disable_paging() deve ser tentado em AMBOS os protocolos.
        # O Netmiko sabe o comando certo para cada device_type.
        try:
            self._log("  - Desativando paginação do terminal (método: disable_paging)...\n")
            self.connection.disable_paging()
            time.sleep(0.5)
            self._log("  - Paginação desativada.\n")
        except Exception as e_pagination:
            self._log(f"    [AVISO] Não foi possível desativar paginação (erro: {e_pagination}).\n")
            if self.connection and not self.connection.is_alive():
                self._log("  [ERRO] A conexão foi perdida durante 'disable_paging'.\n")
                return False, self.model
            pass # Continua mesmo se falhar

        # Removemos a lógica de "Limpeza de Buffer" que só rodava para Telnet,
        # pois agora o disable_paging() trata disso.
        # --- FIM DA CORREÇÃO DE PAGINAÇÃO ---


        # --- INÍCIO DA CORREÇÃO DE LÓGICA ---
        # Invertemos a ordem. Tentamos EdgeCore PRIMEIRO.
        models_to_try = ['edgecore', 'tplink']
        # --- FIM DA CORREÇÃO DE LÓGICA ---

        identified = False
        for model_name in models_to_try:
            try:
                model_profile = self.COMMANDS[model_name]
                command = model_profile['identify_cmd'][0]
                keyword = model_profile['identify_keyword']

                self._log(f"    - Executando verificação para {model_name.upper()} com o comando: '{command}'\n")
                output = self.connection.send_command(command, read_timeout=30)

                if output and (
                        keyword.lower() in output.lower() or (model_name == 'tplink' and 'omada' in output.lower())):
                    self.model = model_name
                    self._log(f"  [SUCESSO] Modelo identificado como: {self.model.upper()}\n")
                    identified = True
                    break
                else:
                    self._log(f"      (Não corresponde ao perfil {model_name.upper()})\n")

            except Exception as e:
                self._log(
                    f"      [AVISO] Comando para perfil {model_name.upper()} falhou ou expirou.\n      Detalhes: {e}\n")

                # --- INÍCIO DA VERIFICAÇÃO DE SEGURANÇA ---
                # Se o comando MATOU a conexão, paramos o teste.
                if "10053" in str(e) or (self.connection and not self.connection.is_alive()):
                    self._log("  [ERRO] A conexão com o switch foi PERDIDA durante a identificação.\n")
                    return False, self.model  # Retorna a falha

                # Se foi só um timeout ou comando inválido, a conexão está viva,
                # então podemos 'continue' para o próximo modelo.
                continue
                # --- FIM DA VERIFICAÇÃO DE SEGURANÇA ---

        if not identified:
            self._log("  [AVISO] Não foi possível identificar o modelo com os perfis conhecidos.\n")

        return True, self.model

    def disconnect(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass

    def get_command(self, key):
        return self.COMMANDS.get(self.model, {}).get(key, [])

    def _execute_command_list(self, command_key, log_output=True):
        command_list = self.get_command(command_key)
        if not self.connection or not command_list: return None, ""
        for command in command_list:
            if log_output: self._log(f"    - Executando comando: '{command}'\n")
            try:
                output = self.connection.send_command(command, read_timeout=30)
                if output is not None and "incomplete command" not in output.lower() and "invalid parameter" not in output.lower() and "% Ambiguous command" not in output:
                    if log_output: self._log(f"      [SAÍDA BRUTA DO SWITCH]\n{output}\n      [FIM DA SAÍDA BRUTA]\n")
                    return output, command
                else:
                    if log_output: self._log(
                        f"      (Comando '{command}' inválido, sem saída útil ou ambíguo. Tentando próximo...)\n")
            except Exception as e:
                if log_output: self._log(f"      (Comando '{command}' falhou: {e})\n")
        return None, (command_list[-1] if command_list else "")

    def discover_and_classify_devices(self):
        self._log("  - Mapeando a rede: identificando portas Wi-Fi e tabelas de clientes...\n")

        wifi_ports = set()
        lldp_output, _ = self._execute_command_list('lldp_neighbors', log_output=False)
        if lldp_output:
            for line in lldp_output.splitlines():
                if any(keyword in line.lower() for keyword in ["ap", "ruckus", "intelbras"]):
                    parts = line.split()
                    if parts:
                        port_match = re.match(r'(Gi\d/\d/\d+|eth-\d-\d-\d+|\d+)', parts[0])
                        if port_match:
                            wifi_ports.add(port_match.group(0))
        self._log(
            f"    - Encontradas {len(wifi_ports)} portas conectadas a Access Points: {', '.join(sorted(list(wifi_ports))) if wifi_ports else 'Nenhuma'}\n")

        mac_table = {}
        mac_output, _ = self._execute_command_list('mac_table', log_output=False)
        if mac_output:
            mac_pattern = re.compile(r'([0-9a-f]{2}[:\.-]){5}[0-9a-f]{2}', re.IGNORECASE)
            for line in mac_output.splitlines():
                mac_match = mac_pattern.search(line)
                if mac_match:
                    mac = mac_match.group(0).lower().replace('-', ':')
                    port_match = re.search(r'(Gi\d/\d/\d+|eth-\d-\d-\d+|\d+)$', line.strip())
                    if port_match:
                        mac_table[mac] = port_match.group(0)
                    elif len(line.split()) > 1:
                        mac_table[mac] = line.split()[-1]

        self._log(f"    - Mapeados {len(mac_table)} endereços MAC para portas físicas.\n")

        ip_bindings_output, source_command = self._execute_command_list('ip_bindings')
        classified_devices = []

        if ip_bindings_output:
            ip_mac_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(([0-9a-f]{2}[:\.-]){5}[0-9a-f]{2})',
                                        re.IGNORECASE)
            for line in ip_bindings_output.splitlines():
                match = ip_mac_pattern.search(line)
                if match:
                    ip, mac = match.group(1), match.group(2).lower().replace('-', ':')
                    port = mac_table.get(mac, 'Desconhecida')
                    conn_type = "Via Wi-Fi" if port in wifi_ports else "Via Cabo"
                    classified_devices.append({'ip': ip, 'type': conn_type})

        if not classified_devices:
            self._log("    - Tabela IP Bindings vazia ou falhou. Tentando com tabela ARP...\n")
            arp_output, source_command = self._execute_command_list('all_devices')
            if arp_output:
                ip_mac_pattern_arp = re.compile(
                    r'\S+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(([0-9a-f]{2}[:\.-]){5}[0-9a-f]{2})', re.IGNORECASE)
                for line in arp_output.splitlines():
                    match = ip_mac_pattern_arp.search(line)
                    if match:
                        ip, mac = match.group(1), match.group(2).lower().replace('-', ':')
                        port = mac_table.get(mac, 'Desconhecida')
                        conn_type = "Via Wi-Fi" if port in wifi_ports else "Via Cabo"
                        classified_devices.append({'ip': ip, 'type': conn_type})

        source_name = 'IP Bindings' if 'binding' in source_command else 'ARP'
        self._log(f"    - Classificados {len(classified_devices)} dispositivos ({source_name}).\n")
        return classified_devices

    def discover_all_devices_from_arp(self):
        output, _ = self._execute_command_list('all_devices')
        if not output: return []
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        found_ips = re.findall(ip_pattern, output)
        return [{'ip': ip, 'type': 'Desconhecido'} for ip in found_ips if ip != self.host_ip]

    def run_ping(self, destination_ip):
        if not self.connection: return "Falha (sem conexão)"
        command = f"ping {destination_ip}"
        self._log(f"    - Testando ping para {destination_ip}... \n")
        self._log(f"      - Executando: '{command}'\n")

        try:
            # Adiciona um pequeno delay para estabilizar sessões Telnet
            time.sleep(1)
            output = self.connection.send_command(command, read_timeout=20)
            self._log(f"      - Saída do Ping: {output.strip()}\n")

            output_lower = output.lower()
            if "0% loss" in output_lower or "reply from" in output_lower:
                return "Sucesso"
            return "Falha"

        except EOFError:
            self._log("      [ERRO] Conexão Telnet encerrada inesperadamente durante o ping.\n")
            return "Falha (Telnet fechado)"
        except Exception as e:
            self._log(f"      [ERRO] Falha ao executar ping: {e}\n")
            return "Falha (erro inesperado)"

        output = self.connection.send_command(command, read_timeout=20)
        self._log(f"      - Saída do Ping: {output.strip()}\n")

        output_lower = output.lower()
        if "0% loss" in output_lower or "reply from" in output_lower: return "Sucesso"
        return "Falha"

    def check_loopback_detection(self):
        output, _ = self._execute_command_list('loopback')
        if output is None: return "Desativado ou não configurado"
        return "Ativado" if "enable" in output.lower() else "Desativado"

    def check_for_active_loops(self):
        output, _ = self._execute_command_list('loop_status')
        if output is None: return "Não foi possível verificar", []
        blocked_ports = []
        for line in output.splitlines():
            if 'blocking' in line.lower():
                parts = line.split()
                if parts: blocked_ports.append(parts[0])
        if blocked_ports: return "LOOP DETECTADO!", blocked_ports
        return "Nenhum loop ativo detectado", []

    def check_health(self):
        health_data = {}
        cpu_output, _ = self._execute_command_list('cpu_util')
        if cpu_output:
            match = re.search(r'(\d+)\s*%', cpu_output)
            if match: health_data['cpu'] = int(match.group(1))

        mem_output, _ = self._execute_command_list('mem_util')
        if mem_output:
            match = re.search(r'(\d+)\s*%', mem_output)
            if match: health_data['memory'] = int(match.group(1))

        return health_data

    def check_port_errors(self):
        output, _ = self._execute_command_list('port_errors')
        if output is None: return "Não foi possível verificar", []

        ports_with_errors, in_error_section = [], False
        error_headers = ['fcs-err', 'late-col', 'runts', 'giants', 'fragments', 'jabbers']

        for line in output.splitlines():
            line_lower = line.lower()
            if any(header in line_lower for header in error_headers):
                in_error_section = True
                continue
            if not in_error_section: continue

            if line.strip().lower().startswith(('gi', 'eth')):
                parts = line.split()
                port_name = parts[0]
                error_counts = [int(p) for p in parts[1:] if p.isdigit()]
                if sum(error_counts) > 0:
                    ports_with_errors.append(port_name)

        if not in_error_section:
            return "Nenhuma informação de erro de porta encontrada", []
        if ports_with_errors:
            return "ERROS ENCONTRADOS!", list(set(ports_with_errors))
        return "Nenhum erro encontrado nas portas", []

    def check_vlan_status(self):
        output, _ = self._execute_command_list('vlan_status')
        if output is None: return "Não foi possível verificar", []

        vlans = []
        vlan_pattern = re.compile(r"^\s*(\d+)\s+([a-zA-Z0-9_-]+)", re.MULTILINE)
        matches = vlan_pattern.findall(output)

        for match in matches:
            vlan_id, vlan_name = match
            vlans.append({'id': vlan_id, 'name': vlan_name})

        if not vlans: return "Nenhuma VLAN encontrada", []
        return f"{len(vlans)} VLANs encontradas", vlans

    def check_poe_status(self):
        output, _ = self._execute_command_list('poe_status')
        if output is None: return {}
        poe_data = {}
        patterns = {
            'limit': r"power limit\s*:\s*(\d+\.?\d*)\s*w",
            'consumption': r"power consumption\s*:\s*(\d+\.?\d*)\s*w",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                poe_data[key] = float(match.group(1))
        return poe_data

    def check_dhcp_logs(self):
        output, _ = self._execute_command_list('logs')
        if output is None: return "Não foi possível verificar logs", []

        error_lines = []
        dhcp_error_keywords = ["deny", "fail", "untrusted", "exceeded", "error"]

        for line in output.splitlines():
            line_lower = line.lower()
            if 'dhcp' in line_lower and any(keyword in line_lower for keyword in dhcp_error_keywords):
                error_lines.append(line.strip())

        if error_lines: return "ERROS DHCP ENCONTRADOS!", error_lines
        return "Nenhum erro DHCP encontrado nos logs recentes", []