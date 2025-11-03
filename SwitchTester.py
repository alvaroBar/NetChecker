import re
import time
import ipaddress
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


class SwitchTester:
    COMMANDS = {
        'tplink': {
            'identify_cmd': ['show system-info'],
            'identify_keyword': 'TP-Link',
            'all_devices': ['show arp'],
            'ip_interface': ['show ip interface vlan 10'],
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
            'identify_keyword': 'Edge-Core',
            'all_devices': ['show arp'],
            'ip_interface': ['show ip interface vlan 10'],
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
            'ip_interface': [],
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
        base_device_info = {
            'device_type': 'tplink_jetstream',
            'host': self.host_ip,
            'username': self.username,
            'password': self.password,
            'secret': self.password,
            'conn_timeout': 20,
            'global_delay_factor': 2,
        }

        try:
            self._log(f"  - Tentando conexão SSH padrão (perfil: {base_device_info['device_type']})...\n")
            self.connection = ConnectHandler(**base_device_info)

        except Exception as e:
            if "no acceptable host key" in str(e).lower() or "incompatible ssh peer" in str(e).lower():
                self._log("  [AVISO] O switch parece ser um modelo mais antigo. Tentando método de conexão legado...\n")
                try:
                    legacy_device_info = base_device_info.copy()
                    legacy_device_info['device_type'] = 'generic'
                    legacy_device_info['disabled_algorithms'] = dict(pubkeys=[], kex=[])
                    self.connection = ConnectHandler(**legacy_device_info)
                except Exception as e_legacy:
                    self._log(f"  [ERRO] A tentativa de conexão legada também falhou.\n     Detalhes: {e_legacy}\n")
                    return False, self.model
            else:
                self._log(f"  [ERRO] Falha na conexão inicial.\n     Detalhes: {e}\n")
                return False, self.model

        try:
            self._log("  - Conexão estabelecida. Executando comando 'enable'...\n")
            self.connection.enable()
            self._log("  - Modo privilegiado ativado.\n")
            time.sleep(0.5)
            self._log("  - Desativando paginação do terminal (comando: 'terminal length 0')...\n")
            self.connection.send_command_timing('terminal length 0')
            time.sleep(0.5)
            self._log("  - Paginação desativada.\n")
            time.sleep(0.5)
        except Exception as e:
            self._log(f"  [ERRO] Falha ao entrar no modo privilegiado ou desativar paginação.\n     Detalhes: {e}\n")
            if self.connection:
                try:
                    self.connection.disconnect()
                except:
                    pass
            return False, self.model

        self._log("  - Buscando informações para identificar o modelo do switch...\n")

        models_to_try = ['tplink', 'edgecore']
        identified = False
        for model_name in models_to_try:
            try:
                model_profile = self.COMMANDS[model_name]
                command = model_profile['identify_cmd'][0]
                keyword = model_profile['identify_keyword']

                self._log(f"    - Executando verificação para {model_name.upper()} com o comando: '{command}'\n")
                output = self.connection.send_command(command, read_timeout=15)

                if output and (
                        keyword.lower() in output.lower() or (model_name == 'tplink' and 'omada' in output.lower())):
                    self.model = model_name
                    self._log(f"  [SUCESSO] Modelo identificado como: {self.model.upper()}\n")
                    identified = True
                    break
                else:
                    self._log(f"      (Não corresponde ao perfil {model_name.upper()})\n")
            except Exception:
                self._log(f"      [AVISO] Comando para perfil {model_name.upper()} falhou ou expirou.\n")
                continue

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
            port_name = None
            port_errors = 0
            port_discards = 0
            for line_log in output.splitlines():
                if line_log.startswith("Port:"):
                    if port_name and (port_errors > 0 or port_discards > 0):
                        ports_with_errors.append(f"{port_name} (Errors: {port_errors}, Discards: {port_discards})")
                    port_name = line_log.split(':')[-1].strip()
                    port_errors = 0
                    port_discards = 0
                elif "Rx Errors:" in line_log or "Tx Errors:" in line_log:
                    try:
                        port_errors += int(line_log.split(':')[-1].strip().replace(',', ''))
                    except:
                        pass
                elif "Rx Discards:" in line_log or "Tx Discards:" in line_log:
                    try:
                        port_discards += int(line_log.split(':')[-1].strip().replace(',', ''))
                    except:
                        pass

            if port_name and (port_errors > 0 or port_discards > 0):
                ports_with_errors.append(f"{port_name} (Errors: {port_errors}, Discards: {port_discards})")

            if ports_with_errors:
                return "ERROS ENCONTRADOS!", list(set(ports_with_errors))
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
        if output is None: return None
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

    def check_system_logs(self):
        output, _ = self._execute_command_list('logs')
        if output is None:
            return {
                'dhcp': {'status': "Não foi possível verificar logs", 'lines': []},
                'poe': {'status': "Não foi possível verificar logs", 'lines': []}
            }

        dhcp_error_lines = []
        dhcp_error_keywords = ["deny", "fail", "untrusted", "exceeded", "error"]

        poe_error_lines = []
        poe_error_keywords = ["overloading", "over 30 watts", "power supply status.*off"]

        for line in output.splitlines():
            line_lower = line.lower()

            if 'dhcp' in line_lower and any(keyword in line_lower for keyword in dhcp_error_keywords):
                dhcp_error_lines.append(line.strip())

            if 'poe' in line_lower and any(re.search(keyword, line_lower) for keyword in poe_error_keywords):
                if "power supply status of port" in line_lower and "changes from off to on" in line_lower:
                    continue
                poe_error_lines.append(line.strip())

        return {
            'dhcp': {
                'status': "ERROS DHCP ENCONTRADOS!" if dhcp_error_lines else "Nenhum erro DHCP encontrado nos logs recentes",
                'lines': dhcp_error_lines
            },
            'poe': {
                'status': "ERROS PoE ENCONTRADOS!" if poe_error_lines else "Nenhum erro PoE encontrado nos logs recentes",
                'lines': poe_error_lines
            }
        }

    def get_network_info(self):
        output, _ = self._execute_command_list('ip_interface')
        ip, mask = None, None

        if output:
            ip_match = re.search(r'(?:IP-Addr|IP Address)\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output,
                                 re.IGNORECASE)
            mask_match = re.search(r'(?:Subnet-Mask|Subnet Mask)\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output,
                                   re.IGNORECASE)

            if ip_match:
                ip = ip_match.group(1)
            if mask_match:
                mask = mask_match.group(1)

            if not ip or not mask:
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                                  output)
                if match:
                    ip, mask = match.group(1), match.group(2)

        if not ip or not mask:
            self._log("    - Falha ao extrair máscara da interface. Tentando via logs de inicialização...\n")
            output_logs, _ = self._execute_command_list('logs', log_output=False)

            if output_logs:
                log_match = re.search(r'set primary ip\s+([0-9.]+)\s+mask\s+([0-9.]+)', output_logs, re.IGNORECASE)
                if log_match:
                    self._log("    - Máscara encontrada no log de inicialização.\n")
                    ip, mask = log_match.group(1), log_match.group(2)

        if not ip or not mask:
            self._log("    - Não foi possível encontrar a máscara de rede.\n")
            return {'total_hosts': None, 'mask': 'Não encontrado'}

        try:
            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            total_hosts = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
            self._log(f"    - Rede: {net.network_address}, Máscara: {mask}, Total de IPs: {total_hosts}\n")
            return {'total_hosts': total_hosts, 'mask': mask}
        except Exception as e:
            self._log(f"  [ERRO] Não foi possível calcular o tamanho da rede com ip={ip}, mask={mask}. Detalhes: {e}\n")
            return {'total_hosts': None, 'mask': mask}

    # --- NOVA FUNÇÃO ---
    def get_mac_address_count(self):
        """
        Conta o número de dispositivos conectados com base na tabela MAC.
        """
        # Não loga a saída bruta (log_output=False), apenas o resultado.
        output, _ = self._execute_command_list('mac_table', log_output=False)
        if output is None:
            self._log("    - Não foi possível executar 'show mac address-table' para contar dispositivos.\n")
            return 0

        # Tenta o método mais confiável (parsear o total do TPLINK, como visto no seu log)
        match = re.search(r'Total MAC Addresses for this criterion:\s*(\d+)', output, re.IGNORECASE)
        if match:
            try:
                count = int(match.group(1))
                self._log(f"    - Contados {count} dispositivos (MACs) via sumário da tabela.\n")
                return count
            except:
                pass  # Continua para o fallback

        # Fallback: Contar linhas que são MAC addresses dinâmicos
        mac_count = 0
        mac_pattern = re.compile(r'([0-9a-f]{2}[:\.-]){5}[0-9a-f]{2}', re.IGNORECASE)
        for line in output.splitlines():
            # Procura por um MAC e a palavra 'dynamic' para evitar contar entradas estáticas/sistema
            if mac_pattern.search(line) and 'dynamic' in line.lower():
                mac_count += 1

        if mac_count > 0:
            self._log(f"    - Contados {mac_count} dispositivos (MACs) via contagem de linhas 'dynamic'.\n")
            return mac_count

        self._log("    - Tabela MAC parecia vazia ou não foi possível parsear. Contagem de dispositivos é 0.\n")
        return 0