import requests
import time
import os
import re
import telnetlib
import logging
import json


class NetScoutSw:
    def __init__(self, ip, user, password):
        self.ip = ip
        self.user = user
        self.password = password
        self.header = {}

    def send(self, method, url):
        if len(self.header) == 0:
            self.login()
        x = requests.request(method, url, headers=self.header)
        if x.status_code == 200:
            return x.json()
        elif x.status_code == 400:
            res = x.json()
            raise NameError(res["message"])
        else:
            msg = f"URL {url} failed {x.status_code} {x.reason}"
            raise RuntimeError(msg)

    def login(self):
        url = f"http://{self.ip}:8080/api/teststream/v1/session/commands/login"
        x = requests.post(url, auth=(self.user, self.password))
        if x.status_code == 200:
            self.header = {"Authorization": f"Bearer {x.json()['token']}"}
        else:
            msg = f"failed to login, {x.status_code} {x.reason}"
            raise RuntimeError(msg)
        
    def logout(self):
        url = f"http://{self.ip}:8080/api/teststream/v1/session/commands/logout"
        res = self.send("post", url)
        print(res)

    def operate_topology(self, name, command=None):
        """parameters:
        --------------
        name: str
            a valid topology name in system
        command: str
            one of ["activate", "deactivate"]
            
        response:
        ----------
        command: activate or deactivate
            {
                "message": "Successful. restopo1 activated. "
            }
            OR
            {
                "message": " Failed to deactivate topology!. Error type [API Failure!], error string
                [ERROR: Topology not found! ]"
            }
        """
        base_url = f"http://{self.ip}:8080/api/teststream/v1/topologies/{name}/commands"
        if command is None:
            url = base_url
            method = "get"
        elif command not in ["activate", "deactivate"]:
            raise ValueError(f"wrong command: {command}")
        else:
            url = f"{base_url}/{command}"
            method = "post"
        return self.send(method, url)


def activate_topology(topology_name):
    ip = "10.160.70.74"
    user = "BMRKAUTO"
    password = "netscout2"
    sw = NetScoutSw(ip, user, password)
    response_activate = response_activate = sw.operate_topology(topology_name, "activate")
    assert "Successful" in response_activate["message"]
    
    time.sleep(30)
    sw.logout()


def deactivate_topology(topology_name):
    ip = "10.160.70.74"
    user = "BMRKAUTO"
    password = "netscout2"
    sw = NetScoutSw(ip, user, password)
    response_activate = response_activate = sw.operate_topology(topology_name, "deactivate")
    assert "Successful" in response_activate["message"]
    
    time.sleep(30)
    sw.logout()


class TelnetConnection:
    def __init__(self, host, port=23, timeout=15):
        self.host = host
        self.port = port
        self.telnet_con = None
        self.last_out = None
        self.cmd_find_status = -1
        self.default_timeout = timeout
        self._last_port = port
        self.logger = logging.getLogger(__name__)

    def connect(self, port=None):
        if not port:
            port = self.port
        self._last_port = port
        retry = 10
        error = None
        while retry > 0:
            try:
                self.telnet_con = telnetlib.Telnet(self.host, port)
                self.logger.info("Console login successful")
                return
            except ConnectionRefusedError as e:
                self.logger.error("Console connect fail, retrying..")
                error = e
                retry -= 1
                time.sleep(3)
        if error:
            raise error

    def login(self, username, password):
        self.get_output("login: ")
        self.send_command(username)
        self.get_output("Password: ")
        self.send_command(password)
        self.get_output("# ")  # Adjust this prompt as needed

    def disconnect(self, ext_cmd="exit"):
        try:
            if ext_cmd:
                self.send_command(ext_cmd)
            if self.telnet_con:
                self.telnet_con.close()
        except Exception as e:
            self.logger.exception("Error when disconnect", exc_info=e)
        self.telnet_con = None

    def get_output(self, exp=None, timeout=None, must_find=False, display=True, waiting=0):
        try:
            if not timeout:
                timeout = self.default_timeout
            if isinstance(exp, str):
                exp = [exp]
            if not exp:
                time.sleep(waiting)
                out = self.telnet_con.read_very_eager()
            else:
                exp = list(map(lambda x: x.encode(), exp))
                findings, _, out = self.telnet_con.expect(exp, timeout)
                self.cmd_find_status = findings
                if exp and findings == -1:
                    msg = f"Can not find {exp}"
                    if must_find:
                        raise LookupError(msg)
                    self.logger.error(msg)
            self.last_out = out.decode()
            if self.last_out and display:
                self.logger.info(self.last_out)
            return self.last_out
        except EOFError:
            self.logger.exception("EOF for get_output")

    def output_contains(self, content):
        return content in self.last_out

    def output_match(self, regx):
        return re.match(regx, self.last_out) is not None

    def send_command(self, cmd, exp=None, timeout=None, must_find=False, newline=True, display=True, waiting=0):
        if display:
            self.logger.info(f">>> SEND: {cmd}")
        cmd = cmd.encode("ascii")
        if newline:
            cmd += b"\n"
        if not self.telnet_con:
            self.connect(self._last_port)
        self.telnet_con.write(cmd)
        if not timeout:
            timeout = self.default_timeout
        self.get_output(exp, timeout, must_find, display=display, waiting=waiting)
        return self.last_out


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # 从环境变量获取参数
    topology_name = os.getenv('TOPOLOGY_NAME')
    atp_str = os.getenv('ATP')
    #atp = {"ftp": "10.160.57.62", "os_image": "", "os_image_info": {"project": "FortiOS", "version": "7", "build": "3376", "file_pattern": "FGT_3501F-.*\\.out", "branch": "main"}, "os_product": "FortiOS", "os_ver": "7.4.4dev", "os_build": "3376", "os_prefix": "FGT_3501F", "os_label": "Interim Build < Target Version >", "ips_image": "", "ips_image_info": {"project": "IPSengine", "version": "7", "build": "0183", "file_pattern": "flen-fos\\d+\\.\\d+-\\d\\.\\d{3}\\.pkg", "branch": "main"}, "ips_ver": "7.0.16dev", "ips_build": "0183", "ips_label": "Interim Build", "config": "test-config-BMRK2", "config_file_id": "", "config_version": "", "config_build": "", "config_checksum": "", "signature": {"apdb": [{"version": "27.789", "file": "apdb_OS7.4.0_27.00789.APDB.pkg"}], "fmwp": [], "iotd": [], "isdb": [{"version": "27.785", "file": "isdb_OS7.4.0_27.00785.ISDB.pkg"}], "nids": [{"version": "27.790", "file": "nids_OS7.4.0_27.00790.NIDS.pkg"}], "otdb": [], "otdp": [], "etdb": [{"version": "92.03702", "file": "vsigupdate-OS7.4.0_92.03702.ETDB.High.pkg"}], "exdb": [{"version": "92.04510", "file": "/exdb/vsigupdate-OS7.0.0_92.04510.EXDB.pkg"}], "mmdb": [{"version": "92.03702", "file": "vsigupdate-OS7.4.0_92.03702.MMDB.pkg"}], "fldb": [{"version": "92.03702", "file": "vsigupdate-OS7.4.0_92.03702.FLDB.pkg"}], "avai": [{"version": "2.16370", "file": "/avai/vsigupdate-OS7.0.0_2.16370.AVAI.pkg"}]}, "signature_path": "signature/7.0"}
    atp = json.loads(atp_str)
    activate_topology(topology_name)

    # 远程设备登录信息
    ip = '10.160.18.223'
    username = 'admin'
    password = 'a'
    command = 'execute reboot'
    os_file = f"{atp['os_prefix']}-v{atp['os_image_info']['version']}-build{atp['os_build']}-FORTINET.out"
    mmdb_file = ', '.join(entry['file'] for entry in atp['signature']['mmdb'])
    fldb_file = ', '.join(entry['file'] for entry in atp['signature']['fldb'])
    etdb_file = ', '.join(entry['file'] for entry in atp['signature']['etdb'])
    apdb_file = ', '.join(entry['file'] for entry in atp['signature']['apdb'])
    nids_file = ', '.join(entry['file'] for entry in atp['signature']['nids'])
    isdb_file = ', '.join(entry['file'] for entry in atp['signature']['isdb'])
    command_os = f"execute restore image tftp {os_file} {atp['ftp']}"
    command_mmdb = f"execute restore av tftp {mmdb_file} {atp['ftp']}"
    command_fldb = f"execute restore av tftp {fldb_file} {atp['ftp']}"
    command_etdb = f"execute restore av tftp {etdb_file} {atp['ftp']}"
    command_apdb = f"execute restore ips tftp {apdb_file} {atp['ftp']}"
    command_nids = f"execute restore ips tftp {nids_file} {atp['ftp']}"
    command_isdb = f"execute restore ips tftp {isdb_file} {atp['ftp']}"

    # 创建 TelnetConnection 对象并执行命令
    telnet_conn = TelnetConnection(ip)
    telnet_conn.connect()
    telnet_conn.login(username, password)
    time.sleep(5)
    telnet_conn.send_command('c g')
    time.sleep(6)
    telnet_conn.send_command(command_os)
    telnet_conn.get_output('(y/n)')
    telnet_conn.send_command('y')
    if telnet_conn.get_output('(y/n)'):
        telnet_conn.send_command('y')
    time.sleep(30)
    telnet_conn.send_command('')
    time.sleep(600)
    telnet_conn.disconnect()

    time.sleep(180)
    telnet_conn = TelnetConnection(ip)
    telnet_conn.connect()
    telnet_conn.login(username, password)
    time.sleep(5)
    telnet_conn.send_command('c g')
    time.sleep(3)
    telnet_conn.send_command(command_mmdb)
    telnet_conn.get_output('(y/n)')
    telnet_conn.send_command('y')
    time.sleep(60)
    telnet_conn.send_command(command_fldb)
    telnet_conn.get_output('(y/n)')
    telnet_conn.send_command('y')
    time.sleep(60)
    telnet_conn.send_command(command_etdb)
    telnet_conn.get_output('(y/n)')
    telnet_conn.send_command('y')
    time.sleep(60)
    telnet_conn.send_command(command_apdb)
    telnet_conn.get_output('(y/n)')
    telnet_conn.send_command('y')
    time.sleep(60)
    telnet_conn.send_command(command_nids)
    telnet_conn.get_output('(y/n)')
    telnet_conn.send_command('y')
    time.sleep(60)
    telnet_conn.send_command(command_isdb)
    telnet_conn.get_output('(y/n)')
    telnet_conn.send_command('y')
    time.sleep(60)
    telnet_conn.disconnect()