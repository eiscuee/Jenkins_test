from telnet import TelnetConnection
from logger import get_logger
from time import time, sleep
import json
import re
import os
import sys


logger = get_logger("clear")

def wait_until(
        condition,
        *args,
        timeout=30,
        period=1,
        expect_true=True,
        **kwargs
):
    mustend = time() + timeout
    i = 0
    while time() < mustend:
        results = condition(*args, **kwargs)
        # Checks if results is explicitly false.
        # Then checks that result against expect_true
        # ex: results = False & expect_true = True;
        # (F == F) > T; (T == !T) > False.  returns False
        # This allows for boolean comparisons without falsifying None, '' and 0.
        if (results is False) is not expect_true:
            return results
        sleep(period)
        i += period
    return condition(*args, **kwargs)


def get_device_info(name, json_file = 'device_info.json'):
    with open(json_file, 'r') as file:
        data = json.load(file)
        for platform in data['platforms']:
            if platform['name'] == name:
                return platform


class FortigateConsole(TelnetConnection):
    def __init__(
        self,
        host,
        port,
        console_type="cisco",
        console_password="",
        username="admin",
        password="a",
        timeout=15,
        multi_blade=True
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.console_password = console_password
        self.logger = get_logger(name=f"cli.{host}")
        self.telnet_con = None
        self.multi_blade = multi_blade
        self.last_out = None
        self.cmd_find_status = -1
        self.default_timeout = timeout
        self.fgt_connected = False
        self.console_type = console_type
        super().__init__(self.host, self.port, self.default_timeout)

    def login_console_server(self):
        self.connect(23)
        self.get_output(exp=[r":\s*$", r"#\s*$"])
        if "Password:" in self.last_out:
            self.send_command(
                self.console_password,
                r">\s*$",
                must_find=True
            )
        if self.cmd_find_status > -1:
            logger.info("Login to console server successful")

    def clear_line(self, line_num=None):
        if self.console_type not in "cisco":
            logger.info("Not a cisco console type, no need clear line")
            return
        if not line_num:
            line_num = self.port % 1000
        logger.info(f"Clearing Line {line_num}")
        self.login_console_server()
        if self.output_contains(">"):
            self.send_command("enable", exp=r":\s*$", must_find=True)
            self.send_command(
                self.console_password,
                exp=[r"#\s*$"],
                must_find=True
            )
        self.send_command(f"clear line {line_num}", exp=r"]\s*$")
        self.send_command("", exp=r"\[OK\]\s*", must_find=True)
        logger.info(f"Line {line_num} cleared")
        self.disconnect()

    def login_fortigate(self):
        logger.info("Login to fortigate from console")
        self.clear_line()
        self.connect()
        retry = 5
        while retry > 0:
            try:
                self.send_command(
                    "",
                    exp=["login:", "#"],
                    must_find=True,
                    timeout=3
                )
                break
            except LookupError as e:
                logger.info("retry login...")
                retry -= 1
                if retry <= 0:
                    raise e
        if self.output_contains("login:"):
            self.send_command(f"{self.username}", "Password:")
            if self.output_contains("Password:"):
                self.send_command(
                    f"{self.password}", exp=["#", "Login incorrect"]
                )
                if self.output_contains("Login incorrect"):
                    logger.info("Current password is incorrect")
                    self.set_password_after_reset()
                if self.output_contains("#"):
                    logger.info("Login Successful")
        else:
            logger.info("already login to fortigate")
            self.send_command("end", exp="#")

    def set_password_after_reset(self):
        logger.info(f"Reset password for user: {self.username}")
        self.send_command("admin", exp="Password:")
        self.send_command("", exp=["New Password:", "#"])
        if self.output_contains("New Password:"):
            self.send_command(
                self.password, exp="Confirm Password:", must_find=True
            )
            self.send_command(self.password)
            msg = f"Fortigate Password reset to {self.password}"
        else:
            msg = "Fortigate Password updated to None, updated user to admin"
            self.username = "admin"
            self.password = ""
        logger.info(msg)

    # pylint: disable=unsupported-membership-test
    def wait_fortigate_bootup(self, timeout=600):
        def wait_func():
            try:
                out = self.get_output()
                return "login:" in out
            except Exception as e:
                logger.exception(
                    "Error when check out put for wait_fortigate_bootup",
                    exc_info=e
                )
            return False

        result = wait_until(wait_func, timeout=timeout, period=5)
        assert result, "Something went wrong when waiting bootup"

    def back_to_root_level(self):
        times = 10
        while times > 0:
            if not self.output_contains(")"):
                break
            self.send_command("end", exp="#", display=False)

    def load_image(self, file, tftp_ip, timeout=120):
        try:
            #self.back_to_root_level()
            self.send_command("config global", exp="(global)", must_find=True)
            self.send_command(
                f"execute restore image tftp {file} {tftp_ip}",
                exp=r"n\)",
            )
            self.send_command("y", newline=False)
            """
            def get_image_func():
                out = self.get_output()
                return "Get image from tftp server OK." in out

            result = wait_until(get_image_func, timeout=timeout, period=5)
"""
            end_time = time() + timeout
            print(end_time)
            while time() < end_time:
                out = self.get_output()
                if "(y/n)" in out:
                    self.send_command("y", newline=False)

            self.wait_fortigate_bootup()
            self.set_password_after_reset()
            logger.info("load image done")
        except Exception as e:
            logger.exception("Error when loading image", exc_info=e)

    def load_signature(self, command):
        try:
            self.send_command(command, exp=r"n\)", must_find=True, timeout=60)
            self.send_command("y", newline=False, exp="tftp server OK", timeout=60)
        except Exception as e:
            logger.exception("Error when update signatrue", exc_info=e)

    def restore_settings(self, file, tftp_ip):
        self.back_to_root_level()
        self.send_command("config global", exp="(global)")
        self.send_command(
            f"execute restore config tftp {file} {tftp_ip}",
            exp=r"n\)",
            must_find=True
        )
        self.send_command("y", newline=False)
        self.wait_fortigate_bootup()

    def get_current_credential(self):
        return {"username": self.username, "password": self.password}

    def clear_session(self):
        cmd = [
            "config global",
            "diagnose sys session filter policy 1",
            "diag sys session clear",
            "diag sys session6 clear",
            "end"
        ]
        self.send_commands(cmd)

    def check_blade_sync(self):
        if self.multi_blade:
            cmd = [
                "config global",
                "diag sys confsync status",
                "end"
            ]

            out = self.send_commands(cmd)
            if len(out) > 0:
                in_sync_re = re.compile(r"in_sync=(.*?)$")
                members_re = re.compile(r"members:(.*?)$")
                out = out[1].split("\n")
                is_status = False
                members = 0
                in_sync = 0
                not_in_sync = []
                for line_number, line in enumerate(out):
                    if line.startswith("====="):
                        if out[line_number + 1].startswith("MBD"):
                            is_status = True
                            continue
                        if is_status:
                            break
                    if is_status:
                        if members == 0:
                            member_match = members_re.search(line)
                            if member_match:
                                members = int(member_match.group(1))
                        in_sync_match = in_sync_re.search(line)
                        if in_sync_match:
                            sync_stat = int(in_sync_re.search(line).group(1))
                            if sync_stat == 1:
                                in_sync += 1
                            else:
                                not_in_sync.append(line)

                if in_sync > 0 and in_sync == members:
                    logger.info(
                        f"All Slaves are in sync with master, "
                        f"members = {members}, in_sync={in_sync}"
                    )
                    return True

                err = "\n".join(not_in_sync)
                logger.info(
                    f"Slave \n {err}\n not in sync"
                )
                return False
        else:
            logger.info("Not multi-blade system, no need check sync status")
            return


if __name__ == "__main__":
    topology_name = os.getenv('TOPOLOGY_NAME')
    #topology_name = 'FGT7040E-2'
    
    if len(sys.argv) < 2:
        logger.info("Usage: python FGT_update.py <atp_setting.json>")
        sys.exit(1)

    atp_setting_file = sys.argv[1]
    try:
        with open(atp_setting_file, 'r') as file:
            atp = json.load(file)
        logger.info(atp)
    except Exception as e:
        print(f"Failed to load ATP settings: {e}")
    
    #atp = {"ftp": "10.160.90.106", "os_image": "/images/FortiOS/v7.00/build1681/FGT_7000E-v7-build1681-FORTINET.out", "os_image_info": {"project": "FortiOS", "version": "7", "build": "1681", "file_pattern": "FGT_7000E-.*\\.out", "branch": "main"}, "os_product": "FortiOS", "os_ver": "7.2.9dev", "os_build": "1681", "os_prefix": "FGT_7000E", "os_label": "Interim Build < Target Version >", "ips_image": "/images/IPSEngine/v7.00/build0342/flen-fos7.2-7.342.pkg", "ips_image_info": {"project": "IPSengine", "version": "7", "build": "0342", "file_pattern": "flen-fos\\d+\\.\\d+-\\d\\.\\d{3,4}\\.pkg", "branch": "main"}, "ips_ver": "7.2.9dev", "ips_build": "0342", "ips_label": "Interim Build", "config": "BMRK-SLBC-7040E-2", "config_file_id": "", "config_version": "", "config_build": "", "config_checksum": "", "signature": {"apdb": [{"version": "28.833", "file": "/apdb/apdb-720-28.833.pkg"}], "fmwp": [{"version": "24.070", "file": "/fmwp/fmwp-720-24.070.pkg"}], "iotd": [{"version": "28.833", "file": "/iotd/iotd-720-28.833.pkg"}], "isdb": [{"version": "28.827", "file": "/isdb/isdb-720-28.827.pkg"}], "nids": [{"version": "28.833", "file": "/nids/nids-720-28.833.pkg"}], "otdb": [], "otdp": [], "avdb": [{"version": "92.06178", "file": "/avdb/vsigupdate-OS7.2.0_92.06178.ETDB.High.pkg"}], "exdb": [{"version": "92.06061", "file": "/exdb/vsigupdate-OS7.2.0_92.06061.EXDB.pkg"}], "mmdb": [{"version": "92.06177", "file": "/mmdb/vsigupdate-OS7.2.0_92.06177.MMDB.pkg"}], "fldb": [{"version": "92.06178", "file": "/fldb/vsigupdate-OS7.2.0_92.06178.FLDB.pkg"}], "avai": [{"version": "2.17356", "file": "/avai/vsigupdate-OS7.2.0_2.17356.AVAI.pkg"}]}, "signature_path": "signature/7.2"}
    device = get_device_info(topology_name)
    
    tftp_ip = atp['ftp']
    if not atp['os_image']:
        os_file = f"{atp['os_prefix']}-v{atp['os_image_info']['version']}-build{atp['os_build']}-FORTINET.out"
    else:
        os_file = atp['os_image']
    mmdb_file =  f'{atp["signature_path"]}{atp["signature"]["mmdb"][0]["file"]}'
    fldb_file =  f'{atp["signature_path"]}{atp["signature"]["fldb"][0]["file"]}'
    etdb_file =  f'{atp["signature_path"]}{atp["signature"]["avdb"][0]["file"]}'   
    apdb_file =  f'{atp["signature_path"]}{atp["signature"]["apdb"][0]["file"]}'
    nids_file =  f'{atp["signature_path"]}{atp["signature"]["nids"][0]["file"]}'
    isdb_file =  f'{atp["signature_path"]}{atp["signature"]["isdb"][0]["file"]}'
    command_mmdb = f"execute restore av tftp {mmdb_file} {atp['ftp']}"
    command_fldb = f"execute restore av tftp {fldb_file} {atp['ftp']}"
    command_etdb = f"execute restore av tftp {etdb_file} {atp['ftp']}"
    command_apdb = f"execute restore ips tftp {apdb_file} {atp['ftp']}"
    command_nids = f"execute restore ips tftp {nids_file} {atp['ftp']}"
    command_isdb = f"execute restore ips tftp {isdb_file} {atp['ftp']}"

    con = FortigateConsole(
        device['console_ip'], port=device['console_port'], username=device['username'], password=device['password'],
        multi_blade=False, console_type='esxi')
    con.clear_line()
    con.login_fortigate()
    con.clear_line()
    con.load_image(os_file, tftp_ip)
    con.send_command("config global")
    con.load_signature(command_apdb)
    con.load_signature(command_nids)
    con.load_signature(command_isdb)
    con.load_signature(command_mmdb)
    con.load_signature(command_fldb)
    con.load_signature(command_etdb)
    con.clear_line()
    con.login_fortigate()
    con.clear_session()