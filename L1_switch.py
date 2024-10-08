import requests
import time
import os
from logger import get_logger


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


def map_topology(topology_name):
    map_dict = {
        "FGT1801F": "FG1801F",
        "FGT2601F": "FG2601F",
        "FGT3001F": "3000F",
        "FGT3501F": "3000F",
        "FGT4201F": "4201F",
        "FGT4401F": "FG4401F-G2",
        "FGT4801F": "4801F",
        "FGT6501F": "6501F-gen2",
        "FGT7040E-2": "7040E-2",
        "FGT7KF": "7KF-72"
        }
    return map_dict[topology_name]

def activate_topology(topology_name):
    ip = "10.160.70.74"
    user = "BMRKAUTO"
    password = "netscout2"
    logger = get_logger(name=f"cli.{ip}")
    sw = NetScoutSw(ip, user, password)
    try:
        response_activate = sw.operate_topology(map_topology(topology_name), "activate")
        assert "Successful" in response_activate["message"]
        time.sleep(30)
    except Exception as e:
        logger.info(f"Failed to activate topology: {str(e)}")
        raise
    finally:
        sw.logout()


def deactivate_topology(topology_name):
    ip = "10.160.70.74"
    user = "BMRKAUTO"
    password = "netscout2"
    logger = get_logger(name=f"cli.{ip}")
    sw = NetScoutSw(ip, user, password)
    try:
        response_deactivate = sw.operate_topology(map_topology(topology_name), "deactivate")
        assert "Successful" in response_deactivate["message"]
        time.sleep(30)
    except Exception as e:
        logger.info(f"Failed to activate topology: {str(e)}")
        raise
    finally:
        sw.logout()


if __name__ == "__main__":
    topology_name = os.getenv('TOPOLOGY_NAME')
    #topology_name = 'FGT6501F'
    L1_status = os.getenv('L1_status')
    if L1_status == 'activate':
        activate_topology(topology_name)
    elif L1_status == 'deactivate':
        deactivate_topology(topology_name)