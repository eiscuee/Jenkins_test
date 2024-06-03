import requests
import time
import pytest


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


@pytest.fixture
def net_scout_sw_instance():
    ip = "10.160.70.74"
    user = "BMRKAUTO"
    password = "netscout2"
    return NetScoutSw(ip, user, password)


def test_activate_topology(net_scout_sw_instance):
    sw = net_scout_sw_instance
    topology_name = pytest.config.getoption('--topology_name')
    response_activate = response_activate = sw.operate_topology(topology_name, "activate")
    assert "Successful" in response_activate["message"]
    
    time.sleep(30)
    sw.logout()


def test_deactivate_topology(net_scout_sw_instance):
    sw = net_scout_sw_instance
    topology_name = pytest.config.getoption('--topology_name')
    response_activate = response_activate = sw.operate_topology(topology_name, "deactivate")
    assert "Successful" in response_activate["message"]
    
    time.sleep(30)
    sw.logout()
