import requests
import time
import os


class NetScoutSw:
    def __init__(self, ip, user, password):
        self.ip = ip
        self.user = user
        self.password = password
        self.header = {}

    def send(self, method, url):
        if len(self.header) == 0:
            self.login()
        print(f"Sending {method} request to {url} with headers {self.header}")
        x = requests.request(method, url, headers=self.header)
        print(f"Response status code: {x.status_code}, Response text: {x.text}")
        if x.status_code == 200:
            return x.json()
        elif x.status_code == 401:
            print("401 Unauthorized - Check your credentials or token")
            res = x.json()
            raise NameError(res["message"])
        elif x.status_code == 400:
            res = x.json()
            raise NameError(res["message"])
        else:
            msg = f"URL {url} failed with status code {x.status_code} and reason {x.reason}"
            raise RuntimeError(msg)

    def login(self):
        url = f"http://{self.ip}:8080/api/teststream/v1/session/commands/login"
        auth_header = requests.auth.HTTPBasicAuth(self.user, self.password)
        print(f"Attempting to log in with user: {self.user}")
        x = requests.post(url, auth=auth_header)
        print(f"Login response status code: {x.status_code}, Response text: {x.text}")
        if x.status_code == 200:
            token = x.json().get('token')
            if token:
                self.header = {"Authorization": f"Bearer {token}"}
                print(f"Login successful, token received: {token}")
            else:
                print("Login failed, no token received")
                raise RuntimeError("Login failed, no token received")
        else:
            msg = f"Failed to login, status code: {x.status_code}, reason: {x.reason}, response: {x.text}"
            raise RuntimeError(msg)
        
    def logout(self):
        url = f"http://{self.ip}:8080/api/teststream/v1/session/commands/logout"
        print(f"Attempting to log out from {url}")
        res = self.send("post", url)
        print(f"Logout response: {res}")

    def operate_topology(self, name, command=None):
        base_url = f"http://{self.ip}:8080/api/teststream/v1/topologies/{name}/commands"
        if command is None:
            url = base_url
            method = "get"
        elif command not in ["activate", "deactivate"]:
            raise ValueError(f"Wrong command: {command}")
        else:
            url = f"{base_url}/{command}"
            method = "post"
        return self.send(method, url)


def map_topology(topology_name):
    map_dict = {
        "FGT6501F": "6501F-gen2",
        "FGT7040E-2": "7040E-2",
        "FGT7KF": "7KF-72"
        }
    return map_dict[topology_name]

def activate_topology(topology_name):
    ip = "10.160.70.74"
    user = "josie"
    password = "a"
    sw = NetScoutSw(ip, user, password)
    response_activate = sw.operate_topology(map_topology(topology_name), "activate")
    assert "Successful" in response_activate["message"]
    
    time.sleep(30)
    sw.logout()


def deactivate_topology(topology_name):
    ip = "10.160.70.74"
    user = "josie"
    password = "a"
    sw = NetScoutSw(ip, user, password)
    response_activate = sw.operate_topology(map_topology(topology_name), "deactivate")
    assert "Successful" in response_activate["message"]
    
    time.sleep(30)
    sw.logout()


if __name__ == "__main__":
    topology_name = 'FGT6501F'
    L1_status = 'deactivate'
    if L1_status == 'activate':
        activate_topology(topology_name)
    elif L1_status == 'deactivate':
        deactivate_topology(topology_name)
