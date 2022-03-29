from browsermobproxy import Server
import sys
import os
cwd = os.path.abspath(os.path.dirname(sys.argv[0]))
path_browsermod = cwd +r"/proxy/browsermob-proxy-2.1.4/bin/browsermob-proxy"
class ProxyManger:
    # Path to browser-mod 
    __BMP = path_browsermod

    def __init__(self):
        self.__server = Server(ProxyManger.__BMP)
        self.__client = None

    def start_server(self):
        self.__server.start()
        return self.__server

    def start_client(self):
        self.__client = self.__server.create_proxy(
            params={"trustAllServers": "true"})
        return self.__client

    @property
    def client(self):
        return self.__client

    @property
    def server(self):
        return self.__server
