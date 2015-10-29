import http.client
import requests


# Monkey patching that instruments the HTTPResponse to collect connection
# source port info
class MonitoredHTTPResponse(http.client.HTTPResponse):
    local_address = None

    def __init__(self, sock, *args, **kwargs):
        self.local_address = sock.getsockname()
        # print(self.local_address)
        super(MonitoredHTTPResponse, self).__init__(sock, *args, **kwargs)

requests.packages.urllib3.connection.HTTPConnection.response_class = MonitoredHTTPResponse

