import sys
from twisted.internet import reactor
from twisted.web import http
from twisted.python import log as log
from datetime import datetime
from email.utils import formatdate


log.startLogging(sys.stdout)
APP_NAME = 'http-open-proxy'

class HttpProxyProtocol(http.HTTPChannel):

    def __init__(self):
        super().__init__()
        self.buffer = b''
        self.header_received = False
        self.max_buffer_size = 8096

    def dataReceived(self, data):
        client = self.transport.getPeer()
        self.buffer += data
        # Check if we have received a complete HTTP header
        if b'\r\n\r\n' in self.buffer:
            self.header_received = True
            self._process_request()
        if sys.getsizeof(self.buffer) > self.max_buffer_size:
            log.err(f"app:{APP_NAME} source_ip:{client.host} source_port:{client.port} Max Buffer size {self.max_buffer_size} exceeded. cannot complete the HTTP Header.")
            # empty the buffer
            self.buffer = b""
            # Send a 400 Bad Request response since the request is too large
            self.transport.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            self.transport.loseConnection()

    def _process_request(self):
        ''' Log & Process Proxy request and Respond with HTTP 200'''
        client = self.transport.getPeer()
        # Split headers and body
        headers, body = self.buffer.split(b'\r\n\r\n', 1)

        # Parse headers
        request_line, *header_lines = headers.decode('utf-8').split("\r\n")
        method, uri, http_version = request_line.split(" ")

        request_headers = {}
        for line in header_lines:
            key, value = line.split(": ", 1)
            request_headers[key] = value
        log.msg(f"app:{APP_NAME} source_ip:{client.host} source_port:{client.port} http_version:{http_version} method:{method} uri:{uri} request_header:{request_headers}")
        # Reset the buffer for the next request
        self.buffer = b""
        # Get the current date and time in RFC 1123 format
        current_time = formatdate(timeval=None, localtime=False, usegmt=True)
        # Send a 200 OK response
        response_raw = f"HTTP/1.1 200 OK\r\nDate: {current_time}\r\nServer: squid/6.10\r\nContent-Length: 1028\r\n" + \
        "X-Cache: MISS from proxy.devnet.local\r\nX-Cache-Lookup: MISS from proxy.devnet.local:3128\r\n" + \
        f"<h1>{uri}</h1><TITLE>302 Moved</TITLE>" + \
        "\r\n"
        self.transport.write(response_raw.encode())
        self.transport.loseConnection()



class ProxyFactory(http.HTTPFactory):
    protocol = HttpProxyProtocol

if __name__ == '__main__':

    PORT = 3128  # You can change this to any port you prefer
    reactor.listenTCP(PORT, ProxyFactory())
    log.msg(f"Proxy server listening on port {PORT}...")
    reactor.run()
