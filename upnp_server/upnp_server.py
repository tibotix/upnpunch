import ssdp
import asyncio
import socket
import logging
import struct

class DialMultiscreenOrgProtocol(ssdp.SimpleServiceDiscoveryProtocol):
    """Protocol to handle responses and requests."""
    def __init__(self, local_ip, local_port, upnp_request_handlers, upnp_response_handlers):
        self.local_ip = local_ip
        self.local_http_port = local_port
        self.upnp_request_handlers = upnp_request_handlers
        self.upnp_response_handlers = upnp_response_handlers

    def response_received(self, response: ssdp.SSDPResponse, addr: tuple):
        """Handle an incoming response."""
        for header in response.headers:
            print("header: {}".format(header))

        for t in self.upnp_response_handlers:
            resp = t.handle(response, addr)
            if(resp is not None):
                resp.sendto(self.transport, addr)

    def request_received(self, request: ssdp.SSDPRequest, addr: tuple):
        """Handle an incoming request and respond to it."""

        for t in self.upnp_request_handlers:
            resp = t.handle(request, addr)
            if(resp is not None):
                resp.sendto(self.transport, addr)



def start_upnp(ip, port, upnp_request_handlers, upnp_response_handlers):

    print("[*] local_ip: {0}".format(str(ip)))
    # Start the asyncio loop.

    l = logging.getLogger("ssdp")
    l.setLevel(logging.INFO)
    l.addHandler(logging.StreamHandler())

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 1900))
    sock.setblocking(False)
    group = socket.inet_aton(DialMultiscreenOrgProtocol.MULTICAST_ADDRESS)
    mreq = struct.pack('4s4s', group, socket.inet_aton(ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


    loop = asyncio.get_event_loop()
    connect = loop.create_datagram_endpoint(
        lambda: DialMultiscreenOrgProtocol(ip, port, upnp_request_handlers, upnp_response_handlers),
        sock=sock
    )
    transport, protocol = loop.run_until_complete(connect)

    DialMultiscreenOrgProtocol.transport = transport

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    transport.close()
    loop.close()


if(__name__ == "__main__"):
    start_upnp("", 8888)
