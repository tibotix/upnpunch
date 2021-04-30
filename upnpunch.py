import sys
from multiprocessing import Process
from http.server import ThreadingHTTPServer
from upnp_server import upnp_server
import argparse
import signal

try:
    from scapy.all import *
except ImportError:
    import fcntl
    import struct
    import socket
    def get_if_addr(iface):
        print("l")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface.encode("utf-8")[:15])
        )[20:24])



parser = argparse.ArgumentParser()
parser.add_argument("-i", "--iface", type=str, help="Interface to use.")
parser.add_argument("-t", "--template", action="append", help="Templates to use. You can specify more templates by using this identifier again.")

args = parser.parse_args()

iface = args.iface
ip = get_if_addr(iface)

http_servers = list()
http_servers_procs = list()
upnp_request_handlers = list()
upnp_response_handlers = list()
for template in args.template:
    t = __import__("exploit_templates.{}.template".format(str(template.replace("..",""))), fromlist=["template"])
    s = ThreadingHTTPServer((ip, t.Template.HTTP_PORT), t.Template.HTTPHandler)
    s.session_usn = t.Template.SESSION_USN
    http_servers.append(s)
    upnp_request_handlers.append(t.Template.UPNPRequestHandler(ip, t.Template.HTTP_PORT, t.Template.SESSION_USN))
    upnp_response_handlers.append(t.Template.UPNPResponseHandler(ip, t.Template.HTTP_PORT, t.Template.SESSION_USN))


for server in http_servers:
    p = Process(target=server.serve_forever)
    p.start()
    http_servers_procs.append(p)
upnp_proc = Process(target=upnp_server.start_upnp, args=(ip, port, upnp_request_handlers, upnp_response_handlers))

try:
    upnp_proc.start()
    signal.pause()
except (KeyboardInterrupt, SystemExit):
    print("\nTerminating")
    upnp_proc.terminate()
    for server in http_servers_procs:
        server.terminate()
    sys.exit()
