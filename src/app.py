import argparse
import logging
import selectors
import signal
import socket
import ssl

def signal_handler(signum, frame):
    logging.info("signal received, notifying end of application")
    Main.RequestExit = True

class Main:

    def __init__(self):
        # variables
        Main.RequestExit = False
        Main.Arguments = None
        self.listen_sock_v4 = None
        self.listen_sock_v6 = None
        self.listen_selector = None
        # signal handling
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        # arguments
        parser = argparse.ArgumentParser()
        parser.add_argument('--listen-port',
            metavar='PORT',
            help="listen on this TCP port",
            type=int,
            default=993)
        parser.add_argument('--listen-ipv4',
            metavar='IPV4',
            help="listen on this IPv4 address",
            default="127.0.0.1")
        parser.add_argument('--listen-ipv6',
            metavar='IPV6',
            help="listen on this IPv6 address",
            default="::1")
        parser.add_argument('--max-wait-conn',
            metavar='NWC',
            help="maximum allowed connections waiting",
            default=50)
        parser.add_argument('--ssl-ciphers', # TODO: UNTESTED !
            help="OpenSSL cipher string defining allowed cipher list",
            default=None)
        parser.add_argument('--ssl-pem-key',
            help="SSL/TLS key file (PEM format)",
            required=True)
        parser.add_argument('--ssl-pem-cert',
            help="SSL/TLS certificate file (PEM format)",
            required=True)
        Main.Arguments = parser.parse_args()
        logging.debug("Arguments: {0}".format(Main.Arguments))

    def create_listen_socket(self, address_family, bind_address):
        logging.debug("creating socket of family {0}".format(address_family))
        sock = socket.socket(address_family, socket.SOCK_STREAM)
        logging.debug("allowing address reuse for socket {0}".format(sock))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        logging.debug("socket {0} created, binding it to {1} on TCP port {2}".format(sock.fileno(), bind_address, Main.Arguments.listen_port))
        sock.bind((bind_address, Main.Arguments.listen_port))
        logging.debug("setting listen queue to {1} on socket {0}".format(sock.fileno(), Main.Arguments.max_wait_conn))
        sock.listen(Main.Arguments.max_wait_conn)
        return sock

    def accept_incoming_connection(self, fileobj, mask):
        logging.debug("accepting incoming connection on socket {0}".format(fileobj))
        client_sock, client_addr = fileobj.accept()
        logging.info("client socket {0} connected from {1} using source port {2}".format(client_sock.fileno(), *client_addr))
        ssl_client_sock = ssl.wrap_socket(client_sock,
            keyfile=Main.Arguments.ssl_pem_key,
            certfile=Main.Arguments.ssl_pem_cert,
            server_side=True,
            cert_reqs=ssl.CERT_NONE,
            ciphers=Main.Arguments.ssl_ciphers)
        logging.info("client socket wrapped as SSL socket {0} using version {1}, cipher {2} with {3} secret bits, and compression={4}".format(ssl_client_sock.fileno(), ssl_client_sock.version(), ssl_client_sock.cipher()[0], ssl_client_sock.cipher()[2], ssl_client_sock.compression()))
        ssl_client_sock.shutdown(socket.SHUT_RDWR)
        ssl_client_sock.close()
        logging.debug("client connection closed")

    def run(self):
        logging.info("starting applicaiton")
        # listen sockets
        if Main.Arguments.listen_ipv4:
            self.listen_sock_v4 = self.create_listen_socket(socket.AF_INET, Main.Arguments.listen_ipv4)
            logging.debug("listening ipv4 socket is {0}".format(self.listen_sock_v4))
            self.listen_sock_v4.settimeout(False)
            logging.debug("listening ipv4 socket set to non-blocking")
        if Main.Arguments.listen_ipv6:
            self.listen_sock_v6 = self.create_listen_socket(socket.AF_INET6, Main.Arguments.listen_ipv6)
            logging.debug("listening ipv6 socket is {0}".format(self.listen_sock_v6))
            self.listen_sock_v6.settimeout(False)
            logging.debug("listening ipv6 socket set to non-blocking")
        if not self.listen_sock_v4 and not self.listen_sock_v6:
            raise Exception("No listening socket created")
        # setup selector
        self.listen_selector = selectors.DefaultSelector()
        logging.debug("socket selector {0} created".format(self.listen_selector))
        if self.listen_sock_v4:
            logging.debug("registering listening ipv4 socket into socket selector")
            self.listen_selector.register(self.listen_sock_v4, selectors.EVENT_READ, self.accept_incoming_connection)
        if self.listen_sock_v6:
            logging.debug("registering listening ipv6 socket into socket selector")
            self.listen_selector.register(self.listen_sock_v6, selectors.EVENT_READ, self.accept_incoming_connection)
        # accept loop
        while not Main.RequestExit:
            # logging.debug("begin while")
            events = self.listen_selector.select(1)
            # logging.debug("events={0}".format(events))
            for key, mask in events:
                # logging.debug("begin for with key={0} and mask={1}".format(key, mask))
                callback = key.data
                # logging.debug("callback is {0} with fileobj={1}".format(callback, key.fileobj))
                callback(key.fileobj, mask)
                # logging.debug("end for")
            # logging.debug("end while")
        # teardown selector
        if self.listen_sock_v4:
            logging.debug("unregistering listening ipv4 socket from socket selector")
            self.listen_selector.unregister(self.listen_sock_v4)
        if self.listen_sock_v6:
            logging.debug("unregistering listening ipv6 socket from socket selector")
            self.listen_selector.unregister(self.listen_sock_v6)
        logging.debug("closing socket selector {0}".format(self.listen_selector))
        self.listen_selector.close()
        # close listening sockets
        self.listen_selector = selectors.DefaultSelector()
        if self.listen_sock_v4:
            self.listen_sock_v4.shutdown(socket.SHUT_RDWR)
            self.listen_sock_v4.close()
            self.listen_sock_v4 = None
        if self.listen_sock_v6:
            self.listen_sock_v6.shutdown(socket.SHUT_RDWR)
            self.listen_sock_v6.close()
            self.listen_sock_v6 = None
        logging.info("terminating applicaiton")
