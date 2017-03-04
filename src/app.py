import argparse
import logging
import signal
import socket

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
        # signal handling
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        # arguments
        parser = argparse.ArgumentParser()
        parser.add_argument('--listen-port',
            metavar='port',
            help="listen on this TCP port",
            type=int,
            default=993)
        parser.add_argument('--listen-ipv4',
            metavar='ipv4',
            help="listen on this IPv4 address",
            default="127.0.0.1")
        parser.add_argument('--listen-ipv6',
            metavar='ipv6',
            help="listen on this IPv6 address",
            default="::1")
        parser.add_argument('--max-wait-conn',
            metavar='nwc',
            help="maximum allowed connections waiting",
            default=50)
        Main.Arguments = parser.parse_args()
        logging.debug("Arguments: {0}".format(Main.Arguments))

    def create_listen_socket(self, address_family, bind_address):
        logging.debug("creating socket of family {0}".format(address_family))
        sock = socket.socket(address_family, socket.SOCK_STREAM)
        logging.debug("socket {0} created, binding it to {1} on TCP port {2}".format(sock.fileno(), bind_address, Main.Arguments.listen_port))
        sock.bind((bind_address, Main.Arguments.listen_port))
        logging.debug("setting listen queue to {1} on socket {0}".format(sock.fileno(), Main.Arguments.max_wait_conn))
        sock.listen(Main.Arguments.max_wait_conn)
        return sock

    def run(self):
        logging.info("starting applicaiton")
        # listen sockets
        if Main.Arguments.listen_ipv4:
            self.listen_sock_v4 = self.create_listen_socket(socket.AF_INET, Main.Arguments.listen_ipv4)
            logging.debug("listening ipv4 socket is {0}".format(self.listen_sock_v4))
        if Main.Arguments.listen_ipv6:
            self.listen_sock_v6 = self.create_listen_socket(socket.AF_INET6, Main.Arguments.listen_ipv6)
            logging.debug("listening ipv6 socket is {0}".format(self.listen_sock_v6))
        if not self.listen_sock_v4 and not self.listen_sock_v6:
            raise Exception("No listening socket created")
        # accept loop
        while not Main.RequestExit:
            pass
        # close listening sockets
        if self.listen_sock_v4:
            self.listen_sock_v4.shutdown(socket.SHUT_RDWR)
            self.listen_sock_v4.close()
            self.listen_sock_v4 = None
        if self.listen_sock_v6:
            self.listen_sock_v6.shutdown(socket.SHUT_RDWR)
            self.listen_sock_v6.close()
            self.listen_sock_v6 = None
        logging.info("terminating applicaiton")
