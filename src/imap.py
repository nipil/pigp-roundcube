import logging
import socket
import threading
import time

class ImapThread(threading.Thread):

    def __init__(self, ssl_client_socket):
        super().__init__()
        self.ssl_client_sock = ssl_client_socket

    def run(self):
        logging.debug("imap thread start for client socket {0}".format(self.ssl_client_sock.fileno()))
        time.sleep(5)
        logging.debug("imap thread finished for client socket {0}".format(self.ssl_client_sock.fileno()))
        # debugging cleanup
        self.ssl_client_sock.shutdown(socket.SHUT_RDWR)
        self.ssl_client_sock.close()

    def recv(self):
        logging.debug("imap thread received something from client socket {0}".format(self.ssl_client_sock.fileno()))
        pass
