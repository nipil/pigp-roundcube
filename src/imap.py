import logging
import socket
import threading
import time

class ImapThread(threading.Thread):

    def __init__(self, ssl_client_socket):
        super().__init__()
        self._ssl_client_sock = ssl_client_socket

    def get_client_ssl_socket(self):
        return self._ssl_client_sock

    def run(self):
        logging.debug("imap thread start for client socket {0}".format(self._ssl_client_sock.fileno()))
        logging.debug("write")
        self._ssl_client_sock.send("* OK IMAP4rev1 Service Ready\r\n".encode())
        logging.debug("begin sleep")
        time.sleep(5)
        logging.debug("imap thread finished for client socket {0}".format(self._ssl_client_sock.fileno()))

    def recv(self, fileobj, mask):
        logging.debug("recv fileobj {0} mask {1}".format(fileobj, mask))
        buff = self._ssl_client_sock.recv()
        logging.debug("recv buff: {0}".format(buff))
