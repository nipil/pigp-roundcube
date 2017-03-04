import argparse
import logging

class Main:

    def __init__(self):
        parser = argparse.ArgumentParser()
        Main.Arguments = parser.parse_args()
        logging.debug("Arguments: {0}".format(Main.Arguments))

    def run(self):
        pass
