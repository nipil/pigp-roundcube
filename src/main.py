#!/usr/bin/env python

import sys
import logging

import app

if __name__ == "__main__":
    ret = 0
    try:
        logging.basicConfig(
            format='%(asctime)s %(levelname)s %(module)s %(message)s',
            level=logging.DEBUG)
        application = app.Main()
        ret = application.run()
    except Exception as e:
        logging.error("Exception: {0}".format(e))
        ret = 1
    logging.info("Exiting with code {0}".format(ret))
    sys.exit(ret)
