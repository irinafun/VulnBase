import logging

logger = logging.getLogger('spider')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)

class Logger:
    @staticmethod
    def debug(msg):
        logger.debug(msg)

    @staticmethod
    def info(msg):
        logger.info(msg)
    
    @staticmethod
    def warning(msg):
        logger.warning(msg)