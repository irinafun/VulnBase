from spider.thirdpart.exploitdb import ExploitDB
from spider.utils.logger import Logger

def init_exploit_db():
    try:
        ExploitDB.init()
    except Exception as e:
        Logger.error('init exploit-db failed: %s' % e)
        raise e

def init_vulnhub():
    init_exploit_db()