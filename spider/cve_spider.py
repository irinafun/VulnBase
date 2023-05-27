from spider.framework import Spider
from typing import List
from spider.exception import NotImplementException
from datetime import datetime

class CVESimpleItem:
    cve_id = ''
    cve_url = ''
    cve_description = ''
    cve_timestamp = 0
    cve_level = 0 # 0: low, 1: medium, 2: high, 3: critical

    refs: List[str] = [] # refs to other website

    def __init__(self, cve_id, cve_url, cve_description, cve_timestamp, cve_level = 0):
        self.cve_id = cve_id
        self.cve_url = cve_url
        self.cve_description = cve_description
        self.cve_timestamp = cve_timestamp
        self.cve_level = cve_level
    
    def add_ref(self, ref: str):
        self.refs.append(ref)
    
    def formatLevel(self):
        if self.cve_level == 0:
            return 'low'
        elif self.cve_level == 1:
            return 'medium'
        elif self.cve_level == 2:
            return 'high'
        elif self.cve_level == 3:
            return 'critical'
        else:
            return 'unknown'

    def __str__(self):
        return 'cve: {}, created: {}, level: {}'.format(self.cve_id, datetime.fromtimestamp(self.cve_timestamp), self.formatLevel())


class CVEComponentItem:
    component_name = ''
    component_version = ''

    def __init__(self, component_name, component_version):
        self.component_name = component_name
        self.component_version = component_version

class CVEDetailItem:
    cve_id: str = ''
    cve_url: str = ''
    cve_description: str = ''
    cve_timestamp: int = 0

    
    poc: str = '' # poc
    exp: str = '' # exp
    refs: List[str] = [] # refs to other website
    components: List[CVEComponentItem] = [] # components affected, like ['nginx:1.1.1', 'nginx:1.1.2']

class CVEListSpider(Spider):
    def __init__(self):
        pass

    '''
        fetch cve list from source, and return a list of cve
    '''
    def get_list(self) -> List[CVESimpleItem]:
        raise NotImplementException('get_list')

class CVEDetailSpider(Spider):
    def __init__(self, cve_list_spider: CVEListSpider):
        pass

    '''
        fetch cve detail from source, and return a cve detail
    '''
    def get_detail(self, cve_id) -> CVEDetailItem:
        raise NotImplementException('get_detail')

class CVESpider(Spider):
    def __init__(self, cve_list_spider: CVEListSpider, cve_detail_spider: CVEDetailSpider):
        self.cve_list_spider = cve_list_spider
        self.cve_detail_spider = cve_detail_spider

    '''
        fetch cve list from source, and return a list of cve
    '''
    def get_list(self) -> List[CVESimpleItem]:
        return self.cve_list_spider.get_list()
    
    '''
        fetch cve detail from source, and return a cve detail
    '''
    def get_detail(self, cve_id) -> CVEDetailItem:
        return self.cve_detail_spider.get_detail(cve_id)
