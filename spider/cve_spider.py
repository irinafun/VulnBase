from spider.framework import Spider
from typing import List
from spider.exception import NotImplementException
from datetime import datetime

import threading

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
    
    def __eq__(self, other):
        return self.component_name == other.component_name and self.component_version == other.component_version

class CVEDetailItem:
    cve_id: str = ''
    cve_url: str = ''
    cve_description: str = ''
    cve_timestamp: int = 0

    
    poc: str = '' # poc
    exp: str = '' # exp
    refs: List[str] = [] # refs to other website
    components: List[CVEComponentItem] = [] # components affected, like ['nginx:1.1.1', 'nginx:1.1.2']

    def __init__(self, cve_id, cve_url, cve_description, cve_timestamp, poc, exp):
        self.cve_id = cve_id
        self.cve_url = cve_url
        self.cve_description = cve_description
        self.cve_timestamp = cve_timestamp
        self.poc = poc
        self.exp = exp
    
    def __str__(self):
        # most 5 lines of poc and exp
        poc = self.poc.split('\n')
        exp = self.exp.split('\n')
        poc = poc[:5]
        exp = exp[:5]
        poc = '\n'.join(poc) + '\n...'
        exp = '\n'.join(exp) + '\n...'

        return 'cve: {}, created: {} \n exp: \n{} \n poc: \n{}'.format(self.cve_id, datetime.fromtimestamp(self.cve_timestamp), exp, poc)
    
    '''
        check if current cve detail is enough
    '''
    def info_enough(self) -> bool:
        return self.poc != '' and self.exp != '' and len(self.components) > 0 and self.cve_description != ''
    
    '''
        merge two cve detail
    '''
    def __add__(self, other):
        if self.cve_id != other.cve_id:
            raise Exception('cve id not match')
        
        if self.cve_description == '':
            self.cve_description = other.cve_description
        
        if self.poc == '':
            self.poc = other.poc
        
        if self.exp == '':
            self.exp = other.exp
        
        if len(other.refs) > 0:
            for ref in other.refs:
                if ref not in self.refs:
                    self.refs.append(ref)
        
        if len(other.components) > 0:
            for component in other.components:
                if component not in self.components:
                    self.components.append(component)
        
        return self
        

class CVEListSpider(Spider):
    def __init__(self):
        pass

    '''
        fetch cve list from source, and return a list of cve
    '''
    def get_list(self) -> List[CVESimpleItem]:
        raise NotImplementException('get_list')

class CVEDetailSpider(Spider):
    '''
        priority of this spider, the higher the priority, the earlier it will be executed
        from 0 to 10
    '''
    __priority__ = 0

    def __init__(self, cve_list_spider: CVEListSpider):
        pass

    '''
        fetch cve detail from source, and return a cve detail
    '''
    def get_detail(self, cve_id: CVESimpleItem) -> CVEDetailItem:
        raise NotImplementException('get_detail')

class CVESpider(Spider):
    def __init__(self, cve_list_spider: List[CVEListSpider], cve_detail_spider: List[CVEDetailSpider]):
        self.cve_list_spider = cve_list_spider
        self.cve_detail_spider = cve_detail_spider

        # rank cve detail spider by priority
        self.cve_detail_spider.sort(key=lambda x: x.__priority__, reverse=True)

        self._max_thread = 10

    '''
        fetch cve list from source, and return a list of cve
    '''
    def get_list(self) -> List[CVESimpleItem]:
        items = []

        threads = []
        cve_map = {}
        thread_lock = threading.Lock
        if max_thread > len(self.cve_list_spider):
            max_thread = len(self.cve_list_spider)
        
        def _get_list(spider: CVEListSpider):
            list = spider.get_list()

            thread_lock.acquire()
            # check if item already exists
            for item in list:
                if item.cve_id not in cve_map:
                    cve_map[item.cve_id] = item
                    items.append(item)
                else:
                    cve = cve_map[item.cve_id]
                    for ref in item.refs:
                        cve.add_ref(ref)
            thread_lock.release()

        for i in range(max_thread):
            thread = threading.Thread(target=_get_list, args=(self.cve_list_spider[i],))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        return items
    
    '''
        fetch cve detail from source, and return a cve detail
    '''
    def get_detail(self, cve: CVESimpleItem) -> CVEDetailItem:
        detail = None
        for spider in self.cve_detail_spider:
            temp_detail = spider.get_detail(cve)
            if temp_detail is None:
                continue

            if detail is None:
                detail = temp_detail
            else:
                detail += temp_detail
            
            if detail.info_enough():
                break
        
        return detail
    
    '''
        start
    '''
    def start(self) -> List[CVEDetailItem]:
        items = self.get_list()
        for item in items:
            detail = self.get_detail(item)
            print(detail)