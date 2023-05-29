from typing import List
from spider.cve_spider import CVEListSpider, CVESimpleItem
from spider.utils.http import HttpUtils
from spider.utils.logger import Logger
from datetime import datetime

import pickle
import time

class NVDSpider(CVEListSpider):
    def __init__(self):
        self.nvd_list_api = 'https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=1000&startIndex={}'

    def get_list(self) -> List[CVESimpleItem]:
        cve_list = []
        # try load from cache
        try:
            with open('cache/nvd_cve_list.pkl', 'rb') as f:
                cve_list = pickle.load(f)
            Logger.info(f'load cached nvd cve list success, got {len(cve_list)} items')
        except:
            Logger.info('load cached nvd cve list failed')
            pass

        total = int(9e10)
        start_time = datetime.now()
        for i in range(len(cve_list), total, 1000):
            # check time, ensure there is about 10 secounds since last request
            if (datetime.now() - start_time).seconds < 10:
                Logger.info('sleep 10 seconds to avoid request too fast')
                time.sleep(10)
            start_time = datetime.now()

            cve_list_url = self.nvd_list_api.format(i)
            # get cve list
            try:
                result = HttpUtils.get(cve_list_url, HttpUtils.accept_json())
                if result['totalResults'] == 0:
                    break
                total = result['totalResults']

                if 'result' in result:
                    for cve in result['result']['CVE_Items']:
                        cve_id = cve['cve']['CVE_data_meta']['ID']
                        cve_url = 'https://nvd.nist.gov/vuln/detail/' + cve_id
                        
                        description = ''
                        if cve['cve']['description']['description_data'] is not None:
                            cn_description = list(filter(lambda x: x['lang'] == 'zh', cve['cve']['description']['description_data']))
                            if len(cn_description) > 0:
                                description = cn_description[0]['value']
                            elif len(cve['cve']['description']['description_data']) > 0:
                                lang = cve['cve']['description']['description_data'][0]['lang']
                                description = cve['cve']['description']['description_data'][0]['value']
                                # TODO: translate description
                                description = description + ' (lang: {})'.format(lang)
                        
                        refs = []
                        if cve['cve']['references']['reference_data'] is not None:
                            for ref in cve['cve']['references']['reference_data']:
                                refs.append(ref['url'])
                        
                        published_date = cve['publishedDate']
                        # format: 2020-01-01T00:00Z
                        timestamp = datetime.strptime(published_date, '%Y-%m-%dT%H:%MZ').timestamp()

                        item = CVESimpleItem(cve_id, cve_url, description, timestamp)

                        for ref in refs:
                            item.add_ref(ref)
                        
                        cve_list.append(item)
            except Exception as e:
                Logger.warning('get cve list failed: {}, {}'.format(cve_list_url, e))
                e.with_traceback()
                continue

            Logger.info('checkpoint: {} / {}, saved cache'.format(i + 1000, total))

            # save to cache
            with open('cache/nvd_cve_list.pkl', 'wb') as f:
                pickle.dump(cve_list, f)
                
        return cve_list

    @staticmethod
    def get_cached_list() -> List[CVESimpleItem]:
        cve_list = []
        # try load from cache
        try:
            with open('cache/nvd_cve_list.pkl', 'rb') as f:
                cve_list = pickle.load(f)
        except:
            pass
        return cve_list