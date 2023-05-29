from spider.cve_spider import CVESpider
from spider.thirdpart.nvd_spider import NVDSpider
from spider.thirdpart.github_spider import GithubSpider
from spider.thirdpart.exploit_db_spider import ExploitDBSpider
from core import init_vulnhub

import argparse

if __name__ == '__main__':
    init_vulnhub()

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', type=str, default='spider', help='mode: spider, cached')
    args = parser.parse_args()

    if args.m == 'spider':
        spider = CVESpider([NVDSpider()], [GithubSpider(), ExploitDBSpider()])
        spider.start()
    elif args.m == 'cached':
        list = NVDSpider.get_cached_list()
        print(f'cached list length: {len(list)}')