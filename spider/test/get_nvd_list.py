from spider.cve_spider import CVESpider
from spider.thirdpart.nvd import NVDSpider

if __name__ == '__main__':
    spider = CVESpider(NVDSpider(), None)
    spider.get_list()