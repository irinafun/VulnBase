from spider.thirdpart.github_spider import GithubSpider
from spider.cve_spider import CVESimpleItem, CVEDetailItem

def test():
    spider = GithubSpider()
    detail = spider.get_detail(CVESimpleItem('CVE-2022-0847', 'https://', 'asdasdasd', 321321))

    print(detail)