from test import test_github_search, test_exploit_db
from core import init_vulnhub

if __name__ == '__main__':
    init_vulnhub()
    
    test_exploit_db.test()