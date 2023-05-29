ACCESS_TOKEN = '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'

'''
    the repos which has losts of trash issues, we should ignore them and do search in a init progress
    to avoid the waste of time
'''
BLACK_LIST_REPOS = [
    'cloudsecurityalliance/gsd-database',
    'CVEProject/cvelist',
    'tholian-network/vulnerabilities',
    'Patrowl/PatrowlHearsData',
    'github/advisory-database',
    'nomi-sec/NVD-Database',
    'oasis-open/cti-stix-common-objects',
    'goncalor/cve-ark',
    'olbat/nvdcve',
    'CVEProject/cvelistV5',
    'Tabll/gemnasium-db',
    'Kaan-Deltics/OpenCVE-RSS-Feed'
]

def is_black_repo(repo: str) -> bool:
    for black in BLACK_LIST_REPOS:
        if repo == black:
            return True
    return False