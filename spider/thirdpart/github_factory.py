from spider.config.github import ACCESS_TOKEN

import github

github_instance = github.Github(ACCESS_TOKEN)

class GithubFactory:
    @staticmethod
    def get_github():
        return github_instance