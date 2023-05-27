from spider.cve_spider import CVEDetailSpider, CVEDetailItem, CVESimpleItem
from spider.thirdpart.github_factory import GithubFactory

class GithubSpider(CVEDetailSpider):
    def __init__(self):
        self.__priority__ = 5

    def check_if_c(self, content: str) -> bool:
        '''
            poc or exp is written in c is more likely to be a real exploit
            which will be executed in the kernel or system
            it will call system/exec/popen/fork to execute shell command or write sensitive file

            mostly, hacker like to leave their name in the code, so we can check if the code is written by hacker
        '''

        # command execution
        if ('bin/sh' in content or 'bin/bash' in content) and ('system' in content or 'exec' in content or 'popen' in content or 'fork' in content):
            return True
        
        # file operation
        if 'etc/passwd' in content or 'etc/shadow' in content or 'etc/hosts' in content or 'etc/group' in content:
            return True
        
        # hacker name
        if 'by hacker' in content or 'by 0x' in content or 'by 0day' in content or 'by 0xd0' in content or 'by 0x00' in content or 'by 0x0' in content:
            return True
        
        # directly exploit
        if 'exploit' in content or 'exploitation' in content:
            return True
        
        return False

    def check_if_python(self, content: str) -> bool:
        '''
            poc or exp written in python is more likely a network attack
            which will send http request to the target server and get response
            sometimes, it will require user to input some args, like ip, port, etc.

            mostly, hacker like to leave their name in the code, so we can check if the code is written by hacker
        '''

        # network attack
        if 'requests' in content and ('get(' in content or 'post(' in content or 'put(' in content or 'delete(' in content):
            return True
        if 'socket' in content and ('connect(' in content or 'send(' in content or 'recv(' in content):
            return True
        if 'urllib' in content and ('request(' in content or 'urlopen(' in content):
            return True
        if 'http' in content and ('get(' in content or 'post(' in content or 'put(' in content or 'delete(' in content):
            return True
                
        # hacker name
        if 'by hacker' in content or 'by 0x' in content or 'by 0day' in content or 'by 0xd0' in content or 'by 0x00' in content or 'by 0x0' in content:
            return True
        
        return False
    
    def check_if_go(self, content: str) -> bool:
        return False
    
    def check_if_java(self, content: str) -> bool:
        return False
    
    def check_if_php(self, content: str) -> bool:
        return False
    
    def check_if_js(self, content: str) -> bool:
        return False
    
    def check_if_ruby(self, content: str) -> bool:
        return False
    
    def check_if_shell(self, content: str) -> bool:
        '''
            shell script should be longer than 5 lines to avoid shell like 'gcc -o exp exp.c'
            which is not a real exploit code
        '''
        return False
    
    def check_if_perl(self, content: str) -> bool:
        return False
    
    def check_if_poc(self, content: str) -> bool:
        '''
            check if the code is a poc
        '''
        if 'poc' in content or 'proof of concept' in content:
            return True
        return False
    
    def check_if_exp(self, content: str) -> bool:
        '''
            check if the code is an exp
        '''
        if 'exp' in content or 'exploit' in content:
            return True
        return False

    def check_if_md(self, content: str) -> tuple[dict, bool]:
        '''
            there is a lot of exploit code written in markdown file
            what we need to do is split the markdown file into several parts to fetch the code
        '''

        code_start = [
            '```python', '```c', '```cpp', '```go', '```java', '```php', '```js', '```rb', '```bash', '```pl', '```shell', '```perl', '```sh', '```'
        ]
        code_end = '```'
        # walk through the content and find every code block
        # if the code block is written in c, python, go, java, php, js, rb, sh, pl, perl, shell, bash, cpp

        code_blocks = []
        for start in code_start:
            tmp_content = content
            index = tmp_content.find(start)
            while index != -1:
                tmp_content = tmp_content[index + len(start):]
                # find the end of the code block
                end_index = tmp_content.find(code_end)

                if end_index != -1:
                    # found
                    # add the code block to the list
                    code_blocks.append([start[3:], tmp_content[:end_index]])
                else:
                    # not found
                    # add the code block to the list, and break the loop
                    code_blocks.append([start[3:], tmp_content])
                    break

                # update the tmp_content and index to find the next code block, if any
                # if not, the index will be -1, and the loop will be break
                tmp_content = tmp_content[end_index + len(code_end):]
                index = tmp_content.find(start)
        
        # check if the code block is a real exploit code
        # if the code block is a real exploit code, return the code block

        exp_or_poc = []

        for code_block in code_blocks:
            lang = code_block[0]
            code = code_block[1]

            if lang == 'c':
                if self.check_if_c(code):
                    exp_or_poc.append(code)
            elif lang == 'python':
                if self.check_if_python(code):
                    exp_or_poc.append(code)
            elif lang == 'go':
                if self.check_if_go(code):
                    exp_or_poc.append(code)
            elif lang == 'java':
                if self.check_if_java(code):
                    exp_or_poc.append(code)
            elif lang == 'php':
                if self.check_if_php(code):
                    exp_or_poc.append(code)
            elif lang == 'js':
                if self.check_if_js(code):
                    exp_or_poc.append(code)
            elif lang == 'rb':
                if self.check_if_ruby(code):
                    exp_or_poc.append(code)
            elif lang == 'sh' or lang == 'shell' or lang == 'bash':
                if self.check_if_shell(code):
                    exp_or_poc.append(code)
            elif lang == 'pl' or lang == 'perl':
                if self.check_if_perl(code):
                    exp_or_poc.append(code)
            else:
                continue
        
        if len(exp_or_poc) == 0:
            return {
                'exp': '',
                'poc': ''
            }, False
        
        exp = ''
        poc = ''

        # if there are more than one code block, we need to choose the best one
        for code_block in exp_or_poc:
            if self.check_if_exp(code_block):
                exp = code_block
            elif self.check_if_poc(code_block):
                poc = code_block
        
        if poc == '':
            # use the longest code block as poc
            poc = max(exp_or_poc, key=lambda x: len(x))
        
        return {
            'exp': exp,
            'poc': poc
        }, True

    def get_detail(self, cve: CVESimpleItem) -> CVEDetailItem:
        cve_id = cve.cve_id

        github_instance = GithubFactory.get_github()
        result = github_instance.search_code(f'{cve_id} in:file,path')

        i = 0            
        for item in result:
            # check if the repository contains exploit code or poc and check if the repo is popular enough
            item_url = item.html_url
            repo = item.repository.full_name

            stars = item.repository.stargazers_count
            forks = item.repository.forks_count

            exp = ''
            poc = ''

            print(f'found {cve_id} in {item_url}')

            if stars < 10 and forks < 10:
                continue

            filetype = item.name.split('.')[-1]
            if filetype in ['zip', 'rar', '7z', 'gz']:
                continue

            if filetype in ['txt', 'conf', 'ini', 'cfg', 'log', 'bak']:
                continue

            content = item.decoded_content.decode('utf-8')

            wait_judge_poc_or_exp = ''

            if filetype in ['md', 'markdown']:
                poc_and_exp, is_exp_or_poc = self.check_if_md(content)
                if is_exp_or_poc:
                    poc = poc_and_exp['poc']
                    exp = poc_and_exp['exp']
            elif filetype in ['c', 'cpp']:
                if self.check_if_c(content):
                    wait_judge_poc_or_exp= content
            elif filetype in ['py']:
                if self.check_if_python(content):
                    wait_judge_poc_or_exp= content
            elif filetype in ['go']:
                if self.check_if_go(content):
                    wait_judge_poc_or_exp= content
            elif filetype in ['java']:
                if self.check_if_java(content):
                    wait_judge_poc_or_exp= content
            elif filetype in ['php']:
                if self.check_if_php(content):
                    wait_judge_poc_or_exp= content
            elif filetype in ['js']:
                if self.check_if_js(content):
                    wait_judge_poc_or_exp= content
            elif filetype in ['rb']:
                if self.check_if_ruby(content):
                    wait_judge_poc_or_exp= content
            elif filetype in ['sh', 'shell', 'bash']:
                if self.check_if_shell(content):
                    wait_judge_poc_or_exp= content
            elif filetype in ['pl', 'perl']:
                if self.check_if_perl(content):
                    wait_judge_poc_or_exp= content
            
            if wait_judge_poc_or_exp != '':
                if self.check_if_exp(wait_judge_poc_or_exp.lower()):
                    exp = wait_judge_poc_or_exp
                
                if self.check_if_poc(wait_judge_poc_or_exp.lower()):
                    poc = wait_judge_poc_or_exp

                if poc == '' and exp == '':
                    poc = wait_judge_poc_or_exp
            
            if poc != '' and exp != '':
                return CVEDetailItem(cve_id, cve.cve_url, cve_description=cve.cve_description, cve_timestamp=cve.cve_timestamp, poc=poc, exp=exp)
            
            i += 1
            if i > 15:
                break