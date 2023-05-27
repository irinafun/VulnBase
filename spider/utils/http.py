from typing import TypeVar, List
from requests import request

T = TypeVar('T')

'''
    http utils
'''
class HttpUtils:

    '''
        timeout: milliseconds
    '''
    @staticmethod
    def timeout(timeout: int):
        return {'typ': 'timeout', 'val': timeout}
    
    @staticmethod
    def cookies(name: str, value: str):
        return {'typ': 'cookies', 'val': { 'name': name, 'value': value }}
    
    @staticmethod
    def headers(name: str, value: str):
        return {'typ': 'headers', 'val': { 'name': name, 'value': value }}
    
    @staticmethod
    def data(name: str, value: str):
        return {'typ': 'data', 'val': { 'name': name, 'value': value }}
    
    @staticmethod
    def accept_json():
        return {'typ': 'accept_type', 'val': 'json'}
    
    @staticmethod
    def accept_xml():
        return {'typ': 'accept_type', 'val': 'xml'}

    @staticmethod
    def accept_text():
        return {'typ': 'accept_type', 'val': 'text'}
    
    @staticmethod
    def proxy(address: str, port: int, protocol: str):
        return {'typ': 'proxy', 'val': { 'address': address, 'port': port, 'protocol': protocol }}
    
    @staticmethod
    def proxy_auth(username: str, password: str):
        return {'typ': 'proxy_auth', 'val': { 'username': username, 'password': password }}
    
    '''
        send http request
    '''
    @staticmethod
    def request(url: str, method: str, *options: List[dict]) -> T:
        timeout = 3000
        cookies = None
        headers = None
        data = None
        accept_type = "json"
        proxy = {
            'address': '',
            'port': 0,
            'protocol': '',
            'username': '',
            'password': ''
        }

        for option in options:
            if option['typ'] == 'timeout':
                timeout = option['val']
            elif option['typ'] == 'cookies':
                if cookies is None:
                    cookies = {}
                cookies[option['val']['name']] = option['val']['value']
            elif option['typ'] == 'headers':
                if headers is None:
                    headers = {}
                headers[option['val']['name']] = option['val']['value']
            elif option['typ'] == 'data':
                if data is None:
                    data = {}
                data[option['val']['name']] = option['val']['value']
            elif option['typ'] == 'accept_type':
                accept_type = option['val']
                if headers is None:
                    headers = {}
                if accept_type == 'json':
                    headers['Accept'] = 'application/json'
                elif accept_type == 'text':
                    headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
                elif accept_type == 'xml':
                    headers['Accept'] = 'application/xml'
            elif option['typ'] == 'proxy':
                proxy['address'] = option['val']['address']
                proxy['port'] = option['val']['port']
                proxy['protocol'] = option['val']['protocol']
            elif option['typ'] == 'proxy_auth':
                proxy['username'] = option['val']['username']
                proxy['password'] = option['val']['password']

        proxy_address = f'{proxy["protocol"]}://{proxy["address"]}:{proxy["port"]}'
        if proxy['username'] != '' and proxy['password'] != '':
            proxy = f'{proxy["username"]}:{proxy["password"]}@{proxy_address}'

        result = request(method, url, timeout=timeout, cookies=cookies, headers=headers, data=data, proxies=proxy)

        if accept_type == 'json':
            return result.json()
        elif accept_type == 'xml':
            return result.xml()
        return result.text

    '''
        send http get request
    '''
    @staticmethod
    def get(url: str, *options: List[dict]) -> T:
        return HttpUtils.request(url, 'get', *options)
    
    '''
        send http post request
    '''
    @staticmethod
    def post(url: str, *options: List[dict]) -> T:
        return HttpUtils.request(url, 'post', *options)
    