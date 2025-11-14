import urllib.request
from bs4 import BeautifulSoup
import re
import json
import logging
import ssl
import os
import argparse
import sys
import js2py
import jsbeautifier

ssl._create_default_https_context = ssl._create_unverified_context

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()


def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -u http://www.baidu.com")
    parser.add_argument("-u", "--url", help="The website")
    parser.add_argument("-c", "--cookie", help="The website cookie")
    parser.add_argument("-r", "--request", help="The raw request ")
    parser.add_argument("-log", "--log_level", help="The log level, default level is DEBUG")
    parser.add_argument("-p", "--proxy", help="The proxy, default proxy is http://127.0.0.1:8080 ")
    parser.add_argument("-out", "--output_path", help="The output path, use relative path")
    parser.add_argument("-s", "--script", help="The script used to decode code obfuscation")
    return parser.parse_args()


class JSFinder(object):

    @staticmethod
    def __parse_host__(url):
        # 这里有个小bug
        count = url.count('/')
        if count > 2:
            file_name = os.path.basename(url)
            logger.debug("file_name: " + file_name)
            return url.replace(file_name, "")
        else:
            return url + "/"

    @staticmethod
    def __parse_url__(url):
        url = url.replace('/./', '/').replace('//', '/').replace(':/', '://')
        return url

    def __request_url__(self, url):

        try:
            response = self.opener.open(url).read().decode()
            file_name = os.path.basename(url).split('?')[0]
            if len(file_name) > 0:
                file_path = self.out + file_name
                if ".js" in file_name:
                    content = jsbeautifier.beautify(response)
                else:
                    content = response
                with open(file_path, mode='w', encoding='utf-8') as file_obj:
                    file_obj.write(content)
        except urllib.request.HTTPError as e:
            logger.error("request " + url + " error: " + str(e))
            return None
        else:
            return response

    def __init__(self, url):
        self.login_url = url
        self.host = self.__parse_host__(url)
        result = urllib.parse.urlparse(self.host)
        # 嗯 这里不能直接用host
        self.domain = result.scheme + "://" + result.netloc + "/"

        logger.debug("host: " + self.host)
        # 设置代理
        proxy = '127.0.0.1:8080'
        if args.proxy is not None:
            proxy = args.proxy
        proxy_support = urllib.request.ProxyHandler({'http': 'http://' + proxy,
                                                     'https': 'https://' + proxy})
        self.opener = urllib.request.build_opener(proxy_support)

        if args.cookie is not None:
            cookie = args.cookie
        else:
            cookie = ""
        headers = [("User-Agent",
                    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 "
                    "Safari/537.36 QIHU 360SE"),
                   ("Cookie", cookie)]

        self.opener.addheaders = headers

        # 设置输出目录
        app_name = self.host.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
        if args.output_path is not None:
            self.out = args.output_path + app_name + '/js/'
        else:
            self.out = app_name + '/js/'
        if not os.path.exists(self.out):
            os.makedirs(self.out)

        # 设置解码函数
        if args.script is not None:
            file_path = args.script
            with open(file_path, mode='r', encoding='utf-8') as file_obj:
                decode_function = file_obj.read()

            self.js = js2py.EvalJs()
            self.js.execute(decode_function)
            print(self.js.decode(0x862))

        # 记录所有的js，后面用来找api
        self.js_urls = []
        # 记录jsLoader名字白名单
        # 目前来看 这几个存在加载机制
        # app*.js mainifest*.js index*.js runtime*.js
        # 20240124 在目标系统种发现新的加载js：my*.js
        self.jsLoader_namelist = ["app.", "index", "manifest", "runtime", "my"]
        self.jsLoaders = {}

        # 查找暴露的js
        # 目前我们发现了有如下几类代码形式
        # 根据正则来匹配这些代码
        self.jsLoader_REs = [
            # 查找形如如下模式的代码：
            # f.p+"static/js/"+({"chunk-commons":"chunk-commons"}[e]||e)+"."+{"chunk-0ef6b8a9":"15dfbb38",
            # 获取两个东西：
            # 相对路径              static/js/
            # js文件名字典          ({"chunk-commons":"chunk-commons"}[e]||e)
            # js文件md5字典         {"chunk-0ef6b8a9":"15dfbb38"}
            # r'([a-zA-Z\_]+\.[a-zA-Z]{1})[\s]*\+[\s]*[\'"]{1}([a-zA-Z\/]+)[\'"]{1}[\s]*\+[\s]*((\(\{[a-zA-Z0-9\-:\'",~\_ ]*\}\[[a-zA-Z0-9]+\]\|\|[a-zA-Z0-9]+\)|[a-zA-Z]+)[\s]*\+[\s]*[\'"]{1}\.[\'"]{1}[\s]*\+[\s]*)*(\{[a-zA-Z0-9\-:\'",~\_ ]*\})\[[a-zA-Z]{1}\][\s]*\+[\s]*[\'"]{1}\.js[\'"]{1}'
            #r'([a-zA-Z\_]+\.[a-zA-Z]{1})[\s]*\+[\s]*[\'"]{1}([a-zA-Z0-9\/]+)[\'"]{1}[\s]*\+[\s]*((\(\{[a-zA-Z0-9\-:\'",~\_ \/]*\}\[[a-zA-Z0-9]+\]\|\|[a-zA-Z0-9]+\)|[a-zA-Z]+)[\s]*\+[\s]*[\'"]{1}\.[\'"]{1}[\s]*\+[\s]*)*(\{[a-zA-Z0-9\-:\'",~\_ \/]*\})\[[a-zA-Z]{1}\][\s]*\+[\s]*[\'"]{1}\.js[\'"]{1}'
            # r'([a-zA-Z\_]+\.[a-zA-Z]{1})[\s]*\+[\s]*[\'"]{1}([a-zA-Z0-9\/]+)[\'"]{1}[\s]*\+[\s]*((\(\{[a-zA-Z0-9\-:\'",~\_ \/]*\}\[[a-zA-Z0-9]+\]\|\|[a-zA-Z0-9]+\)|[a-zA-Z]+)[\s]*\+[\s]*[\'"]{1}\.[\'"]{1}[\s]*\+[\s]*)*\([\S]*\)\+[\'"]{1}\.[\'"]{1}\+(\{[a-zA-Z0-9\-:\'",~\_ \/]*\})\[[a-zA-Z]{1}\][\s]*\+[\s]*[\'"]{1}\.js[\'"]{1}'
            r'([a-zA-Z\_]+\.[a-zA-Z]{1})[\s]*\+[\s]*[\'"]{1}([a-zA-Z0-9\/]+)[\'"]{1}[\s]*\+[\s]*((\(\{[a-zA-Z0-9\-:\'",~\_ \/]*\}\[[a-zA-Z0-9]+\]\|\|[a-zA-Z0-9]+\)|[a-zA-Z]+)[\s]*\+[\s]*[\'"]{1}\.[\'"]{1}[\s]*\+[\s]*)*(\([\S]*\)\+[\'"]{1}\.[\'"]{1}\+)*(\{[a-zA-Z0-9\-:\'",~\_ \/]*\})\[[a-zA-Z]{1}\][\s]*\+[\s]*[\'"]{1}\.js[\'"]{1}',
            # 查找形如如下模式的代码：
            # {'chunk-00471e9b':_0x1eb29b('0x862'),'chunk-0088177c':_0x1eb29b('0x8e6'),
            # 获取一个东西：
            # js文件名和js文件md5解密函数的入参  例如：chunk-00471e9b 和 0x862
            r'\{([\s]*(\'chunk-[0-9a-zA-Z]+\')+:[\s]*[_0-9a-zA-Z\'\(\)]*,)+([\s]*(\'chunk-[0-9a-zA-Z]+\')+:[\s]*[_0-9a-zA-Z\'\(\)]*)[\s]*\}?'
        ]

    # 主函数
    # 找到所有的js
    def find_js(self):
        self.__get_script_tag()
        self.__handle_jsLoader()

    # 按照模式获取生成所有的js
    # reOjbect  正则结果
    # mode  模式
    # 模式2 直接从re结果里面拼接相对路径和js名字
    # 模式1 re结果里面只有js名字，需要传相对路径
    # relative_path
    def __get_js__(self, reOjbect, mode, relative_path="", host_sub=""):
        host = self.domain + host_sub
        # 还是host的问题
        host = self.host
        if mode == 2:
            relative_path = reOjbect.group(2)
            fileNames = reOjbect.group(6)

            # 粗暴地处理一下，因为原生字符串可能不是标准字典形式
            # 兼容一下，判断单双引号
            if '"' in fileNames:
                fileNames = fileNames.replace('{', '{"').replace('{""', '{"') \
                    .replace(',', ',"').replace(':', '":') \
                    .replace(',""', ',"').replace('"":', '":')
            else:
                fileNames = fileNames.replace('{', '{\'').replace('{\'\'', '{\'') \
                    .replace(',', ',\'').replace(':', '\':').replace(',\'\'', ',\'') \
                    .replace('\'\':', '\':')
            logger.debug("fileNames: " + fileNames)
            fileNames = json.loads(fileNames)

            for i, j, in fileNames.items():
                js_url = host + host_sub + relative_path + i + "." + j + ".js"
                logger.debug("open url: " + js_url)
                self.js_urls.append(js_url)
                self.__request_url__(js_url)
        # 模式1里面有重复得，得先去重
        if mode == 1:
            relative_path = relative_path
            temp_file_name = {}
            for i in reOjbect:
                file_name = i[1].replace('\\"', '').replace('\\\'', '')
                temp_file_name[file_name] = 1
            for i in temp_file_name:
                file_name = i
                js_url = host + relative_path + file_name + ".js"
                logger.debug("open url: " + js_url)
                self.js_urls.append(js_url)
                self.__request_url__(js_url)

    # 获取所有的script标签，并判断jsLoader模式
    def __get_script_tag(self):
        logger.info("begin parse html to get javascript tag")
        # 嗯 这里不能直接用host
        # 这里有些问题，建融慧学用domain会有问题，得用host
        # 我先调成host，看下能不能解决问题，后面再想如何兼容
        domain = self.domain
        host = self.host
        response = self.__request_url__(self.login_url)
        if response is not None:
            soup = BeautifulSoup(response, 'html.parser')
            script_tags = soup.find_all('script')
            # 遍历script标签
            for script_tag in script_tags:
                try:
                    src = script_tag['src']
                    # 注意：这里用host还是domain得想一下兼容方案
                    # 域名可能发生变化
                    if src.startswith("http"):
                        js_url = src
                    else:
                        js_url = self.__parse_url__(host + src)
                    logger.debug("find js: " + js_url)
                    self.js_urls.append(js_url)
                    # 判断是不是jsLoader
                    for i in self.jsLoader_namelist:
                        if i in js_url:
                            self.jsLoaders[i] = js_url
                except KeyError as e:
                    # script 标签没有src属性
                    # 要判断一下标签内容，可能有jsLoader代码
                    logger.info("this script tag does not have src")
                    jsContent = script_tag.get_text()
                    for RE in self.jsLoader_REs:
                        findObject = re.search(RE, jsContent, re.IGNORECASE)
                        if findObject is not None:
                            self.__get_js__(findObject, 2)

    # 处理jsLoader数组
    def __handle_jsLoader(self):
        logger.info("begin handle jsLoader dict")
        host = self.host
        relative_path = ""
        found_runtime_js = False

        # 如果有manifest，就直接在这个js里面找
        if self.jsLoaders.__contains__("manifest"):
            logger.debug("found manifest*.js")
            logger.info("find jsLoader mode 2, and begin to get relative path js Names")
            js_url = self.jsLoaders["manifest"]
            response = self.__request_url__(js_url)
            if response is not None:
                for RE in self.jsLoader_REs:
                    findObject = re.search(RE, response, re.IGNORECASE)
                    if findObject is not None:
                        host_sub = findObject.group(1)
                        # 处理host下面的子路径
                        pattern = host_sub + r'=[\'"]{1}([a-zA-Z0-9\/]*)[\'"]{1}'
                        resultObject = re.search(pattern, response)
                        if resultObject is not None:
                            host_sub = resultObject.group(1)
                        else:
                            host_sub = ""
                        self.__get_js__(findObject, 2, host_sub)

        # 去runtime*.js里面找相对路径
        else:
            if self.jsLoaders.__contains__("runtime"):
                logger.debug("found runtime*.js")
                logger.info("find jsLoader mode 1, and begin to get relative path")
                found_runtime_js = True
                js_url = self.jsLoaders["runtime"]
                response = self.__request_url__(js_url)
                if response is not None:
                    if response.find("__webpack_require__.e = function requireEnsure") > -1:
                        # 在runtime*.js里面找jsLoader的代码
                        # 但是我其实只是想要它的相对路径
                        RE = r'[a-zA-Z\_]+\.[a-zA-Z]{1}[\s]*\+[\s]*[\'"]{1}([a-zA-Z\/]*)[\'"]{1}[\s]*\+[\s]*\((\{[a-zA-Z0-9\-:\'",~\_]*\})\[[a-zA-Z0-9]+\]\|\|[a-zA-Z0-9]+\)[\s]*\+[\s]*[\'"]{1}\.js[\'"]{1}'
                        findObject = re.search(RE, response)
                        relative_path = findObject.group(1)
                        # js名字还是要在app*.js里面取找

            if self.jsLoaders.__contains__("app."):
                logger.debug("found app*.js")
                logger.info("begin handle app*.js to get jsNames")
                js_url = self.jsLoaders["app."]
                response = self.__request_url__(js_url)
                if response is not None:
                    # 如果没有runtime*.js，那么就去app*.js找相对路径和js名字
                    # 模式1
                    if response.find("__webpack_require__.e = function requireEnsure") > -1 or \
                            found_runtime_js:
                        if len(relative_path) == 0:
                            logger.info("find jsLoader mode 1, and begin to get relative path")
                            # 在app*.js里面找jsLoader的代码
                            # 但是我其实只是想要它的相对路径
                            RE = r'[a-zA-Z\_]+\.[a-zA-Z]{1}[\s]*\+[\s]*[\'"]{1}([a-zA-Z\/]*)[\'"]{1}[\s]*\+[\s]*\((\{[a-zA-Z0-9\-:\'",~\_]*\})\[[a-zA-Z0-9]+\]\|\|[a-zA-Z0-9]+\)[\s]*\+[\s]*[\'"]{1}\.js[\'"]{1}'
                            findObject = re.search(RE, response)
                            relative_path = findObject.group(1)

                        logger.info("find jsLoader mode 1, and begin to get js Names")
                        RE = r'__webpack_require__.e\((\/\*\! import\(\) \*\/ )*([\\\'"0-9a-zA-Z\~]+)\)'
                        chunkIDs = re.findall(RE, response)
                        if chunkIDs is not None:
                            self.__get_js__(chunkIDs, 1, relative_path)
                    # 模式2
                    else:
                        logger.info("find jsLoader mode 2, and begin to get relative path js Names")
                        for RE in self.jsLoader_REs:
                            findObject = re.search(RE, response, re.IGNORECASE)
                            if findObject is not None:
                                host_sub = findObject.group(1)
                                # 处理host下面的子路径
                                pattern = host_sub + r'=[\'"]{1}([a-zA-Z0-9\/]*)[\'"]{1}'
                                resultObject = re.search(pattern, response)
                                if resultObject is not None:
                                    host_sub = resultObject.group(1)
                                else:
                                    host_sub = ""
                                self.__get_js__(findObject, 2, host_sub=host_sub)
            if self.jsLoaders.__contains__("my"):
                logger.debug("found my*.js")
                logger.info("begin handle my*.js to get jsNames")
                js_url = self.jsLoaders["my"]
                response = self.__request_url__(js_url)
                if response is not None:
                    # 如果没有runtime*.js，那么就去app*.js找相对路径和js名字
                    # 模式1
                    logger.info("find jsLoader mode 2, and begin to get js Names")
                    for RE in self.jsLoader_REs:
                        findObject = re.search(RE, response, re.IGNORECASE)
                        if findObject is not None:
                            # print(findObject.group())
                            # md5需要解码。姑且认为这种情况只会出现在my*.js里面
                            temp = findObject.group().replace('\'', '"').replace(':', ':"').replace('("', '(\\"').replace('")', '\\")"')
                            jsonObject = json.loads(temp)
                            # print(jsonObject)
                            # md5解码
                            # 临时 后面再改
                            for key, value in jsonObject.items():
                                md5 = self.js.decode(int(value.split('"')[1], 16))
                                print(md5)
                                # jsonObject[key] = md5
                                # js_url = 'https://test.com/static/js/' + key + '.' + md5 + '.js'
                                js_url = js_url + key + '.' + value + '.js'
                                logger.debug("open url: " + js_url)
                                self.js_urls.append(js_url)
                                self.__request_url__(js_url)

def test():
    test_host = 'https://test.com/'

    logger.debug(test_host)
    jsFinder = JSFinder(test_host)
    jsFinder.find_js()


if __name__ == '__main__':
    args = parse_args()
    if args.log_level is not None:
        log_level = args.log_level
        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level:{0}'.format(log_level))
        logger.setLevel(level=numeric_level)
    if args.url is not None:
        url = args.url
        logger.info("begin find js in url: " + url)
        jsFinder = JSFinder(url)
        jsFinder.find_js()
        logger.info("finished")
    else:
        args.proxy = "127.0.0.1:8080"
        test()
