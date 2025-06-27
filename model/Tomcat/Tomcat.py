# -*- coding: utf-8 -*-
# @Time    : 13 1月 2025 11:57 下午
# @Author  : codervibe
# @File    : Tomcat.py
# @Project : TomcatScan
import socket
from model.Tomcat.constants import prepare_ajp_forward_request
from model.AjpForwardRequest import AjpForwardRequest
from model.AjpForwardRequest import REQUEST_METHODS, AjpForwardRequest


class Tomcat:
    """
    Tomcat类用于建立与Tomcat服务器的连接，并执行HTTP请求。

    属性:
    - target_host: 目标主机地址。
    - target_port: 目标主机端口。
    - socket: 用于与Tomcat服务器通信的socket对象。
    - stream: 用于读取响应数据的文件对象。
    """

    def __init__(self, target_host, target_port):
        """
        初始化Tomcat类，建立与目标Tomcat服务器的连接。

        参数:
        - target_host: 目标主机地址。
        - target_port: 目标主机端口。
        """
        self.target_host = target_host
        self.target_port = target_port

        # 创建并配置socket对象
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((target_host, target_port))
        self.stream = self.socket.makefile("rb")

    def perform_request(self, req_uri, headers={}, method='GET', user=None, password=None, attributes=[]):
        """
        执行HTTP请求，并返回响应结果。

        参数:
        - req_uri: 请求的URI。
        - headers: 请求头字典。
        - method: HTTP方法，默认为GET。
        - user: 用户名，用于HTTP认证。
        - password: 密码，用于HTTP认证。
        - attributes: 附加属性列表。

        返回:
        - snd_hdrs_res: 响应头对象。
        - data_res: 响应数据对象列表。
        """
        self.req_uri = req_uri
        # # 准备AJP请求
                # ...此处为省略代码...
        # # 准备AJP请求
        # self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri,
        #                                                    method=AjpForwardRequest.REQUEST_METHODS.get(method))

        # 准备转发请求
        self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri,
                                                           method=REQUEST_METHODS.get(method))

        # 设置认证信息
        if user is not None and password is not None:

            self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + (
                    "%s:%s" % (user, password)).encode('base64').replace('\n', '')
        # 设置请求头
        for h in headers:
            self.forward_request.request_headers[h] = headers[h]
        # 添加附加属性
        for a in attributes:
            self.forward_request.attributes.append(a)
        # 发送请求并接收响应
        responses = self.forward_request.send_and_receive(self.socket, self.stream)
        if len(responses) == 0:
            return None, None
        snd_hdrs_res = responses[0]
        data_res = responses[1:-1]
        if len(data_res) == 0:
            print("No data in response. Headers:%s\n" % snd_hdrs_res.response_headers)
        return snd_hdrs_res, data_res
