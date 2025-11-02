# TomcatScan 代码使用说明文档

## 目录

1. [项目简介](#项目简介)
2. [环境配置](#环境配置)
3. [代码结构](#代码结构)
4. [主要功能](#主要功能)
5. [使用方法](#使用方法)
6. [配置文件](#配置文件)
7. [常见问题](#常见问题)
8. [支持漏洞](#支持漏洞)
9. [免杀](#免杀)
10. [其他功能and作者语](#其他功能and作者语)

---

## 项目简介

`TomcatScan` 是一个用于检测 Tomcat 服务器漏洞的工具，支持以下主要功能：

- 检测 CVE-2017-12615 和 CNVD-2020-10487 漏洞。
- 进行弱口令检测。

## 环境配置

确保你的环境中已安装 Python 3.6 及以上版本，并安装所需的依赖库。可以通过以下命令安装所有依赖：

~~~bash
 pip install -r requirements.txt
~~~

依赖库包括 `requests`, `yaml`, `bs4` 等。
## 代码结构

项目目录结构如下：

~~~
E:\python\Python_project\TomcatScan\
├── common\
│   └── common.py
├── config.yaml
├── README.md
├── model\
├── Tomcat\
│   ├── constants.py
│   └── Tomcat.py
├── pocs\
│   └── CVE_2024_50379.py
├── AjpBodyRequest.py
├── AjpForwardRequest.py
├── AjpResponse.py
└── NotFoundException.py
└── TomcatScan.py
~~~

每个文件的主要功能如下：

- **common/common.py**: 提供通用工具函数。
- **config.yaml**: 配置文件，包含线程池、重试机制、 CVE-2020-1938（CNVD-2020-10487）  漏洞检测等配置信息。
- **README.md**: 项目的使用说明文档。
- **model/Tomcat/constants.py**: 定义常量，用于AJP请求的准备。
- **model/Tomcat/Tomcat.py**: 实现与 Tomcat 服务器的连接和请求处理。
- **model/AjpBodyRequest.py**: 处理 AJP Body 请求的序列化和发送。
- **model/AjpForwardRequest.py**: 处理 AJP Forward 请求的创建、序列化和解析。
- **model/AjpResponse.py**: 解析 AJP 响应数据。
- **model/NotFoundException.py**: 自定义异常类。
- **poc/CVE_2024_50379.py**: CVE_2024_50379 POC EXP 脚本
- **TomcatScan.py**: 主程序逻辑，负责加载配置、初始化资源并启动漏洞检测流程。


## 主要功能



### 1. **CVE-2017-12615 漏洞检测**

- 工具支持三种利用方式：

  `PUT /1.jsp/`

  `PUT /1.jsp%20`

  `PUT /1.jsp::$DATA`

- 成功上传后，工具会尝试访问并执行上传的 JSP 文件，判断是否能远程执行代码。
- 对每种利用方式的结果分别记录成功或失败状态。

### ** 2. CVE-2020-1938/CNVD-2020-10487 (AJP 协议本地文件包含漏洞)**

- 工具利用 AJP 协议进行本地文件包含（LFI）攻击，默认读取 WEB-INF/web.xml 文件，但文件路径和判断条件可以通过配置文件灵活调整。
- 支持对目标文件中的关键字（例如 "Welcome"）进行自定义判断，确定文件读取成功与否。
- 检测到文件包含成功后，详细记录成功的 URL 和读取到的敏感文件路径。

### 2. **弱口令检测**

- 支持通过用户名与密码组合进行弱口令暴力破解。
- 若登录成功，工具会自动尝试上传 WebShell 文件，提供远程管理和代码执行能力。
- 登录成功以及 WebShell 上传的结果都会详细记录在日志文件中。

### 3. **后台部署 WAR 包 `getshell`**

- 在弱口令破解成功后，工具会尝试通过 Tomcat 管理后台上传 `WAR` 包，以获取远程代码执行权限。
- 部署的 `WAR` 包会自动在服务器上解压并生成 JSP Shell 文件，访问该文件后便可以获取 Shell 权限。
- 支持通过配置文件自定义` Shell  `文件的内容。

###  ** 4.Apache-Tomcat条件竞争致远程代码执行漏洞(CVE-2024-50379) **
- 由于 Apache Tomcat 在路径校验逻辑中存在缺陷，当在不区分大小写的系统（如 Windows）上启用了 default servlet 的写入功能（默认关闭）时，攻击者可构造恶意请求绕过路径一致性检查，从而可能上传 webshell 并造成远程代码执行。漏洞利用需要条件竞争，对网络以及机器性能环境等有一定要求。
- 利用条件竞争致远程代码执行漏洞(CVE-2024-50379)
- 利用成功后 windows 电脑 会打开 计算器 或者访问地址 也会打开 计算器
- 代码中注释的部分 是 打开计算器，现在 则是可以直接将木马种进去 和 CNVD-2020-10487 (AJP 协议本地文件包含漏洞) 一样 是 哥斯拉的 jsp 木马文件
  - 影响版本:
  - Apache Tomcat 11.0.0-M1到11.0.1
  - Apache Tomcat 10.1.1.0 - m1到10.1.33
  - Apache Tomcat 9.0.0。M1到9.0.97
  
## 使用方法

1. 准备包含URL、用户名和密码的文本文件，分别命名为`urls.txt`、`user.txt`和`passwd.txt`。
2. `urls.txt`保存格式：https://127.0.0.1/  或者 https://127.0.0.1/manager/html 脚本会自行判断检测
3. 在`config.yaml`中配置文件路径和其他设置。
4. 运行脚本，将会在`success.txt`文件中记录成功利用漏洞信息。

```bash
  python TomcatScan.py
```

## 配置文件

配置文件 `config.yaml` 包含了项目的各项配置参数，用户可以根据需要进行修改。主要配置项包括：

- `files`: 文件路径配置
- `thread_pool`: 线程池配置
- `retry`: 重试机制配置
- `cnvd_2020_10487`: CNVD-2020-10487 漏洞检测配置

## 常见问题

### Q: 如何解决 SSL 证书验证失败的问题？

A: 在 `TomcatScan.py` 中，部分 HTTP 请求设置了 `verify=False` 来忽略 SSL 证书验证。如果需要启用 SSL 验证，请移除该参数或设置为 `True`。

### Q: 如何提高检测效率？

A: 可以通过调整 `config.yaml` 中的 `thread_pool` 和 `retry` 配置来优化线程池大小和重试策略，从而提高检测效率。

### Q: 如何调试日志？

A: 日志级别默认为 `INFO`，可以在 `TomcatScan.py` 中调整 `logging.basicConfig` 的 `level` 参数来控制日志级别。例如：
~~~python
logging.basicConfig(level=logging.DEBUG, format='%(messages')
~~~

## 支持漏洞:
1. CNVD-2020-10487(AJP协议本地文件包含)漏洞检测，支持灵活配置目标文件路径与判断条件。
2. CVE-2017-12615文件上传漏洞的不同利用方式的检测
3. 弱口令爆破成功后自动配置war进行getshell

---
# 免杀
* 在配置文件中使用的免杀jsp代码使用了混淆代码,加密与解密,动态加载,环境检测,四种方法来进行免杀

# 其他功能and作者语:
1. 引入配置文件，使得调整参数更加灵活
2. 增加处理登录时无法访问URL的情况，并在重试次数达到顶点时(默认3次)将URL从待检测列表中排除
3. 在上传成功或失败后删除WAR文件与JSP文件，磁盘空间浪费
4. 增加上传失败时重试机制(默认3次)，避免网络问题或服务器偶尔响应慢可能会导致上传失败问题
5. 使用随机生成的文件名增加脚本的灵活和隐蔽性
6. 自定义webshell默认Godzilla马，连接密码pass 加密密钥 xc
7. 动态调整线程池大小:根据用户名和密码的组合队列计算调整线程池大小
8. 使用的 tomcat版本为apache-tomcat-8.5.31 哥斯拉是最新版 [godzilla：https://github.com/BeichenDream/Godzilla/releases/tag/v4.0.1-godzilla](https://github.com/BeichenDream/Godzilla/releases/tag/v4.0.1-godzilla)
9. 项目中的字典过于简单 各位可以自行配置
10. CNVD-2020-10487 和CVE-2020-1938 是同一个安全漏洞的不同命名