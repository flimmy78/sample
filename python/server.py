#!/usr/bin/python
#coding:utf-8

# conf_svr.py
# 配置项服务
# python conf_svr.py -b 192.168.56.1:7826 --reload --with-thread



import sys
import os


import time
import random
import datetime
import base64
import json
import re
import fnmatch
from collections import defaultdict

import netaddr
import requests
import traceback
import ConfigParser

import flask
from flask import Flask, request, session, g, redirect, url_for, abort, \
    render_template, flash, jsonify, current_app
from flask import has_app_context, has_request_context
from flask import send_from_directory, send_file, make_response
from flask import Response
from flask_httpauth import HTTPBasicAuth, HTTPDigestAuth


from werkzeug.serving import run_simple


#创建一个Flask类的实例
app = Flask(__name__)
#auth = HTTPBasicAuth()
auth = HTTPDigestAuth()

# 登录账号认证配置
users = {
    # "qzgw": "conf1711",
}

@auth.get_password
def get_pw(username):
    if username in users:
        return users.get(username)
    return None


# kong conf
CFG_GW_CONF_FILE = "/etc/kong/kong.conf"
# 账号登录登出解析规则
ACC_RULE_CONF = "/opt/apigw/protocol_parser/rule.config"
# 账号登录登出环境配置
PP_CFG_CONF = "/opt/apigw/protocol_parser/config.txt"
# 参数最大字节数
PARAM_MAX_SIZE = 100 * 1024L
# 超时时间 默认 3s
CFG_TIMEOUT = 3
# 连接超时时间 默认 1s
CFG_CONNECT_TIMEOUT = 1*1000

# 从请求对像获取参数
def get_req_param(request, field):
    if request.method == 'POST':
        data = request.form.get(field)
    else:
        data = request.args.get(field)
    return data


def get_ip_addr(s):
    try:
        return str(netaddr.IPAddress(s))
    except:
        pass
    return None

def get_cidr(s):
    try:
        return str(netaddr.IPNetwork(s))
    except netaddr.AddrFormatError:
        pass
    return None

def get_ip_port(s):
    try:
        L = s.split(':')
        if len(L)!=2:
            return str(netaddr.IPAddress(s))
        ip = str(netaddr.IPAddress(L[0]))
        port = int(L[1])
        if '{}'.format(port)==L[1] and port > 0 and port < 65536:
            return (ip, port)
    except:
        pass
    return None

# domain 判断正则表达式
regex_domain = re.compile(
    r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)' #domain...
    , re.IGNORECASE)

def get_domain_port(s):
    try:
        L = s.split(':')
        if len(L)!=2:
            if regex_domain.match(s):
                return s
        else:
            if regex_domain.match(L[0]):
                domain = L[0]
                port = int(L[1])
                if '{}'.format(port)==L[1] and port > 0 and port < 65536:
                    return (domain, port)
    except:
        pass
    return None

# 配置负载均衡的地址
# 修改 /etc/kong/kong.conf 文件 配置负载均衡中的IP地址 trusted_ips=
@app.route('/lbips', methods=['POST', 'GET'])
@auth.login_required
def api_set_lbips():
    ips = get_req_param(request, 'ips')
    if not ips or len(ips) == 0:
        return jsonify(msg="not param", err=1, data=None)

    L = []
    for v in ips.split(','):
        s = get_ip_addr(v)
        if s is not None:
            L.append(s)
            continue
        s = get_cidr(v)
        if s is not None:
            L.append(s)
            continue
        # try:
        #     L.append( str(netaddr.IPAddress(v)) )
        # except:
        #     try:
        #         L.append( str(netaddr.IPNetwork(v)) )
        #     except netaddr.AddrFormatError:
        #         pass
    s = ','.join(L)
    ss = "trusted_ips = {}".format(s)
    with open(CFG_GW_CONF_FILE, 'rU') as f:
        da = f.read()
    L = []
    flg = False
    for v in da.split('\n'):
        if v.strip().find('trusted_ips') == 0:
            t = v.strip().split('=')
            if len(t)>1 and t[0].strip()=='trusted_ips':
                if not flg:
                    flg = True
                    L.append(ss)
                continue
        L.append(v)
    if not flg:
        L.append(ss)
    d = '\n'.join(L)
    try:
        with open(CFG_GW_CONF_FILE, 'w') as f:
            f.write(d)
    except:
        return jsonify(msg="conf file write error", err=-3, data=None)

    return jsonify(msg="ok", err=0, data=None)


# 获取负载均衡的地址
# 读取 /etc/kong/kong.conf 文件 配置负载均衡中的IP地址 trusted_ips=
@app.route('/list/lbips', methods=['GET'])
@auth.login_required
def api_get_lbips():
    s = None
    with open(CFG_GW_CONF_FILE, 'rU') as f:
        da = f.read()
    L = []
    flg = False
    for v in da.split('\n'):
        if v.strip().find('trusted_ips') == 0:
            t = v.strip().split('=')
            if len(t)>1 and t[0].strip()=='trusted_ips':
                if not flg:
                    flg = True
                    print v[v.find('=')+1:]
                    s = v[v.find('=')+1:].strip()
                    print s
                continue
        L.append(v)


    return jsonify(msg="ok", err=0, data=s)





# 解析API管理接口的响应数据，
# 参数： requests请求的返回值，
# 返回值：Json格式对象，有异常情况返回None
def get_api_rsp_data(rsp):
    #print dir(rsp)
    #print rsp.ok
    #print rsp.status_code
    #print rsp.reason
    #print rsp.content
    if not rsp.ok:
        #print >>sys.stderr, rsp.status_code, rsp.reason
        return
    try:
        js = json.loads(rsp.content)
    except ValueError:
        print >>sys.stderr, rsp.content
        return None
    else:
        return js
    pass


# 获取API对应的插件ID
def get_api_plugin_id(host, api_name, plugin_name, timeout):
    url = '{}/apis/{}/plugins'.format(host, api_name)
    js = get_api_rsp_data(requests.get(url, timeout=timeout))
    # pp.pprint(js)
    p_id = None
    for k in range(js['total']):
        if js['data'][k]['name'] == plugin_name:
            p_id = js['data'][k]['id']
            break
    if not p_id:
        return

    return p_id


# url 判断正则表达式
regex_url = re.compile(
    r'^(?:http|ftp)s?://' # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
    # r'localhost|' #localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)


# 更新到api服务中的插件配置参数
def update_apis_plugin_data(app, cfg):
    L = []
    url = app.config['CONF_URL']
    conf_plugin_name = app.config['CONF_PLUGIN_NAME']
    apis = get_api_rsp_data(requests.get(url + '/apis', timeout=CFG_TIMEOUT))
    for k in range(apis['total']):

        v = apis['data'][k]
        api_name = v["name"]
        p_id = get_api_plugin_id(url, api_name, conf_plugin_name, timeout=CFG_TIMEOUT)
        if not p_id:
            # add plugin
            url_p = '{}/apis/{}/plugins'.format(url, api_name)
            data = {
                "name": conf_plugin_name,
            }
            data.update(cfg)
            if not get_api_rsp_data(requests.post(url_p, data, timeout=CFG_TIMEOUT)):
                L.append(api_name)
            continue
        url_p = '{}/apis/{}/plugins/{}'.format(url, api_name, p_id)
        data = cfg
        if not get_api_rsp_data(requests.patch(url_p, data, timeout=CFG_TIMEOUT)):
            L.append(api_name)
    return L


# 从api服务中获取插件的数据
def get_apis_plugin_data(app, key):
    url = app.config['CONF_URL']
    conf_plugin_name = app.config['CONF_PLUGIN_NAME']
    apis = get_api_rsp_data(requests.get(url + '/apis', timeout=CFG_TIMEOUT))
    plugins = get_api_rsp_data(requests.get(url + '/plugins', timeout=CFG_TIMEOUT))
    di_mirror = {}
    L = []
    for kk in range(plugins['total']):
        vv = plugins['data'][kk]
        if vv['name'] == conf_plugin_name:
            di_mirror.update({vv['api_id']: vv['config'].get(key)})
    for k in range(apis['total']):
        v = apis['data'][k]
        # v["name"], v["hosts"]
        if v["id"] in di_mirror and di_mirror[ v["id"] ]:
            L.append(di_mirror[v["id"]])
    return L


# 设置服务器地址
@app.route('/evtsvr', methods=['POST', 'GET'])
@auth.login_required
def gw_set_evtsvr():
    addr = get_req_param(request, 'addr')
    if not addr or len(addr) == 0 or len(addr) > PARAM_MAX_SIZE:
        return jsonify(msg="not param", err=1, data=None)

    # 检测是否为一个URL
    if not regex_url.match(addr):
        return jsonify(msg="not url", err=-100, data=None)

    # 更新到api中
    L = []
    try:
        data = {
            "config.http_endpoint": addr,
        }
        L = update_apis_plugin_data(app, data)
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)
    if L:
        return jsonify(msg="config error apis", err=2, data=L)
    return jsonify(msg="ok", err=0, data=None)


# 获取事件服务器地址
@app.route('/list/evtsvr', methods=['GET'])
@auth.login_required
def gw_get_evtsvr():
    d = None
    try:
        L = get_apis_plugin_data(app, 'http_endpoint')
        d = list(set(L))
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)
    return jsonify(msg="ok", err=0, data=d)




# domain 判断正则表达式
# 支持泛域名，有待严格检查
regex_wildcarddomain = re.compile(
    r'^(((?:(?:[A-Z0-9*](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)[*]?)|' # domain
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))' # ip
    r'(:\d+)?)$' # port
    , re.IGNORECASE)


# 从url中提取出host
def get_host_from_url(url):
    idx1 = url.find("://")
    assert idx1 > 0
    idx2 = url.find("/", idx1 + 3) # len("://")
    host = url[idx1 + 3: idx2 if idx2 > 0 else None] # len("://")
    return host


# 配置域名及IP
@app.route('/domain', methods=['POST', 'GET'])
@auth.login_required
def gw_set_domain():
    data = get_req_param(request, 'data')
    if not data or len(data) == 0 or len(data) > PARAM_MAX_SIZE:
        return jsonify(msg="not param", err=1, data=None)

    d = None
    url = app.config['CONF_URL']
    conf_plugin_name = app.config['CONF_PLUGIN_NAME']
    # data json strings
    # [{'host': '*.uvw.xyz',
    #   'ip': ['192.168.56.1', '192.168.56.1:5001'],
    #   'up_url': 'http://abc.de/'}]
    try:
        js = json.loads(data)
        apis = get_api_rsp_data(requests.get(url + '/apis', timeout=CFG_TIMEOUT))
        errs = [] 
        for dd in js:
            host = dd['host']
            upstream_url = dd.get('up_url')
            ips = dd.get('ip', [])
            preserve_host = dd.get('preserve_host', "true")
            preserve_host = "true" if preserve_host == "true" else "false"
            # 是否为域名， 支持泛域名
            if not (len(host) < 128 and regex_wildcarddomain.match(host)):
                err = {}
                err['host'] = host
                err['err_msg'] = 'host not valide'
                errs.append(err)
                continue
            L = []
            for v in ips:
                ip_port = get_ip_port(v)
                if ip_port is None:
                    continue
                if not (type(ip_port) is type((None,))):
                    L.append((ip_port,80))
                    continue
                L.append(ip_port)

            # upstream_url is None
            if not upstream_url: # 为null 或 为空字符串 或 为false
                # 删除 host 所在的api
                for k in range(apis['total']):
                    v = apis['data'][k]
                    api_name = v["name"]
                    hosts = v["hosts"]
                    if host in hosts:
                        requests.delete(url + '/apis/{}'.format(api_name), timeout=CFG_TIMEOUT)
                        break
                continue

            # 是否为URL
            if not (len(upstream_url) < 256 and regex_url.match(upstream_url)):
                continue


            # upstreams name
            domain_port = get_domain_port(get_host_from_url(upstream_url))
            upstream_name = domain_port[0] if (type(domain_port) is type((None,))) else domain_port
            if upstream_name:
                # 仅当host为域名时，再进行配置
                # delete upstreams
                requests.delete(url + '/upstreams/{}'.format(upstream_name), timeout=CFG_TIMEOUT)
                if ips:
                    # has ip list
                    # add upstreams
                    data = {
                        "name": upstream_name,
                        "slots": 10,
                    }
                    requests.post(url + '/upstreams/', data, timeout=CFG_TIMEOUT)
                    # delete target
                    targets = get_api_rsp_data(requests.get(url + "/upstreams/{}/targets".format(upstream_name), timeout=CFG_TIMEOUT))
                    if targets:
                        for v in targets["data"]:
                            requests.delete(url + '/upstreams/{}/targets/{}'.format(upstream_name, v['target']), timeout=CFG_TIMEOUT)
                    # add target
                    for v in L:
                        data = {
                            "target": "{}:{}".format(*v),
                        }
                        rsp = requests.post(url + '/upstreams/{}/targets'.format(upstream_name), data, timeout=CFG_TIMEOUT)

            # apis
            flg = False
            for k in range(apis['total']):
                v = apis['data'][k]
                api_name = v["name"]
                hosts = v["hosts"]
                if host in hosts:
                    # modify api
                    # 更新 upstream_url
                    data = {
                        "preserve_host": preserve_host,
                        "upstream_connect_timeout": CFG_CONNECT_TIMEOUT, # 设置连接超时时间 1s
                        "upstream_url": "{}".format(upstream_url),
                    }
                    rsp = requests.patch(url + '/apis/{}'.format(api_name), data, timeout=CFG_TIMEOUT)
                    if rsp.status_code != 200:
                      err = {}
                      err['host'] = host
                      err['err_msg'] = rsp.content 
                      errs.append(err)
                    flg = True
                    break

            if not flg:
                # add api
                api_name = "{}_{}_a".format(host, base64.b64encode(host)).replace('*','~').replace('+', '-').replace('/', '_').replace('=', '').replace(':', '.')
                data = {
                    # "preserve_host": "true",
                    "preserve_host": preserve_host,
                    "hosts": host,
                    "name": api_name,
                    "upstream_connect_timeout": CFG_CONNECT_TIMEOUT, # 设置连接超时时间 1s
                    "upstream_url": "{}".format(upstream_url),
                }
                rsp = requests.post(url + '/apis/', data, timeout=CFG_TIMEOUT)
                if rsp.status_code != 201:
                  err = {}
                  err['host'] = host
                  err['err_msg'] = rsp.content 
                  errs.append(err)
        if len(errs) > 0 and len(errs) < len(js): 
          return jsonify(msg="partial fail", err=-2, data=errs)
        elif len(errs) == len(js):
          return jsonify(msg="all fail", err=-1, data=errs)


    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)
    return jsonify(msg="ok", err=0, data=d)


# 获取域名及IP
@app.route('/list/domain', methods=['GET'])
@auth.login_required
def gw_get_domain():
    url = app.config['CONF_URL']
    d = None
    # [{'host': '*.uvw.xyz',
    #   'ip': ['192.168.56.1', '192.168.56.1:5001'],
    #   'up_url': 'http://abc.de/'}]
    try:
        apis = get_api_rsp_data(requests.get(url + '/apis', timeout=CFG_TIMEOUT))
        L = []
        for k in range(apis['total']):
            v = apis['data'][k]
            #api_name = v["name"]
            hosts = v["hosts"]
            preserve_host = v["preserve_host"]
            upstream_url = v["upstream_url"]
            # upstreams name
            idx1 = upstream_url.find("//")
            assert idx1 > 2
            idx2 = upstream_url.find("/", idx1+2)
            upstream_name = upstream_url[idx1 + 2: idx2 if idx2 > 0 else None]
            ip = []
            targets = get_api_rsp_data(requests.get(url + '/upstreams/{}/targets/'.format(upstream_name), timeout=CFG_TIMEOUT))
            if targets:
                for kk in range(targets['total']):
                    vv = targets['data'][kk]
                    ip.append( vv['target'] )

            for host in hosts:
                di = dict(up_url=upstream_url, host=host, preserve_host=preserve_host)
                if ip:
                    di.update({"ip":ip})
                L.append( di )
        d = L
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)

    return jsonify(msg="ok", err=0, data=d)



# 配置流量转发域名
@app.route('/forward', methods=['POST', 'GET'])
@auth.login_required
def gw_set_forward():
    rule = get_req_param(request, 'rule')
    if not rule or len(rule) == 0 or len(rule) > PARAM_MAX_SIZE:
        return jsonify(msg="not param", err=1, data=None)

    # ["http://abc.com/123", "http://192.168.56.101/"]
    L = []
    try:
        rule_js = json.loads(rule)
        # if not rule_js:
        #     data = {
        #         "config.forward": "",
        #     }
        #     L = update_apis_plugin_data(app, data)
        #     break

        url = app.config['CONF_URL']
        conf_plugin_name = app.config['CONF_PLUGIN_NAME']
        L = []
        # 根据解析转发URL，做一个host-url的映射关系，在对每一个api接口，做相关的配置
        rule_for_host = defaultdict(list)
        if rule_js:
            for vr in rule_js:
                if regex_url.match(vr):
                    #h = get_host_from_url(vr)
                    host = get_host_from_url(vr)
                    domain_port = get_domain_port(host)
                    ip_port = get_ip_port(host)
                    h1 = domain_port[0] if (type(domain_port) is type((None,))) else domain_port
                    h2 = ip_port[0] if (type(ip_port) is type((None,))) else ip_port
                    h = h2 or h1
                    #print >> sys.stderr, h, domain_port, ip_port, vr
                    if h:
                        rule_for_host[h].append( vr )

        apis = get_api_rsp_data(requests.get(url + '/apis', timeout=CFG_TIMEOUT))
        for k in range(apis['total']):
            v = apis['data'][k]
            api_name = v["name"]
            p_id = get_api_plugin_id(url, api_name, conf_plugin_name, timeout=CFG_TIMEOUT)
            if not p_id:
                continue
            url_p = '{}/apis/{}/plugins/{}'.format(url, api_name, p_id)

            hosts = v["hosts"]
            # 配置 host匹配中 的转发url
            print >>sys.stderr, rule_for_host, hosts
            LL = [ ul for host in hosts for h, ul in rule_for_host.items() if fnmatch.fnmatch(h, host) ]
            all_url_list = [ u for ul in LL for u in ul ]
            # 当前host没有配置过规则且参数中有规则，则清空现有的规则
            # 修改 URL转发规则不当的配置
            #rule_host = json.dumps(all_url_list) if all_url_list else ""
            rule_host = json.dumps(all_url_list) if all_url_list and rule_js else ""
            data = {
                # "config.forward": rule.lower(), # 全部转为小写字符
                "config.forward": rule_host.lower(), # 只配置HOST相对应的转发URL， 全部转为小写字符
            }
            if not get_api_rsp_data(requests.patch(url_p, data, timeout=CFG_TIMEOUT)):
                L.append(api_name)
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)

    if L:
        return jsonify(msg="config error apis", err=2, data=L)

    return jsonify(msg="ok", err=0, data=None)


# 获取流量转发域名
@app.route('/list/forward', methods=['GET'])
@auth.login_required
def gw_get_forward():
    d = None
    try:
        L = get_apis_plugin_data(app, 'forward')
        d = list(set(L))
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)

    return jsonify(msg="ok", err=0, data=d)


# 配置账号访问接口解析规则
@app.route('/if_conf', methods=['POST', 'GET'])
@auth.login_required
def gw_set_if_conf():
    rule = get_req_param(request, 'rule')
    if not rule or len(rule) == 0 or len(rule) > PARAM_MAX_SIZE:
        return jsonify(msg="not param", err=1, data=None)

    # TODO 格式合法性检查
    # TODO 内容合法性检查
    try:
        js = json.loads(rule)
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="rule verify error", err=2, data=None)


    L = []
    try:
        data = {
            "config.rule": rule,
        }
        L = update_apis_plugin_data(app, data)
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)

    if L:
        return jsonify(msg="config error apis", err=2, data=L)

    return jsonify(msg="ok", err=0, data=None)



# 获取账号访问接口解析规则
@app.route('/list/if_conf', methods=['GET'])
@auth.login_required
def gw_get_if_conf():
    d = None
    try:
        L = get_apis_plugin_data(app, 'rule')
        d = list(set(L))
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)

    return jsonify(msg="ok", err=0, data=d)



# 配置账号登录登出解析规则
@app.route('/acc_conf', methods=['POST', 'GET'])
@auth.login_required
def dp_set_acc_conf():
    rule = get_req_param(request, 'rule')
    if not rule or len(rule) == 0 or len(rule) > PARAM_MAX_SIZE:
        return jsonify(msg="not param", err=1, data=None)

    if not os.path.exists(ACC_RULE_CONF):
        return jsonify(msg="no conf file", err=-2, data=None)

    # TODO 格式合法性检查
    # TODO 内容合法性检查
    try:
        js = json.loads(rule)
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="rule verify error", err=2, data=None)


    try:
        with open(ACC_RULE_CONF, 'w') as f:
            f.write(rule)
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="conf file write error", err=-3, data=None)

    return jsonify(msg="ok", err=0, data=None)


# 获取账号登录登出解析规则
@app.route('/list/acc_conf', methods=['GET'])
@auth.login_required
def dp_get_acc_conf():
    if not os.path.exists(ACC_RULE_CONF):
        return jsonify(msg="no conf file", err=-2, data=None)

    d = None
    try:
        with open(ACC_RULE_CONF, 'rU') as f:
            d = f.read()
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)

    return jsonify(msg="ok", err=0, data=d)


# 设置kafka服务配置
@app.route('/kafka_cfg', methods=['POST', 'GET'])
@auth.login_required
def gw_set_kafka_cfg():
    data = get_req_param(request, 'data')
    if not data or len(data) == 0 or len(data) > PARAM_MAX_SIZE:
        return jsonify(msg="not param", err=1, data=None)

    # TODO 格式合法性检查
    # TODO 内容合法性检查
    try:
        js = json.loads(data)
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="data verify error", err=2, data=None)
    kafka_data = data

    # 更新到api中
    L = []
    try:
        data = {
            "config.kafka": kafka_data,
        }
        L = update_apis_plugin_data(app, data)
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)
    if L:
        return jsonify(msg="config error apis", err=2, data=L)
    return jsonify(msg="ok", err=0, data=None)


# 设置kafka服务配置
@app.route('/list/kafka_cfg', methods=['POST', 'GET'])
@auth.login_required
def gw_get_kafka_cfg():
    d = None
    try:
        L = get_apis_plugin_data(app, 'kafka')
        d = list(set(L))
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)
    return jsonify(msg="ok", err=0, data=d)



# 写入配置项到config文件
def write_config(config, section, key, value):
    try:
        if not config.has_section(section):
            config.add_section(section)
        config.set(section, key, value)
        return True
    except:
        return False

# 配置账号登录登出模块环境配置
@app.route('/pp_cfg', methods=['POST', 'GET'])
@auth.login_required
def dp_set_pp_cfg():
    data = get_req_param(request, 'data')
    if not data or len(data) == 0 or len(data) > PARAM_MAX_SIZE:
        return jsonify(msg="not param", err=1, data=None)

    if not os.path.exists(PP_CFG_CONF):
        return jsonify(msg="no conf file", err=-2, data=None)

    # TODO 格式合法性检查
    # TODO 内容合法性检查
    try:
        js = json.loads(data)
    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="rule verify error", err=2, data=None)


    try:
        config = ConfigParser.ConfigParser()
        config.read(PP_CFG_CONF)

        if "mongodb_host" in js:
            mongodb_host = js["mongodb_host"]
            write_config(config, "Main", "MONGODB_HOST", mongodb_host)
        if "mongodb_port" in js:
            mongodb_port = js["mongodb_port"]
            write_config(config, "Main", "MONGODB_PORT", mongodb_port)
        if "mongodb_username" in js:
            mongodb_username = js["mongodb_username"]
            write_config(config, "Main", "MONGODB_USERNAME", mongodb_username)
        if "mongodb_password" in js:
            mongodb_password = js["mongodb_password"]
            write_config(config, "Main", "MONGODB_PASSWORD", mongodb_password)
        if "kafka_hosts" in js:
            kafka_hosts = js["kafka_hosts"]
            write_config(config, "Main", "KAFKA_HOSTS", kafka_hosts)
        if "db_name" in js:
            db_name = js["db_name"]
            write_config(config, "Main", "DB_NAME", db_name)
        if "db_tab_name" in js:
            db_tab_name = js["db_tab_name"]
            write_config(config, "Main", "DB_TAB_NAME", db_tab_name)
        if "kafka_topic" in js:
            kafka_topic = js["kafka_topic"]
            write_config(config, "Main", "KAFKA_TOPIC", kafka_topic)
        if "kafka_group" in js:
            kafka_group = js["kafka_group"]
            write_config(config, "Main", "KAFKA_GROUP", kafka_group)

        with open(PP_CFG_CONF, 'w') as f:
            config.write(f)

    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="conf file write error", err=-3, data=None)

    return jsonify(msg="ok", err=0, data=None)

# 从config文件中，读取配置参数
def read_config(config, section, key, def_value):
    try:
        return config.get(section, key)
    except:
        return def_value


# 获取账号登录登出模块环境配置
@app.route('/list/pp_cfg', methods=['GET'])
@auth.login_required
def dp_get_pp_cfg():
    if not os.path.exists(PP_CFG_CONF):
        return jsonify(msg="no conf file", err=-2, data=None)

    d = None
    try:
        config = ConfigParser.ConfigParser()
        config.read(PP_CFG_CONF)

        mongodb_host = read_config(config, "Main", "MONGODB_HOST", "")
        mongodb_port = read_config(config, "Main", "MONGODB_PORT", 0)
        mongodb_username = read_config(config, "Main", "MONGODB_USERNAME", "")
        mongodb_password = read_config(config, "Main", "MONGODB_PASSWORD", "")
        kafka_hosts = read_config(config, "Main", "KAFKA_HOSTS", "")
        db_name = read_config(config, "Main", "DB_NAME", "")
        db_tab_name = read_config(config, "Main", "DB_TAB_NAME", "")
        kafka_topic = read_config(config, "Main", "KAFKA_TOPIC", "")
        kafka_group = read_config(config, "Main", "KAFKA_GROUP", "")

        d = json.dumps({
            "mongodb_host": mongodb_host,
            "mongodb_port": mongodb_port,
            "mongodb_username": mongodb_username,
            "mongodb_password": mongodb_password,
            "kafka_hosts": kafka_hosts,
            "db_name": db_name,
            "db_tab_name": db_tab_name,
            "kafka_topic": kafka_topic,
            "kafka_group": kafka_group,
        })

    except:
        print >> sys.stderr, traceback.format_exc()
        return jsonify(msg="unknown", err=-1, data=None)

    return jsonify(msg="ok", err=0, data=d)



# 调试测试用
@app.route('/test', methods=['POST', 'GET'])
@auth.login_required
def test():
    if not app.config.get('DEBUG', False):
        # 被禁止
        abort(403)

    url = app.config['CONF_URL']
    try:
        return jsonify([get_api_rsp_data(requests.get(url + '/apis/', timeout=CFG_TIMEOUT)),
                        get_api_rsp_data(requests.get(url + '/plugins/', timeout=CFG_TIMEOUT)),
                        get_api_rsp_data(requests.get(url + '/upstreams/', timeout=CFG_TIMEOUT)),
                        get_api_rsp_data(requests.get(url + '/upstreams/{}/targets/'.format('abc.de'), timeout=CFG_TIMEOUT)),
                        get_api_rsp_data(requests.get(url + '/upstreams/{}/targets/active/'.format('abc.de'), timeout=CFG_TIMEOUT)),
                        ])
        #return jsonify(get_api_rsp_data(requests.get(url + '/apis', timeout=CFG_TIMEOUT)))
        #return jsonify(get_api_rsp_data(requests.get(url + '/plugins', timeout=CFG_TIMEOUT)))
        #return jsonify(get_api_rsp_data(requests.get(url + '/upstreams', timeout=CFG_TIMEOUT)))
        #return jsonify(get_api_rsp_data(requests.get(url + '/upstreams/{}/targets'.format('abc.de'), timeout=CFG_TIMEOUT)))
    except:
        print >> sys.stderr, traceback.format_exc()
        # 服务不可用
        abort(503)


# @app.route('/', methods=['POST', 'GET'])
# #@auth.login_required
# def index():
#     if request.method == 'POST':
#         user = request.form['nm']
#         return redirect(url_for('success',name = user))
#    else:
#         user = request.args.get('nm')




app.config.update(dict(
    #CONF_USERS={},
    CFG_TIMEOUT=CFG_TIMEOUT,
    CFG_CONNECT_TIMEOUT=CFG_CONNECT_TIMEOUT,
    CONF_URL='http://127.0.0.1:9001',
    CONF_PLUGIN_NAME='mirror',
    #APP_DATA_DIR=os.path.join(app.root_path, 'data'),
    #TEMPLATES_AUTO_RELOAD=True,
    #DATABASE=os.path.join(app.root_path, '_data', 'flaskr.db'),
    #DEBUG=True,
    DEBUG=False,
    SECRET_KEY='\xf1\xc1.V\xebB\xb6\x12\t\xc3y\x84A\xaaDj\xda\xf9\xba\xe8\xf7\xb5R-', # os.urandom(24)
    USERNAME='admin',
    PASSWORD='default'
))

# 从文件中加载配置
if os.path.exists("config.json"):
    try :
        app.config.from_json("config.json", silent=True)
        users.update(app.config.get('CONF_USERS', {}))
        print users
        d = app.config.get("CFG_TIMEOUT", CFG_TIMEOUT)
        # 最长为100s
        if d>0 and d<=100:
            CFG_TIMEOUT = d
        d = app.config.get("CFG_CONNECT_TIMEOUT", CFG_CONNECT_TIMEOUT)
        # 最长为100s
        if d>0 and d<=100*1000:
            CFG_CONNECT_TIMEOUT = d
    except:
        print >> sys.stderr, traceback.format_exc()


# 从环境变量中加载配置
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

application = app




def main():
    # in contrast to argparse, this works at least under Python < 2.7
    import optparse
    from werkzeug.utils import import_string

    parser = optparse.OptionParser(
        usage='Usage: %prog [options] ')
    parser.add_option('-b', '--bind', dest='address',
                      help='The hostname:port the app should listen on.')
    parser.add_option('-d', '--debug', dest='use_debugger',
                      action='store_true', default=False,
                      help='Use Werkzeug\'s debugger.')
    parser.add_option('-r', '--reload', dest='use_reloader',
                      action='store_true', default=False,
                      help='Reload Python process if modules change.')
    parser.add_option('-t', '--with-threads', dest='use_threads',
                      action='store_true', default=False,
                      help='With multithreading.')
    options, args = parser.parse_args()


    hostname, port = None, None
    if options.address:
        address = options.address.split(':')
        hostname = address[0]
        if len(address) > 1:
            port = address[1]
    run_simple(
        hostname=(hostname or '127.0.0.1'), port=int(port or 5000),
        application=application, use_reloader=options.use_reloader,
        use_debugger=options.use_debugger, threaded=options.use_threads
    )


if __name__ == '__main__':
    random.seed(time.time())
    main()

