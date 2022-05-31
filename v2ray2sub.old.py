#!/usr/bin/python3
import sys
import re
import json
import base64
import argparse
import urllib.request

class UnknowProtocolException(Exception):
    pass

def get_host_ip():
    print("trying to get host ip address ...")
    req = urllib.request.Request(url="https://www.cloudflare.com/cdn-cgi/trace")
    with urllib.request.urlopen(req, timeout=5) as response:
        body = response.read().decode()
        for line in body.split("\n"):
            if line.startswith("ip="):
                _, _ip = line.split("=", maxsplit=2)
                if _ip != "":
                    print("using host ipaddress: {}, if not intended, use --addr option to specify".format(_ip))
                    return _ip
    return ""

def amend(obj, plain_amends, sed_amends):
    # plain replace
    for key, plain in plain_amends.items():
        val = obj.get(key, None)
        if val is None:
            continue
        obj[key] = plain

    # sed-like cmd replace
    for key, opt in sed_amends.items():
        val = obj.get(key, None)
        if val is None:
            continue
        obj[key] = re.sub(opt[0], opt[1], val, opt[2])
    return obj

def parse_inbounds(jsonobj, host, plain_amends, sed_amends, ss_type='ssr'):
    vmess_links = []
    ss_links = []

    if "inbounds" in jsonobj:
        for inbound in jsonobj["inbounds"]:
            if inbound["protocol"] == "vmess":
                try:
                    vmess_links.extend(inbound2vmess(inbound, host, plain_amends, sed_amends))
                except UnknowProtocolException:
                    pass
            elif inbound['protocol'] == 'shadowsocks':
                try:
                    ss_link = inbound2ss(inbound, host, plain_amends, sed_amends, ss_type)
                    ss_links.append(ss_link)
                except:
                    pass

    return ss_links + vmess_links

def inbound2ss(inbound, host, plain_amends, sed_amends, ss_type='ssr'):
    setting = inbound.get('settings', {})
    ss_dict = {
        'port': inbound['port'],
        'host': host,
        'method': setting.get('method', ''),
        'password': setting.get('password', '')
    }
    if ss_type == 'ssr':
        ss_dict['ps'] = base64.urlsafe_b64encode('ssr-{host}-{port}'.format(**ss_dict).encode('utf-8')).decode('utf-8')
        ss_dict['auth'] = base64.urlsafe_b64encode(ss_dict['password'].encode('utf-8')).decode('utf-8')
        ss_dict = amend(ss_dict, plain_amends, sed_amends)
        ss_link = '{host}:{port}:origin:{method}:plain:{auth}/?obfsparam=&protoparam=&remarks={ps}&group='.format(**ss_dict)
        return 'ssr://' + base64.urlsafe_b64encode(ss_link.encode('utf-8')).decode('utf-8')
    elif ss_type == 'ss':
        ss_dict['ps'] = 'ss-{host}-{port}'.format(**ss_dict)
        ss_dict['auth'] = base64.b64encode('{method}:{password}'.format(**ss_dict).encode('utf-8')).decode()
        ss_dict = amend(ss_dict, plain_amends, sed_amends)
        ss_link = 'ss://{auth}@{host}:{port}#{ps}'.format(**ss_dict)
        return ss_link

# def inbound2tj(inbound, host, plain_amends, sed_amends):
#     setting = inbound.get('settings', {})
#     tj_dict = {
        
#     }

def inbound2vmess(inbound, host, plain_amends, sed_amends):
    vmess_links = []
    port = inbound["port"]
    fake_type = "none"
    add = host
    path = ""
    tls = ""
    stream_settings = inbound.get("streamSettings", {})
    net = stream_settings.get("network", 'tcp')
    net_setting = stream_settings.get('{}Settings'.format(net if net != 'h2' else 'http'), {})
    ps = 'vmess-{net}-{add}-{port}'.format(net=net, add=add, port=port)

    if option.filter:
        for filt in option.filter:
            if filt.startswith("!") and net == filt[1:]:
                raise UnknowProtocolException()
            elif net != filt:
                raise UnknowProtocolException()
    
    if net == "tcp":
        tls = stream_settings.get("security", '')
        fake_type = net_setting.get('header', {}).get('type', 'none')

    elif net == "kcp":
        fake_type = net_setting.get('header', {}).get('type', 'none')

    elif net == "ws":
        host = net_setting.get('headers', {}).get('Host', add)
        path = net_setting.get('path', '')
        tls = stream_settings.get("security", '')

    elif net == "h2" or net == "http":
        host = ",".join(net_setting.get("host", [add]))
        path = net_setting.get('path', '')
        tls = "tls"

    elif net == "quic":
        host = net_setting.get('security', add)
        path = net_setting.get("key", '')
        fake_type = net_setting.get("header", {}).get("type", 'none')

    else:
        raise UnknowProtocolException()

    for client in inbound.get('settings', {}).get('clients', []):
        vmess_dict = {
            'id': client['id'],
            'aid': str(client['alterId']),
            'v': '2',
            'tls': tls,
            'add': add,
            'port': port,
            'type': fake_type,
            'net': net,
            'path': path,
            'host': host,
            'ps': ps
        }
        vmess_dict = amend(vmess_dict, plain_amends, sed_amends)
        vmess_link = "vmess://" + base64.urlsafe_b64encode(json.dumps(vmess_dict, sort_keys=True).encode('utf-8')).decode('utf-8')
        vmess_links.append(vmess_link)
    return vmess_links

def parse_amendsed(val):
    if not val.startswith("s"):
        raise ValueError("not sed")
    spliter = val[1:2]
    _, pattern, repl, tags = sedcmd.split(spliter, maxsplit=4)
    return pattern, repl, tags

def links2base64(links):
    links_str = '\n'.join(links)
    base_str = base64.urlsafe_b64encode(links_str.encode('utf-8')).decode('utf-8')
    if option.debug:
        print(links)
        print(base_str)
    return base_str

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="json2vmess convert server side json into vmess links")
    parser.add_argument('-a', '--addr',
                        action="store",
                        default="",
                        help="server address. If not specified, program will detect the current IP")
    parser.add_argument('-r', '--ssr',
                        action='store_true',
                        default=False,
                        help="output with ssr link")
    parser.add_argument('-f', '--filter',
                        action="append",
                        help="Protocol Filter, useful for inbounds with different protocols. "
                        "FILTER starts with ! means negative selection. Multiple filter is accepted.")
    parser.add_argument('-m', '--amend',
                        action="append",
                        help="Amend to the output values, can be use multiple times. eg: -a port:80 -a ps:amended")
    parser.add_argument('--debug',
                        action="store_true",
                        default=False,
                        help="debug mode, show vmess obj")
    parser.add_argument('json',
                        type=argparse.FileType('r'),
                        default=sys.stdin,
                        help="parse the server side json")
    parser.add_argument('-o', '--output',
                        type=argparse.FileType('w'),
                        default=sys.stdout,
                        help='output subscribe info to file')

    option = parser.parse_args()

    host = option.addr if option.addr else get_host_ip()
    sed_amends = {}
    plain_amends = {}
    if option.amend:
        for s in option.amend:
            key, sedcmd = s.split(":", maxsplit=1)
            try:
                pattern, repl, tags = parse_amendsed(sedcmd)
            except ValueError:
                plain_amends[key] = sedcmd
                continue

            reflag = 0
            if "i" in tags:
                reflag |= re.IGNORECASE
            sed_amends[key] = [pattern, repl, reflag]

    jsonobj = json.load(option.json)
    ss_type = 'ssr' if option.ssr else 'ss'
    links = parse_inbounds(jsonobj, host, plain_amends, sed_amends, ss_type)
    base_str = links2base64(links)
    option.output.write(base_str)


