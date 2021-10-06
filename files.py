#!/usr/bin/env python3

from sys import stdin
import json5 as json
import nacl.utils
import nacl.public
import qrcode
from   qrcode.image.svg import SvgFillImage
import datetime
import re

b64 = nacl.encoding.Base64Encoder

# Known bug: Does not check if IPv4 decimal numbers (within [0,255]) are out of
# range (e.g. 256.300.123.666 is not valid)
# Same for CIDR suffixes, valid in the interval [0,32] for IPv4 and [0,128] for
# IPv6
ip_re_ipv4 = re.compile("^(\d{1,3}\.?){4}(/\d{1,3})?$")
ip_re_ipv6 = re.compile("^([0-9a-fA-F]{0,4}:?){1,8}(/\d{1,3})?$")

def peers(peer_list):
    accum = "\n"
    for p in peer_list:
        accum += section("Peer")
        # See https://github.com/MindFlavor/prometheus_wireguard_exporter
        accum += "# friendly_name = {:10}\n".format(p["name"])
        accum += key("PublicKey", p["publ_key"])
        accum += key("PersistentKeepalive", "25")
        if p["server"]:
            accum += key("Endpoint", "{}:{:05}".format(p["hostname"],
                                                       p["port"]))
        allowedips = []
        if p["primary"]:
            allowedips += p["ips"]
        else:
            for ip in p["ips"]:
                allowedips.append(ip_localize(ip))
        if "addl_nets" in p:
            allowedips += p["addl_nets"]
        accum += key("AllowedIPs", allowedips)
        accum += '\n'
    return accum

def ip_split(ip):
    spl = ip.split('/')
    assert len(spl) >= 1 and len(spl) <= 2
    return spl

def ip_type(ip):
    ip_type_v = None
    if   ip_re_ipv4.match(ip): ip_type_v = 'ipv4'
    elif ip_re_ipv6.match(ip): ip_type_v = 'ipv6'
    assert ip_type_v
    return ip_type_v

# Takes an IPv4 or IPv6 address with or without CIDR and outputs a "localized"
#   form of said address, to wit: IPv4 addresses will have a CIDR of /32 and
#   IPv6 addresses will have a CIDR of /128.
def ip_localize(ip):
    ip_type_v = ip_type(ip)
    ip_cidr   = ip_split(ip)
    if   ip_type_v == 'ipv4':
        ip_cidr[1] = 32
    elif ip_type_v == 'ipv6':
        ip_cidr[1] = 128
    return "{ip[0]}/{ip[1]}".format(ip=ip_cidr)

def section(name):
    return "[{}]\n".format(name)

def key(key, value):
    return "{:20} = {}\n".format(key, key_val(value))

def key_val(value):
    fmt = ""
    if isinstance(value, list):
        #print("A: {}".format(value))
        fmt = value[0]
        for i in value[1:]:
            fmt = "{}, {}".format(fmt, key_val(i))
    elif isinstance(value, bool):
        if value:
            fmt = "true"
        else:
            fmt = "false"
    elif isinstance(value, str) or isinstance(value, int):
        #print("R: {}".format(value))
        fmt = '{}'.format(value)
    else:
        raise ValueError(type(value))
    assert isinstance(fmt, str)
    return fmt

config = json.loads(stdin.buffer.read())
for i in config:
    for v in ["phone", "server", "primary"]:
        if not v in i:
            i[v] = False
for n, i in enumerate(config):
    i_config_text = ''
    iso8601 = datetime.datetime.now().strftime("%Y-%m-%d")
    i_config_text += "# Wireguard configuration for host '{}'\n".format(i["name"])
    i_config_text += "# Generated on {} by wg-conf-tools\n".format(iso8601)

    i_config_text += section("Interface")
    i_config_text += key("Address", i["ips"])
    i_config_text += key("PrivateKey", i["priv_key"])
    #i_config_text += key("SaveConfig", False)
    if i["server"]:
        i_config_text += key("ListenPort", i["port"])

    # Peers
    peer_list = []
    if i["server"]:
        peer_list = config.copy()
        peer_list.pop(n)
    else:
        peer_list = [item for item in config if item["server"]]
    i_config_text += peers(peer_list)
    with open(i["sname"]+".conf", "w") as f:
        f.write(i_config_text)
    if i["phone"]:
        qr = qrcode.make(i_config_text,
                         image_factory=SvgFillImage)
        qr.save('{}.svg'.format(i['sname']))
