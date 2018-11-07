#!/usr/bin/env python
# coding: utf-8
# reference https://github.com/anpengapple/apple_dns
import configparser
import os
import re
import socketserver
import dnslib
import gevent
from gevent import monkey
from gevent.queue import Queue
import pylru
monkey.patch_all()


def query(qname):
    """
    query in the file
    """
    with open('infnote_db.csv') as fdb:
        soa_line = fdb.readline().rstrip().split(',')
        soa = tuple(soa_line) if len(soa_line) == 2 else None
        dns = [tuple(line.rstrip('\r\n').split(',')) for line in fdb.readlines()]
        print('dns', dns)
    ret = []
    for t in dns:
        if (t[0] == qname ):
            ret.append(t)
    print('qname', qname)
    print('ret',ret)
    return ret, soa


def pack_dns(dns, answers, soa=None):
    content_type = lambda x: 'A' if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', x) else 'CNAME'
    if answers:
        for ans in answers:
            print('ans', ans)
            if content_type(ans[1]) == 'A':
                dns.add_answer(dnslib.RR(ans[0], dnslib.QTYPE.A, rdata=dnslib.A(ans[1])))
            elif content_type(ans[1]) == 'CNAME':
                dns.add_answer(dnslib.RR(ans[0], dnslib.QTYPE.CNAME, rdata=dnslib.CNAME(ans[1])))
    elif soa:
        soa_content = soa[1].split()
        dns.add_auth(
            dnslib.RR(soa[0],
            dnslib.QTYPE.SOA,
            rdata=dnslib.SOA(soa_content[0],
                soa_content[1],
                (int(i) for i in soa_content[2:]))))
    return dns


def handler(data, addr, sock):
    '''
    handle requests
    :param data:
    :param addr:
    :param sock:
    :return:
    '''
    try:
        dns = dnslib.DNSRecord.parse(data)
    except Exception as e:
        print('Not a DNS packet.\n', e)
    else:
        dns.header.set_qr(dnslib.QR.RESPONSE)
        # get request name
        qname = dns.q.qname
        # query response in LRUCache
        response = DNSServer.dns_cache.get(qname)
        print('qname =', qname, 'response =', response)
        if response:
            # return responce from db
            response[:2] = data[:2]
            sock.sendto(response, addr)
        else:
            # quary from db file if not in cache
            answers, soa = query(str(qname).rstrip('.'))
            answer_dns = pack_dns(dns, answers, soa)
            # cache responce
            DNSServer.dns_cache[qname] = answer_dns.pack()
            sock.sendto(answer_dns.pack(), addr)


def init_cache_queue():
    '''
    :return:
    '''
    while True:
        # get request from queue
        data, addr, sock = DNSServer.deq_cache.get()
        # handle request
        gevent.spawn(handler, data, addr, sock)


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if not DNSServer.deq_cache.full():
            #  cache request client_address sock
            DNSServer.deq_cache.put((self.request[0], self.client_address, self.request[1]))


class DNSServer(object):
    @staticmethod
    def start():
        # casch the request
        DNSServer.deq_cache = Queue(maxsize=deq_size) if deq_size > 0 else Queue()
        # LRU Cache
        DNSServer.dns_cache = pylru.lrucache(lru_size)
        # process the queue
        gevent.spawn(init_cache_queue)
        # start DNS sever
        print('Start DNS server at %s:%d\n' % (ip, port))
        dns_server = socketserver.UDPServer((ip, port), DNSHandler)
        dns_server.serve_forever()


def load_config(filename):
    with open(filename, 'r') as fc:
        cfg = configparser.ConfigParser()
        cfg.read_file(fc)
    return dict(cfg.items('DEFAULT'))


if __name__ == '__main__':
    # read infnote.ini
    config_file = os.path.basename(__file__).split('.')[0] + '.ini'
    config_dict = load_config(config_file)
    ip, port = config_dict['ip'], int(config_dict['port'])
    deq_size = int(config_dict['deq_size'])
    lru_size = int(config_dict['lru_size'])
    db = config_dict['db']
    DNSServer.start()
