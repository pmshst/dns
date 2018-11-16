#!/usr/bin/env python
import asyncio
import websockets
import json
import pandas as pd
import logging
import time
import os

logger = logging.getLogger('crawler')
hdlr = logging.FileHandler('crawler.log')
#formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
formatter = logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt = '%Y-%m-%d %A %H:%M:%S')


ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.addHandler(ch)
logger.setLevel(logging.DEBUG)

# xn--infnote-q68luew60n.com
# 47.74.45.239:32767
message = {
   'identifier': '0',
   'type': 'question',
   'content': {
       'type': 'want_peers',
       'count': 10000
   }
}
full_node1_ip = '47.74.45.239'
full_node1_port = '32767'
# True means was crawled
ips = {'47.74.45.239':True}
ports = ['32767']
f = open('infnote_db_new.csv', 'w')
f.write('primarysever.infnote.com,test.admin.infnote.com 2016071114 28800 7200 604800 86400\n')
nodes_file = open('nodes.csv', 'w')
nodes_file.write('ip,good,last_check_time\n')

def get_ws_url(ip='47.74.45.239', port='32767'):
    return 'ws://' + ip + ':'+ port


async def request_peers(ip='47.74.45.239', port='32767'):
    good = True
    logger.info('try to connect '+ ip)
    try:
        async with websockets.connect(get_ws_url(ip, port)) as websocket:
            await websocket.send(json.JSONEncoder().encode(message))
            time_out_flag = False
            try:
                respose = await asyncio.wait_for(websocket.recv(), timeout=1)
            except asyncio.TimeoutError:
                time_out_flag = True
                good = False
                logger.info(ip+' connect is timeout, is not good')
            finally:
                if(time_out_flag is False):
                # respose = await websocket.recv()
                    j_respose = json.loads(respose)
                    pears = j_respose['content']['peers']
                    for pear in pears:
                        if (pear['address'] not in ips.keys()):
                            ips[pear['address']] = False
                            ports.append(pear['port'])                   #
                return
    except OSError as error:
        logger.info(ip+' is not good')
        ips[ip] = True
        good = False

    finally:
        if(good):
            logger.info(ip+' is good')
            f.write('infnote.com,' + ip + '\n')
            nodes_file.write(ip + ',yes,' + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n')
        else:
            nodes_file.write(ip + ',no,' + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n')
        return

def main(ip = '47.74.45.239',port = '32767'):
    asyncio.get_event_loop().run_until_complete(request_peers(ip, port))
    while True:
        for ip in ips.keys():
            if(ips[ip] == False):
                asyncio.get_event_loop().run_until_complete(request_peers(ip, port))
                # asyncio.get_event_loop().run_until_complete(request_peers('47.74.45.239', '32765'))
                ips[ip] = True
        break
    logger.info('crawled ips ' + str(ips.keys()))
    nodes_file.close()
    f.close()
    old_file = 'infnote_db_old.csv'
    new_file = 'infnote_db_new.csv'
    current_file = 'infnote_db.csv'
    if os.path.exists(old_file):
        os.remove(old_file)
    if os.path.exists(current_file):
        os.rename(current_file, old_file)
    os.rename(new_file, current_file)

main(full_node1_ip, full_node1_port)
