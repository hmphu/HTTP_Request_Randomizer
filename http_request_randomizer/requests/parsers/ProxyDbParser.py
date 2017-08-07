# @Author:        Tuan Do
# @Create Date:   8/4/2017
import logging

import requests
from bs4 import BeautifulSoup

from http_request_randomizer.requests.parsers.UrlParser import UrlParser

import re

logger = logging.getLogger(__name__)
__author__ = 'pgaref'


class ProxyDbParser(UrlParser):
    def __init__(self, web_url, timeout=None):
        UrlParser.__init__(self, web_url, timeout)

    def parse_proxyList(self):
        off_set = 0
        curr_proxy_list = []
        # get 120 proxies
        while off_set < 120:
            response = requests.get(self.get_URl() + '&offset=' + str(off_set), timeout=self.timeout)
            off_set += 20
            if not response.ok:
                logger.warn("Proxy Provider url failed: {}".format(self.get_URl()))
                return []
            content = response.content
            soup = BeautifulSoup(content, "lxml")
            # table = soup.find('tbody').find_all('tr')
            table = soup.find("table", attrs={"class": "table table-sm table-hover table-bordered table-responsive"})
            if table is None:
                return curr_proxy_list

            for ls in table.find_all("tr")[1:]:
                tds = ls.find_all('td')
                proxy_script = ''.join(tds[0].text.split())
                proxy_containers = proxy_script.replace('PleaseenableJavaScripttoseeproxy', '')
                var_x_containers = re.search(r"varx='([\d+\.]+)'", proxy_containers).group().split("varx=")[1][::-1]
                var_x = re.search(r"([\d+\.]+)", var_x_containers).group()
                var_y_containers = re.search(r"vary='([\d+\.]+)'", proxy_containers).group().split("vary=")[1]
                var_y = re.search(r"([\d+\.]+)", var_y_containers).group()
                ip = var_x + var_y
                var_p_containers = re.search(r"varp=([-|+\d+\.]+)", proxy_containers).group().split("varp=")[1]
                var_p = var_p_containers.split('+')
                port = int(var_p[0]) + int(var_p[1])
                ip_address = ip + ':' + str(port)
                _type = ''.join(tds[1].text.split()).lower()
                curr_proxy_list.append('http://' + ip_address)

        return curr_proxy_list


def __str__(self):
    return "ProxyDb Parser of '{0}' with required bandwidth: '{1}' KBs" \
        .format(self.url, self.minimum_bandwidth_in_KBs)
