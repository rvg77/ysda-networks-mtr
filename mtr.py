#!/usr/bin/env python3

import argparse

from curses import wrapper

from scapy.all import *
import pandas as pd

def display_status(stdscr, text):
    stdscr.clear()
    stdscr.addstr(text)
    stdscr.scrollok(True)
    stdscr.refresh()

def extract_ip_packet(p):
    if IP in p:
        return p[IP]
    elif IPv6 in p:
        return p[IPv6]
    else:
        raise NotImplementedError('Please choose ipv4 or ipv6')

def build_packet(ip, wrap, dst_host, ttl):
    if ip == 'ipv4':
        packet = IP(dst=dst_host, ttl=ttl)
    elif ip == 'ipv6':
        packet = IPv6(dst=dst_host, hlim=ttl)

    if wrap == 'icmp':
        if ip == 'ipv4':
            packet = packet/ICMP()
        elif ip == 'ipv6':
            packet = packet/ICMPv6EchoRequest()
    elif wrap == 'udp':
        packet = packet/UDP(dport=30000)/Raw(load='0'*32)
    elif wrap == 'tcp':
        return packet/TCP(dport=80, seq=0, flags='S')
    
    return packet


class Hop:
    def __init__(self):
        self.hosts = set()
        self.sent = 0
        self.received = 0

    def receive(self, query, answer):
        self.sent += 1
        if answer is not None:
            self.hosts.add(extract_ip_packet(answer).src)
            self.received += 1

    def get_stats(self):
        return [
            '\n'.join(self.hosts),                          # hosts
            (1 - (self.received / self.sent)) * 100,        # loss (%)
            self.sent,                                      # sent
        ]


class MTRSession:
    def __init__(self, host, max_ttl, timeout, ip, wrap):
        self.dst_host = host  # url
        self.max_ttl = max_ttl
        self.timeout = timeout
        self.ip = ip
        self.wrap = wrap
    
        self.target_dst = None  # ip
        self._is_reached = False
        self.total_ttl = 1
        self.hops = []

    def receive(self, query, answer):
        if self.target_dst is None:
            self.target_dst = extract_ip_packet(query).dst
        if not self._is_reached and answer is not None:
            self._is_reached = self.target_dst == extract_ip_packet(answer).src

        if IP in query:
            orig_ttl = query[IP].ttl
        elif IPv6 in query:
            orig_ttl = query[IPv6].hlim
        else:
            raise NotImplementedError('Please, use ipv4/ipv6')
        # new hop
        if len(self.hops) < orig_ttl:
            self.hops.append(Hop())

        self.hops[orig_ttl - 1].receive(query, answer)

    def __str__(self):
        rows = []
        prev_loss = 0
        for hop_no, hop in enumerate(self.hops):
            hop_stats = hop.get_stats()
            hop_stats[1], prev_loss = max(0, hop_stats[1] - prev_loss), hop_stats[1]
            hop_stats[1] = '{:.2f}'.format(hop_stats[1])

            rows.append([hop_no + 1] + hop_stats)
        
        table = pd.DataFrame(
            data={
                col: val
                for col, val in zip(['Hop No.', 'Hosts', 'Loss (%)', 'Sent'], zip(*rows))
            }
        )
        return table.to_markdown(tablefmt="grid", index=False)

    def can_go_deeper(self):
        if len(self.hops) < 2:
            return True
        return len(self.hops[-1].hosts) > 0 or len(self.hops[-2].hosts) > 0

    def increase_ttl_if_needed(self):
        if (not self._is_reached) and self.can_go_deeper() and self.total_ttl < self.max_ttl:
            self.total_ttl += 1

    def finished_expansion(self):
        return self._is_reached or self.total_ttl == self.max_ttl

    def run(self, stdscr):
        is_reachable = True
        while True:
            cur_ttl = (1, self.total_ttl) if self.finished_expansion() else self.total_ttl
            
            req = build_packet(self.ip, self.wrap, self.dst_host, cur_ttl)
            ans, unans = sr(req, timeout=self.timeout, verbose=0)
            # process results
            if ans:
                for a in ans:
                    assert len(a) == 2
                    self.receive(a[0], a[1])
            if unans:
                if self.total_ttl == 1:
                    is_reachable = False
                    break
                for u in unans:
                    self.receive(u, None)

            display_status(stdscr, f'MTR for {self.dst_host} ({self.target_dst})\nis_reached: {self._is_reached}\nCurrent ttl: {cur_ttl}\n{self}')
            # handle quit
            try:
                if stdscr.getkey() == 'q':
                    break
            except:
                pass

            self.increase_ttl_if_needed()
        
        if not is_reachable:
            display_status(stdscr, 'Unreachable')
            stdscr.nodelay(False)
            stdscr.getch()


def run(stdscr, args):
    stdscr.nodelay(True)
    stdscr.clear()

    MTRSession(args.host, args.max_ttl, args.timeout, args.ip, args.wrap).run(stdscr)

def parse_args():
    parser = argparse.ArgumentParser(description='Traceroute + packet loss %')
    
    parser.add_argument('host', help='destination host address')
    parser.add_argument('-i', '--ip', type=str, choices=['ipv4', 'ipv6'], help='IP protocol version', default='ipv4')
    parser.add_argument('-w', '--wrap', type=str, choices=['icmp', 'udp', 'tcp'], help='L3/L4 protocol to use', default='icmp')
    parser.add_argument('-t', '--timeout', type=int, help='Timeout per 1 scapy.sr call', default=1)
    parser.add_argument('--max-ttl', type=int, help='max TTL for IP packets', default=16)
    
    args = parser.parse_args()
    assert args.max_ttl >= 1
    
    return args

if __name__ == '__main__':
    args = parse_args()
    wrapper(run, args)