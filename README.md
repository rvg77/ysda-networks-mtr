# YSDA TLS client

Аналог [MTR](https://www.cloudflare.com/ru-ru/learning/network-layer/what-is-mtr/) поверх Scapy.

## Сборка и запуск окружения

1. Собираем conda:
```bash
conda create -n ysda-networks python scapy pandas ipython tabulate -y
```
2. Команда запуска:
```bash
conda activate ysda-networks
```

## Usage


Функциональность можно легко глянуть через `--help`:
```bash
$ python mtr.py --help
YSDA networks home assignment
usage: mtr.py [-h] [-i {ipv4,ipv6}] [-w {icmp,udp,tcp}] [-t TIMEOUT] [--max-ttl MAX_TTL] host

Traceroute + packet loss %

positional arguments:
  host                  destination host address

options:
  -h, --help            show this help message and exit
  -i {ipv4,ipv6}, --ip {ipv4,ipv6}
                        IP protocol version
  -w {icmp,udp,tcp}, --wrap {icmp,udp,tcp}
                        L3/L4 protocol to use
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout per 1 scapy.sr call
  --max-ttl MAX_TTL     max TTL for IP packets
```

### Пример

```bash
python mtr.py ya.ru
```
