#!/usr/bin/env python3
"""
Network Traffic Analyzer - Sniffer de paquetes con detección de amenazas.
Captura tráfico en vivo o lee .pcap, clasifica por protocolo,
detecta patrones sospechosos y genera alertas en consola + CSV.
"""

import argparse
import csv
import os
import sys
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import (
        sniff,
        rdpcap,
        IP,
        TCP,
        UDP,
        ICMP,
        DNS,
        DNSQR,
        ARP,
        wrpcap,
    )
except ImportError:
    print("[!] Scapy no está instalado. Ejecuta: pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuración de umbrales (ajustables)
# ---------------------------------------------------------------------------
PORT_SCAN_THRESHOLD = 15          # puertos distintos en ventana temporal
PORT_SCAN_WINDOW = 60             # segundos
ARP_SPOOF_THRESHOLD = 3           # MACs distintas para la misma IP
ARP_SPOOF_WINDOW = 120
DNS_QUERY_LEN_THRESHOLD = 55      # longitud sospechosa de dominio
DNS_FREQ_THRESHOLD = 20           # consultas en ventana temporal
DNS_FREQ_WINDOW = 60


# ---------------------------------------------------------------------------
# Colores ANSI para la consola
# ---------------------------------------------------------------------------
class Color:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# ---------------------------------------------------------------------------
# PacketClassifier
# ---------------------------------------------------------------------------
class PacketClassifier:
    """Clasifica cada paquete por su protocolo principal."""

    @staticmethod
    def classify(pkt) -> str:
        if pkt.haslayer(ARP):
            return "ARP"
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        return "OTHER"


# ---------------------------------------------------------------------------
# RuleEngine — patrones sospechosos
# ---------------------------------------------------------------------------
class RuleEngine:
    """Evalúa reglas de detección sobre paquetes clasificados."""

    def __init__(self):
        # Escaneo de puertos: {src_ip: [timestamps de SYN]}
        self.syn_tracker: dict[str, list[float]] = defaultdict(list)
        # {src_ip: {(dst_ip, dst_port): [timestamps]}}
        self.port_access: dict[str, dict[tuple, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        # ARP spoofing: {src_ip: {mac: [timestamps]}}
        self.arp_table: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        # DNS: {src_ip: [timestamps]}
        self.dns_tracker: dict[str, list[float]] = defaultdict(list)

    def evaluate(self, pkt, protocol: str) -> list[dict]:
        """Devuelve una lista de alertas generadas por las reglas."""
        alerts = []
        now = time.time()

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        else:
            src_ip = "N/A"
            dst_ip = "N/A"

        # --- Regla 1: Escaneo de puertos TCP ---
        if protocol == "TCP" and pkt[TCP].flags & 0x02:  # SYN
            dst_port = pkt[TCP].dport
            self.port_access[src_ip][(dst_ip, dst_port)].append(now)
            self.syn_tracker[src_ip].append(now)

            # Limpiar ventanas
            self.syn_tracker[src_ip] = [
                t for t in self.syn_tracker[src_ip] if now - t < PORT_SCAN_WINDOW
            ]
            puertos = set()
            for (dip, dp), _ in self.port_access[src_ip].items():
                if dip == dst_ip:
                    puertos.add(dp)

            if len(self.syn_tracker[src_ip]) >= PORT_SCAN_THRESHOLD and len(puertos) >= PORT_SCAN_THRESHOLD:
                alerts.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "alert_type": "PORT_SCAN",
                    "detail": (
                        f"{len(self.syn_tracker[src_ip])} SYN en "
                        f"{len(puertos)} puertos distintos hacia {dst_ip}"
                    ),
                    "severity": "HIGH",
                })

        # --- Regla 2: ARP Spoofing ---
        if protocol == "ARP" and pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.op == 2:  # ARP reply
                src_mac = arp.hwsrc
                src_ip_arp = arp.psrc
                self.arp_table[src_ip_arp][src_mac].append(now)

                # Limpiar entradas expiradas
                macs_activos = [
                    mac for mac, ts in self.arp_table[src_ip_arp].items()
                    if any(t > now - ARP_SPOOF_WINDOW for t in ts)
                ]
                for mac in list(self.arp_table[src_ip_arp]):
                    if mac not in macs_activos:
                        del self.arp_table[src_ip_arp][mac]

                if len(macs_activos) >= ARP_SPOOF_THRESHOLD:
                    alerts.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "src_ip": src_ip_arp,
                        "dst_ip": "N/A",
                        "alert_type": "ARP_SPOOFING",
                        "detail": (
                            f"{len(macs_activos)} MACs diferentes "
                            f"para la IP {src_ip_arp}: {', '.join(macs_activos[:5])}"
                        ),
                        "severity": "CRITICAL",
                    })

        # --- Regla 3: DNS Exfiltration ---
        if protocol == "DNS" and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            dns = pkt[DNS]
            if dns.qd and dns.qd.haslayer(DNSQR):
                qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                query_len = len(qname)

                self.dns_tracker[src_ip].append(now)
                self.dns_tracker[src_ip] = [
                    t for t in self.dns_tracker[src_ip] if now - t < DNS_FREQ_WINDOW
                ]

                if query_len >= DNS_QUERY_LEN_THRESHOLD:
                    alerts.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "alert_type": "DNS_LONG_QUERY",
                        "detail": (
                            f"Consulta DNS anormalmente larga ({query_len} chars): "
                            f"{qname[:80]}..."
                        ),
                        "severity": "MEDIUM",
                    })

                if len(self.dns_tracker[src_ip]) >= DNS_FREQ_THRESHOLD:
                    alerts.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "alert_type": "DNS_HIGH_FREQ",
                        "detail": (
                            f"{len(self.dns_tracker[src_ip])} consultas DNS "
                            f"en {DNS_FREQ_WINDOW}s desde {src_ip}"
                        ),
                        "severity": "HIGH",
                    })

        return alerts


# ---------------------------------------------------------------------------
# AlertLogger — consola + CSV
# ---------------------------------------------------------------------------
class AlertLogger:
    """Escribe alertas a consola y a un archivo CSV."""

    SEVERITY_COLOR = {
        "CRITICAL": Color.RED + Color.BOLD,
        "HIGH": Color.RED,
        "MEDIUM": Color.YELLOW,
        "LOW": Color.GREEN,
    }

    def __init__(self, csv_path: str = "alerts.csv"):
        self.csv_path = csv_path
        self.csv_file = None
        self.writer = None
        self._init_csv()

    def _init_csv(self):
        exists = os.path.exists(self.csv_path)
        self.csv_file = open(self.csv_path, "a", newline="", encoding="utf-8")
        self.writer = csv.writer(self.csv_file)
        if not exists:
            self.writer.writerow(
                ["timestamp", "src_ip", "dst_ip", "alert_type", "severity", "detail"]
            )
            self.csv_file.flush()

    def log(self, alert: dict):
        color = self.SEVERITY_COLOR.get(alert["severity"], "")

        # Consola
        print(
            f"{color}[{alert['severity']}]{Color.RESET} "
            f"{Color.CYAN}{alert['timestamp']}{Color.RESET} | "
            f"{alert['alert_type']} | "
            f"{Color.BOLD}{alert['src_ip']}{Color.RESET} -> {alert['dst_ip']} | "
            f"{alert['detail']}"
        )

        # CSV
        self.writer.writerow([
            alert["timestamp"],
            alert["src_ip"],
            alert["dst_ip"],
            alert["alert_type"],
            alert["severity"],
            alert["detail"],
        ])
        self.csv_file.flush()

    def close(self):
        if self.csv_file:
            self.csv_file.close()


# ---------------------------------------------------------------------------
# Stats — estadísticas de captura
# ---------------------------------------------------------------------------
class Stats:
    def __init__(self):
        self.total = 0
        self.by_protocol: dict[str, int] = defaultdict(int)
        self.alerts_count = 0
        self.start_time = time.time()

    def record(self, protocol: str):
        self.total += 1
        self.by_protocol[protocol] += 1

    def record_alert(self):
        self.alerts_count += 1

    def summary(self):
        elapsed = time.time() - self.start_time
        print(f"\n{Color.BOLD}{'=' * 60}")
        print("  RESUMEN DE CAPTURA")
        print(f"{'=' * 60}{Color.RESET}")
        print(f"  Duración: {elapsed:.1f}s")
        print(f"  Paquetes totales: {self.total}")
        for proto in sorted(self.by_protocol):
            pct = (self.by_protocol[proto] / self.total * 100) if self.total else 0
            print(f"    {proto:>6}: {self.by_protocol[proto]:>6}  ({pct:.1f}%)")
        print(f"  Alertas generadas: {self.alerts_count}")
        print(f"{Color.BOLD}{'=' * 60}{Color.RESET}\n")


# ---------------------------------------------------------------------------
# Procesamiento principal
# ---------------------------------------------------------------------------
def process_packet(pkt, classifier: PacketClassifier, rule_engine: RuleEngine,
                   logger: AlertLogger, stats: Stats):
    protocol = classifier.classify(pkt)
    stats.record(protocol)

    src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"

    print(
        f"{Color.GREEN}[+]{Color.RESET} {protocol:>5} | "
        f"{src_ip:>15} -> {dst_ip:>15}"
    )

    try:
        alerts = rule_engine.evaluate(pkt, protocol)
        for alert in alerts:
            logger.log(alert)
            stats.record_alert()
    except Exception as e:
        print(f"    {Color.RED}[!] Error evaluando paquete: {e}{Color.RESET}")


def live_capture(interface: str | None, count: int | None,
                 classifier: PacketClassifier, rule_engine: RuleEngine,
                 logger: AlertLogger, stats: Stats):
    print(f"{Color.BOLD}[*] Captura en vivo en la interfaz: {interface or 'default'}{Color.RESET}")
    print(f"    Presiona Ctrl+C para detener\n")

    try:
        sniff(
            iface=interface,
            count=count or 0,
            prn=lambda pkt: process_packet(pkt, classifier, rule_engine, logger, stats),
            store=False,
        )
    except PermissionError:
        print(f"\n{Color.RED}[!] Error: Se necesitan permisos de administrador/root.")
        print(f"    Ejecuta: sudo python packet_sniffer.py -i {interface}{Color.RESET}")
        sys.exit(1)


def pcap_capture(pcap_path: str, classifier: PacketClassifier,
                 rule_engine: RuleEngine, logger: AlertLogger, stats: Stats):
    print(f"{Color.BOLD}[*] Leyendo archivo PCAP: {pcap_path}{Color.RESET}\n")

    packets = rdpcap(pcap_path)
    print(f"    {len(packets)} paquetes encontrados\n")

    for pkt in packets:
        process_packet(pkt, classifier, rule_engine, logger, stats)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer — Sniffer con detección de amenazas",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  Captura en vivo (interfaz por defecto):
    python packet_sniffer.py

  Captura en una interfaz específica, máximo 1000 paquetes:
    python packet_sniffer.py -i eth0 -c 1000

  Leer un archivo PCAP:
    python packet_sniffer.py -r captura.pcap

  Guardar alertas en un CSV personalizado:
    python packet_sniffer.py -o mis_alertas.csv
""",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Interfaz de red para captura en vivo",
    )
    parser.add_argument(
        "-r", "--read",
        help="Leer tráfico desde un archivo .pcap",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        help="Número máximo de paquetes a capturar (0 = ilimitado)",
    )
    parser.add_argument(
        "-o", "--output",
        default="alerts.csv",
        help="Ruta del archivo CSV de alertas (default: alerts.csv)",
    )
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        default=PORT_SCAN_THRESHOLD,
        help=f"Umbral de puertos para escaneo (default: {PORT_SCAN_THRESHOLD})",
    )
    parser.add_argument(
        "--dns-len-threshold",
        type=int,
        default=DNS_QUERY_LEN_THRESHOLD,
        help=f"Umbral de longitud de consulta DNS (default: {DNS_QUERY_LEN_THRESHOLD})",
    )
    parser.add_argument(
        "--dns-freq-threshold",
        type=int,
        default=DNS_FREQ_THRESHOLD,
        help=f"Umbral de frecuencia DNS (default: {DNS_FREQ_THRESHOLD})",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Aplicar umbrales personalizados
    global PORT_SCAN_THRESHOLD, DNS_QUERY_LEN_THRESHOLD, DNS_FREQ_THRESHOLD
    PORT_SCAN_THRESHOLD = args.port_scan_threshold
    DNS_QUERY_LEN_THRESHOLD = args.dns_len_threshold
    DNS_FREQ_THRESHOLD = args.dns_freq_threshold

    classifier = PacketClassifier()
    rule_engine = RuleEngine()
    logger = AlertLogger(csv_path=args.output)
    stats = Stats()

    print(f"\n{Color.BOLD}{'=' * 60}")
    print("  NETWORK TRAFFIC ANALYZER")
    print(f"{'=' * 60}{Color.RESET}")
    print(f"  Modo: {'Lectura PCAP' if args.read else 'Captura en vivo'}")
    print(f"  CSV:  {os.path.abspath(args.output)}")
    print(f"  Umbrales: port_scan={PORT_SCAN_THRESHOLD}, "
          f"dns_len={DNS_QUERY_LEN_THRESHOLD}, dns_freq={DNS_FREQ_THRESHOLD}")
    print(f"{Color.BOLD}{'=' * 60}{Color.RESET}\n")

    try:
        if args.read:
            pcap_capture(args.read, classifier, rule_engine, logger, stats)
        else:
            live_capture(args.interface, args.count, classifier, rule_engine, logger, stats)
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}[*] Captura detenida por el usuario.{Color.RESET}")
    finally:
        stats.summary()
        logger.close()
        print(f"[i] Alertas guardadas en: {os.path.abspath(args.output)}")


if __name__ == "__main__":
    main()
