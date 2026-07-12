# Network Traffic Analyzer

Sniffer de paquetes en Python con deteccion de amenazas en tiempo real. Captura trafico en vivo o lee archivos `.pcap`, clasifica por protocolo y genera alertas cuando detecta patrones sospechosos.

## Caracteristicas

- **Captura en vivo** o **lectura de archivos .pcap**
- **Clasificacion por protocolo**: TCP, UDP, ICMP, DNS, ARP
- **Deteccion de amenazas** con reglas configurables:
  - Escaneo de puertos (SYN flood a multiples puertos)
  - ARP spoofing (multiples MACs para la misma IP)
  - DNS exfiltration (consultas anormalmente largas o frecuentes)
- **Alertas en consola** con colores ANSI, timestamp, IPs y severidad
- **Log en CSV** para analisis posterior (Excel, PowerBI, scripts)
- **Estadisticas** de captura al finalizar

## Arquitectura

```
[Interfaz de red / archivo .pcap]
        |
   [Scapy Sniffer]
        |
   [PacketClassifier] --> TCP / UDP / ICMP / DNS / ARP
        |
   [RuleEngine]
    |            |
   Normal    Alerta -> [AlertLogger] --> consola + alerts.csv
```

## Requisitos

- Python 3.10+
- [Scapy](https://scapy.net/)

## Instalacion

```bash
git clone https://github.com/JaimeUTP/Network_Traffic_Analyzer.git
cd Network_Traffic_Analyzer
pip install -r requirements.txt
```

## Uso

### Generar trafico de prueba

```bash
python generate_pcap.py
```

Crea `test_malicious.pcap` con 117 paquetes que incluyen port scan, ARP spoofing, DNS exfiltration y trafico normal de fondo.

### Analizar un archivo PCAP

```bash
python packet_sniffer.py -r test_malicious.pcap
```

### Captura en vivo

```bash
# Interfaz por defecto
sudo python packet_sniffer.py

# Interfaz especifica, maximo 1000 paquetes
sudo python packet_sniffer.py -i eth0 -c 1000
```

### Opciones CLI

```
-o, --output             Ruta del CSV de alertas (default: alerts.csv)
-i, --interface          Interfaz de red para captura en vivo
-r, --read               Leer desde archivo .pcap
-c, --count              Maximo de paquetes a capturar
--port-scan-threshold    Puertos SYN para disparar alerta (default: 15)
--dns-len-threshold      Longitud de dominio sospechosa (default: 55)
--dns-freq-threshold     Consultas DNS en ventana temporal (default: 20)
```

## Reglas de deteccion

| Regla | Tipo | Severidad | Condicion por defecto |
|-------|------|-----------|----------------------|
| `PORT_SCAN` | TCP SYN scan | HIGH | >=15 puertos distintos en 60s |
| `ARP_SPOOFING` | MAC spoofing | CRITICAL | >=3 MACs para una IP en 120s |
| `DNS_LONG_QUERY` | Dominio largo | MEDIUM | >=55 caracteres en el query |
| `DNS_HIGH_FREQ` | Frecuencia alta | HIGH | >=20 consultas en 60s |

## Salida de ejemplo

```
[HIGH] 2026-07-12 13:15:57 | PORT_SCAN | 10.0.0.99 -> 10.0.0.1 | 20 SYN en 20 puertos distintos
[CRITICAL] 2026-07-12 13:15:57 | ARP_SPOOFING | 10.0.0.1 -> N/A | 5 MACs diferentes
[MEDIUM] 2026-07-12 13:15:57 | DNS_LONG_QUERY | 10.0.0.77 -> 8.8.8.8 | 79 chars
[HIGH] 2026-07-12 13:15:57 | DNS_HIGH_FREQ | 10.0.0.77 -> 8.8.8.8 | 25 consultas en 60s
```

## Estructura del proyecto

```
Network_Traffic_Analyzer/
├── packet_sniffer.py      # Sniffer principal
├── generate_pcap.py       # Generador de trafico malicioso de prueba
├── requirements.txt       # Dependencias
├── LICENSE                # MIT License
└── README.md
```

## License

[MIT](LICENSE)
