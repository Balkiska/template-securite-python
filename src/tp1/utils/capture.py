from collections import defaultdict
from scapy.all import sniff, ARP, IP, TCP, DNS, Raw
from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


# attack aetection aelpers DRY=each rule is one small function

def _detect_arp_spoofing(packets):
    """Detect ARP spoofing: same IP claimed by different MACs."""
    ip_to_mac = {}
    alerts = []
    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            if src_ip in ip_to_mac and ip_to_mac[src_ip] != src_mac:
                alerts.append({
                    "type": "ARP Spoofing",
                    "protocol": "ARP",
                    "attacker_ip": src_ip,
                    "attacker_mac": src_mac,
                    "detail": f"IP {src_ip} claimed by {src_mac} (was {ip_to_mac[src_ip]})",
                })
            ip_to_mac[src_ip] = src_mac
    return alerts


def _detect_port_scan(packets, threshold=10):
    """Detect port scan: one source IP sends SYN to many different ports."""
    syn_map = defaultdict(set)
    alerts = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = pkt[TCP].flags
            if flags == "S":  # SYN only
                syn_map[pkt[IP].src].add(pkt[TCP].dport)
    for src_ip, ports in syn_map.items():
        if len(ports) > threshold:
            alerts.append({
                "type": "Port Scan",
                "protocol": "TCP",
                "attacker_ip": src_ip,
                "attacker_mac": "",
                "detail": f"{src_ip} scanned {len(ports)} ports",
            })
    return alerts


_SQL_PATTERNS = ["' or ", "union select", "drop table", "1=1", "' --", "'; --"]


def _detect_sql_injection(packets):
    """Detect SQL injection patterns in HTTP payloads."""
    alerts = []
    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(IP):
            try:
                payload = pkt[Raw].load.decode("utf-8", errors="ignore").lower()
            except Exception:
                continue
            for pattern in _SQL_PATTERNS:
                if pattern in payload:
                    alerts.append({
                        "type": "SQL Injection",
                        "protocol": "HTTP/TCP",
                        "attacker_ip": pkt[IP].src,
                        "attacker_mac": "",
                        "detail": f"Suspicious pattern '{pattern}' in payload from {pkt[IP].src}",
                    })
                    break
    return alerts


def _detect_dns_tunneling(packets, max_len=50):
    """Detect DNS tunneling: unusually long domain names in queries."""
    alerts = []
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qd:  # query
                qname = dns.qd.qname.decode("utf-8", errors="ignore")
                if len(qname) > max_len:
                    alerts.append({
                        "type": "DNS Tunneling",
                        "protocol": "DNS",
                        "attacker_ip": pkt[IP].src,
                        "attacker_mac": "",
                        "detail": f"Long DNS query ({len(qname)} chars): {qname[:60]}...",
                    })
    return alerts


# main capture class

class Capture:
    def __init__(self, interface=None, count=50, timeout=30) -> None:
        self.interface = interface or choose_interface()
        self.count = count
        self.timeout = timeout
        self.packets = []
        self.protocol_stats = {}
        self.alerts = []
        self.summary = ""

    def capture_traffic(self) -> None:
        """Capture network traffic from the selected interface using Scapy."""
        logger.info(f"Capturing on '{self.interface}' (max {self.count} pkts, {self.timeout}s timeout)")
        self.packets = list(
            sniff(iface=self.interface or None, count=self.count, timeout=self.timeout, store=1)
        )
        logger.info(f"Captured {len(self.packets)} packets")

    def get_all_protocols(self) -> dict:
        """Extract all protocol layers from captured packets and count them.

        :return: dict mapping protocol name -> packet count
        """
        stats = defaultdict(int)
        for pkt in self.packets:
            layer = pkt
            while layer:
                stats[layer.__class__.__name__] += 1
                layer = layer.payload if layer.payload and layer.payload.__class__.__name__ != "NoPayload" else None
        self.protocol_stats = dict(stats)
        return self.protocol_stats

    def sort_network_protocols(self) -> list:
        """Sort protocols by packet count (descending).

        :return: sorted list of (protocol, count) tuples
        """
        sorted_protocols = sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_protocols

    def analyse(self, protocols: str) -> None:
        """Analyse captured packets for illegitimate traffic.

        Runs all detection rules and builds alerts + summary.
        """
        self.get_all_protocols()
        self.sort_network_protocols()

        logger.debug(f"All protocols: {self.protocol_stats}")

        self.alerts = []
        self.alerts.extend(_detect_arp_spoofing(self.packets))
        self.alerts.extend(_detect_port_scan(self.packets))
        self.alerts.extend(_detect_sql_injection(self.packets))
        self.alerts.extend(_detect_dns_tunneling(self.packets))

        if self.alerts:
            logger.warning(f"Detected {len(self.alerts)} potential attack(s)!")
            for alert in self.alerts:
                logger.warning(f"  [{alert['type']}] {alert['detail']}")
        else:
            logger.info("No threats detected — all traffic looks legitimate.")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """Return the generated summary string."""
        return self.summary

    def _gen_summary(self) -> str:
        """Generate a human-readable summary of the capture and analysis."""
        lines = [
            f"Capture Summary: {len(self.packets)} packets captured",
            f"Protocols detected: {len(self.protocol_stats)}",
            "",
        ]

        sorted_protos = self.sort_network_protocols()
        for proto, count in sorted_protos:
            lines.append(f"  {proto}: {count} packets")

        lines.append("")
        if self.alerts:
            lines.append(f"ALERTS: {len(self.alerts)} potential attack(s) detected!")
            for alert in self.alerts:
                lines.append(f"  [{alert['type']}] {alert['detail']}")
                if alert["attacker_ip"]:
                    lines.append(f"    Attacker IP: {alert['attacker_ip']}")
                if alert["attacker_mac"]:
                    lines.append(f"    Attacker MAC: {alert['attacker_mac']}")
        else:
            lines.append("STATUS: All traffic appears legitimate.")

        return "\n".join(lines)
