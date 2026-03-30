"""
Argos — QoS & Jitter Analyst Module
===================================
Module to evaluate network readiness for VoIP and real-time streams
by measuring Latency, Jitter, and Packet Loss.
Supports ICMP and UDP probing modes.
"""

import time
import asyncio
from typing import Dict, Optional, Callable, Any
from argos.core.models import QoSResultModel


def _calculate_mos(avg_latency: float, jitter: float, loss_pct: float) -> tuple:
    """Calculate Pseudo-MOS (Mean Opinion Score) 1-5 scale and rating."""
    effective_latency = avg_latency + (jitter * 2) + 10
    if effective_latency < 160:
        r_factor = 93.2 - (effective_latency / 40)
    else:
        r_factor = 93.2 - (effective_latency - 120) / 10

    r_factor = r_factor - (loss_pct * 2.5)
    r_factor = max(0, min(100, r_factor))

    mos = 1 + (0.035 * r_factor) + (r_factor * (r_factor - 60) * (100 - r_factor) * 0.000007)
    mos = max(1.0, min(5.0, mos))

    if mos >= 4.0:
        rating = "EXCELLENT"
    elif mos >= 3.6:
        rating = "GOOD"
    elif mos >= 3.0:
        rating = "ACCEPTABLE"
    else:
        rating = "POOR"

    return round(mos, 2), rating


async def measure_qos_jitter_async(
    target_ip: str,
    count: int = 50,
    interval: float = 0.05,
    protocol: str = "ICMP",
    udp_port: int = 33434,
    update_callback: Optional[Callable] = None
) -> QoSResultModel:
    """
    Sends a burst of probes to measure latency variance (Jitter) with high precision.
    
    Args:
        target_ip: Target IP address.
        count: Number of probes to send (Standard VoIP test is 50-100).
        interval: Seconds between probes (default 50ms).
        protocol: 'ICMP' or 'UDP'.
        udp_port: Base destination port for UDP probes.
        update_callback: Callback(sent, total, avg_lat, jitter, loss_pct).
    """
    try:
        from scapy.all import IP, ICMP, UDP, Raw, sr1
    except ImportError:
        return {"status": "error", "message": "Scapy no instalado o no se detectó entorno de red."}

    latencies = []
    lost = 0
    jitter_sum = 0
    last_lat = None
    
    # Payload de 160 bytes simula un frame G.711 RTP (voz real)
    payload = Raw(load=b"\x00" * 160)

    for i in range(count):
        loop_start = time.perf_counter()
        
        if protocol == "UDP":
            pkt = IP(dst=target_ip) / UDP(dport=udp_port + i, sport=33000 + (i % 1000)) / payload
        else:
            pkt = IP(dst=target_ip) / ICMP(id=999, seq=i) / payload

        try:
            # We use asyncio.to_thread for the blocking Scapy sr1 call
            from scapy.all import sr1
            ans = await asyncio.to_thread(sr1, pkt, timeout=0.4, verbose=False)
            
            if ans:
                # Precision: Usamos timestamps del kernel/capa de red que Scapy captura
                # Esto elimina el lag del procesado de Python en el cálculo.
                lat = (ans.time - pkt.sent_time) * 1000
                latencies.append(lat)
                
                # Jitter cumulative calculation (O(1))
                if last_lat is not None:
                    jitter_sum += abs(lat - last_lat)
                last_lat = lat
            else:
                lost += 1
                last_lat = None # Reset jitter reference on packet loss
                
        except PermissionError:
            return {"status": "error", "message": "Argos QoS requiere privilegios de ADMINISTRADOR."}
        except Exception as e:
            return {"status": "error", "message": f"Fallo en sonda: {e}"}

        if update_callback:
            curr_avg = sum(latencies) / len(latencies) if latencies else 0
            curr_jitter = jitter_sum / (len(latencies) - 1) if len(latencies) > 1 else 0
            curr_loss = (lost / (i + 1)) * 100
            update_callback(i + 1, count, curr_avg, curr_jitter, curr_loss)

        # Strict Pacing
        elapsed = time.perf_counter() - loop_start
        wait_time = max(0, interval - elapsed)
        if wait_time > 0:
            await asyncio.sleep(wait_time)

    if not latencies:
        return {"status": "error", "message": "Destino inalcanzable. 100% Packet Loss."}

    avg_latency = sum(latencies) / len(latencies)
    jitter = jitter_sum / (len(latencies) - 1) if len(latencies) > 1 else 0
    loss_pct = (lost / count) * 100

    return QoSResultModel(
        target_ip=target_ip,
        avg_latency=round(avg_latency, 2),
        jitter=round(jitter, 2),
        loss_pct=round(loss_pct, 1),
        probes_sent=count,
        probes_received=len(latencies),
        status="ok"
    )

def measure_qos_jitter(target_ip: str, count: int = 50) -> QoSResultModel:
    """Synchronous wrapper."""
    return asyncio.run(measure_qos_jitter_async(target_ip, count=count))
