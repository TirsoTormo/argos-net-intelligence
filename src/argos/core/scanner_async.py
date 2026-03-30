"""
Argos - High Performance Async Port Scanner
===========================================
Uses asyncio for non-blocking concurrent scanning of thousands of ports.
"""
import asyncio
import time
from typing import List, Dict, Optional, Callable
from argos.core.models import ServiceAuditModel

async def scan_port_async(ip: str, port: int, timeout: float = 1.0) -> Optional[Dict]:
    """Scans a single port asynchronously."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return {"port": port, "status": "open"}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

async def scan_ports_bulk_async(
    ip: str, 
    ports: List[int], 
    concurrency: int = 200, 
    timeout: float = 1.0,
    progress_callback: Optional[Callable] = None
) -> List[Dict]:
    """Scans a list of ports with controlled concurrency."""
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    total = len(ports)
    completed = 0

    async def _sem_scan(port):
        nonlocal completed
        async with semaphore:
            res = await scan_port_async(ip, port, timeout)
            completed += 1
            if progress_callback and completed % 20 == 0:
                progress_callback(f"Scanning port {port}...", completed / total)
            if res:
                results.append(res)

    tasks = [_sem_scan(p) for p in ports]
    await asyncio.gather(*tasks)
    return sorted(results, key=lambda x: x["port"])

def run_bulk_scan(ip: str, ports: List[int], concurrency: int = 500) -> List[Dict]:
    """Synchronous entry point for the bulk scanner."""
    return asyncio.run(scan_ports_bulk_async(ip, ports, concurrency))
