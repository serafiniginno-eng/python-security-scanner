import socket
import argparse
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Configuración de Logging para reportes limpios
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class PortScanner:
    def __init__(self, target, threads=10):
        self.target = target
        self.threads = threads
        self.target_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
            3389: "RDP", 8080: "HTTP-Proxy"
        }

    def check_port(self, port):
        """Intenta conectar a un puerto específico."""
        service = self.target_ports.get(port, "Unknown")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    return f"[!] EXPOSICIÓN DETECTADA: Puerto {port} ({service}) ABIERTO"
                return None
        except Exception:
            return None

    def run(self):
        """Ejecuta el escaneo usando hilos para mayor velocidad."""
        logger.info("-" * 60)
        logger.info(f"AUDITORÍA DE SEGURIDAD PARA: {self.target}")
        logger.info(f"Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("-" * 60)

        # Uso de ThreadPoolExecutor para escaneo simultáneo (mucho más rápido)
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(self.check_port, self.target_ports.keys())

        found_any = False
        for res in results:
            if res:
                logger.info(res)
                found_any = True
        
        if not found_any:
            logger.info("[-] No se detectaron servicios críticos expuestos.")

        logger.info("-" * 60)
        logger.info("Escaneo completado.")

def main():
    # Argumentos por línea de comandos (Indispensable para un Ingeniero)
    parser = argparse.ArgumentParser(description="Professional Security Port Scanner")
    parser.add_argument("target", help="IP o Dominio a escanear")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Número de hilos (velocidad)")
    
    args = parser.parse_args()

    try:
        scanner = PortScanner(args.target, args.threads)
        scanner.run()
    except KeyboardInterrupt:
        logger.error("\n[!] Proceso abortado por el usuario.")
    except socket.gaierror:
        logger.error("\n[!] Error: No se pudo resolver el host.")

if __name__ == "__main__":
    main()
