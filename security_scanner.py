import socket
import threading
import datetime
from queue import Queue

# Base simples de vulnerabilidades por serviço
VULN_DATABASE = {
    "ftp": "FTP permite ataques de brute force. Recomendação: usar SFTP.",
    "ssh": "Verifique política de senhas e uso de chaves.",
    "http": "Verifique headers de segurança e versão do servidor.",
    "https": "Garantir TLS 1.2+ e certificados atualizados.",
    "mysql": "MySQL exposto é um risco crítico.",
    "rdp": "RDP é alvo comum de força bruta."
}

def scan_port(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        result = sock.connect_ex((target, port))

        if result == 0:
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "Não identificado"

            results.append((port, banner))
        sock.close()

    except Exception:
        pass

def generate_report(target, results):
    filename = f"relatorio_{target}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("RELATÓRIO DE ANÁLISE DE SEGURANÇA\n")
        f.write(f"Alvo: {target}\n")
        f.write(f"Data: {datetime.datetime.now()}\n\n")

        if not results:
            f.write("Nenhuma porta aberta detectada.\n")
            return filename

        for port, banner in results:
            service = banner.lower()

            f.write(f"Porta: {port}\n")
            f.write(f"Banner: {banner}\n")

            found_risk = False
            for key, risk in VULN_DATABASE.items():
                if key in service:
                    f.write(f"Possível vulnerabilidade: {risk}\n")
                    found_risk = True

            if not found_risk:
                f.write("Nenhum risco identificado pelo banner.\n")

            f.write("\n")

    return filename

def main():
    print("=== Python Security Scanner ===")
    target = input("Digite o IP/host para análise: ")

    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]

    results = []
    threads = []

    print(f"\nIniciando scan em {target}...\n")

    for port in ports:
        t = threading.Thread(target=scan_port, args=(target, port, results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\nScan finalizado. Gerando relatório...")
    filename = generate_report(target, results)

    print(f"\nRelatório salvo como: {filename}")
    print("\nFinalizado com sucesso.")

if __name__ == "__main__":
    main()