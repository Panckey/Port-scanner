import socket
import time
from concurrent.futures import ThreadPoolExecutor
import threading
import os
import requests
import argparse
import ipadress

OuvPort = []
SerPort = []

ports_services = {}
try:
    with open("nmap-services.txt", "r") as f:
        for line in f:
            if not line.startswith("#") and line.strip():
                parts = line.split()
                port_proto = parts[1].split("/")
                if port_proto[1] == "tcp":
                    ports_services[int(port_proto[0])] = parts[0]
except Exception as e:
    print("Fichier nmap-services.txt non trouvé")
    try:
        response = requests.get("https://raw.githubusercontent.com/nmap/nmap/master/nmap-services")
        with open("nmap-services.txt", "wb") as f:
            f.write(response.content)
        print("Veuillez relancer le fichier")
        exit()
    except Exception as e:
        print(e)
        print("Fichier Non trouvable, veuillez le télécharger manuellement")
        exit()

lock = threading.Lock()

NTime = round(time.time(), 1)
NTime = str(NTime)

def ScanPort(ip, Port):
    """
    Envoie des paquets à un port précis puis retourne s'il est ouvert ou non ainsi que son service en utilisant la base de donnée nmap-service.txt
    ip (str): L'adresse ip ou domaine à scanner
    Port (int): Numéro du port à scanner
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)
        s.connect((ip, Port))
        service = ports_services.get(Port, "Non identifié")
        print(f"Port {Port} Ouvert : {service} \n")
        with lock:
            OuvPort.append(Port)
            SerPort.append(f"Port {Port} Ouvert : {service} \n")
    except socket.error as e:
        if str(e) != "timed out":
            print(f"Port {Port} : Fermé - Raison : {e} \n")
    finally:
        s.close()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Scanner de port fais par Panckey")
    parser.add_argument("-ip", type=str, help="Addresse IP ou domaine à scanner")
    parser.add_argument("-min", type=int, default=1, help="Port a partir duquel le scan commencera")
    parser.add_argument("-max", type=int, default=65535, help="Port a partir duquel le scan s'arretera")
    parser.add_argument("-out", type=str, default=None, help="Nom du fichier sous lequel enregistrer")

    args = parser.parse_args()


    cpu = os.cpu_count() or 4
    try:
        MinPort = args.min or int(input("Port minimum (défault 1): "))
    except Exception as e:
        MinPort = 1

    try:
        MaxPort = args.max or int(input("Port Maximum (défault 65535): "))
    except Exception as e:
        MaxPort = 65535

    if MaxPort > 65535:
        MaxPort= 65535
    elif MaxPort <= 0:
        print("Port maximal trop petit")
        exit()

    if MinPort <= 0:
        MinPort = 1
    elif MinPort > 65535:
        print("Port Minimum trop grand")
        exit()
    elif MinPort >= MaxPort:
        print("Port minimum supérieur au maximum")
        exit()

    ip = args.ip or str(input("Adresse rechercher : "))

    plage = MaxPort - MinPort

    try:
        ip = socket.gethostbyname(ip)
        print(f"Adresse Résolue à scanner : {ip}")
    except Exception as e:
        print("L'adresse spécifié est invalide")
        exit()

    Start_T = time.time()
    with ThreadPoolExecutor(max_workers=min(plage, cpu*50)) as executor:
        executor.map(lambda Port : ScanPort(ip, Port), range(MinPort, MaxPort+1))
    print(f"{len(OuvPort)} Port ouvert sur {MaxPort}")
    print(sorted(OuvPort))
    sorted(SerPort)
    if args.out != None:
        with open(f"{args.out}", "+a") as f:
            for port in SerPort:
                f.write(port)
    End_T = time.time()
    print(f"Temps écoulé : {round(End_T-Start_T, 3)} secondes")