#!/usr/bin/python3.9
# -*- coding: utf-8 -*-

import ipaddress
import os
import random
import re
import socket
import struct
import sys
import time
import dns.resolver
import requests

from threading import Thread


# Ajuda
def Help():
    print("\n[?]--> Help <--[?]\n\nExample: python3.9 stelfdoor.py [HOST] [--ARG]\n\n[DOOR SCANNER]\n\n -m_T1, -m_T2, "
          "-m_T3, -m_T4 -m_T5 --> To scan "
          "main ports\n -a_T1, --a_T2, "
          "-a_T3, -a_T4 -a_T5 --> To scan all possible ports from 1 to 65535\n -c_T1, -c_T2, "
          "-c_T3, -c_T4 -c_T5 --> To scan only 20 ports of your "
          "choice\n")

    print("[DIRECTORY SCANNER]\n\n --dir --> To search for directories\n--sub --> Search for subdomains or dns\n")

    print("[BRUTE FORCE ATTACKE]\n\n --ftp --> With this option it is possible to perform a brute force attack "
          "based on a wordlist containing possible passwords in FTP services\n")

    print("[CRAWLERS]\n\n--spider --> search for internal and external links within the site\n")


# Desenvolvedor
def Info():
    print("Developer by - Matheus Carvalho Da Silva")


# Verificação de argumentos
if len(sys.argv) < 2 or 1 == '-h':
    Help()
    exit(0)

if len(sys.argv) == 0:
    Help()


# Socket TCP/IP
def Connect():
    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set Timeout on socket Main_doors
    if sys.argv[2] == '-m_T1':
        s.settimeout(5.0)
    elif sys.argv[2] == '-m_T2':
        s.settimeout(2.0)
    elif sys.argv[2] == '-m_T3':
        s.settimeout(0.9)
    elif sys.argv[2] == '-m_T4':
        s.settimeout(0.5)
    elif sys.argv[2] == '-m_T5':
        s.settimeout(0.1)
    # Set Timeout on socket All_the_doors
    if sys.argv[2] == '-a_T1':
        s.settimeout(5.0)
    elif sys.argv[2] == '-a_T2':
        s.settimeout(2.0)
    elif sys.argv[2] == '-a_T3':
        s.settimeout(0.9)
    elif sys.argv[2] == '-a_T4':
        s.settimeout(0.5)
    elif sys.argv[2] == '-a_T5':
        s.settimeout(0.1)
    # Set Timeout on socket Choice_of_doors
    if sys.argv[2] == '-c_T1':
        s.settimeout(5.0)
    elif sys.argv[2] == '-c_T2':
        s.settimeout(2.0)
    elif sys.argv[2] == '-c_T3':
        s.settimeout(0.9)
    elif sys.argv[2] == '-c_T4':
        s.settimeout(0.5)
    elif sys.argv[2] == '-c_T5':
        s.settimeout(0.1)


# Scanner de portas tcp mais usadas
def Main_Dors():
    ports = [18, 20, 21, 22, 23, 25, 38, 43, 57, 80, 107, 110, 115, 119, 135, 137, 138, 139, 143, 443, 445, 1080, 1433,
             1434, 2082, 2083, 3306, 8080]

    for port in ports:
        Connect()
        code = s.connect_ex((sys.argv[1], port))

        scan1 = open('Main_dors.tmp', 'a')

        if code == 0:
            print("\n[+] " + str(port) + " --> code: 0 = Open door")
            scan1.write("\n\nPORTA ENCONTRADA :: " + str(port) + ' CODE >> ' + str(code) + '\n')
        elif code == 11:
            print("\n[-] " + str(port) + " --> code: 11 = Feature temporarily unavailable")
        elif code == 111:
            print("\n[-] " + str(port) + " --> code: 111 = Connection refused")
        elif code == 4:
            print("\n[-] " + str(port) + " --> code: 4 = System call interrupted")
        elif code == 13:
            print("\n[-] " + str(port) + " --> code: 13 = Permission denied")
        elif code == 110:
            print("\n[-] " + str(port) + " --> code: 110 = connection timeout")
        else:
            continue

        if port == ports[27]:
            s.close()
            print("\n\n\n|===============[RELATORIO DO SCAN]===============|\n")
            os.system('cat Main_dors.tmp')
            os.system('rm Main_dors.tmp')
            exit(0)


# Scanner de todas portas tcp possíveis
def All_The_Dors():
    ports2 = range(1, 65535)

    for port2 in ports2:
        Connect()

        code = s.connect_ex((sys.argv[1], port2))

        if port2 == 65535:
            s.close()
            exit(0)

        scan2 = open("Scan_Doors_All.txt", 'a')

        if code == 0:
            print("[+] " + str(port2) + " --> code: 0 = Open door\n")
            scan2.write("Portas abertas: " + str(port2) + " Status: Open door\n")

        elif code == 11:
            print("[-] " + str(port2) + " --> code: 11 = Feature temporarily unavailable\n")
        elif code == 111:
            print("[-] " + str(port2) + " --> code: 111 = Connection refused\n")
        elif code == 4:
            print("[-] " + str(port2) + " --> code: 4 = System call interrupted\n")
        elif code == 13:
            print("[-] " + str(port2) + " --> code: 13 = Permission denied\n")
        elif code == 110:
            print("[-] " + str(port2) + " --> code: 110 = Connection timeout\n")
        elif code == 112:
            print("[-] " + str(port2) + " --> code: 112 = Host is disabled\n")
        elif code == 101:
            print("[-] " + str(port2) + " --> code: 101 = The network is inaccessible\n")
        elif code == 93:
            print("[-] " + str(port2) + " --> code: 93 = Unsupported protocol\n")
        elif code == 92:
            print("[-] " + str(port2) + " --> code: 92 = Protocol not available\n")
        elif code == 91:
            print("[-] " + str(port2) + " --> code: 91 = Wrong protocol type for socket\n")

    print("\n|===============[RELATORIO DO SCAN]===============|\n")
    show_open_ports = open("Scan_Doors_All.tmp", 'r')
    show_open_ports_lines = show_open_ports.readlines()
    for port_foud in show_open_ports_lines:
        print(port_foud + '\n')

    exit(0)


# Scanner de portas tcp personalizáveis
def Choice_Of_Dors():
    ports3 = []
    count = 0
    print("ATENÇAO A PORTA NAO PODE FICAR EM BRANCO !!!\n\nDigite 20 portas\n")

    while count != 20:
        ports3.append(int(input("Port :: ")))
        count += 1

    for port3 in ports3:
        Connect()

        code = s.connect_ex((sys.argv[1], port3))

        if code == 0:
            print("[+] " + str(port3) + " --> code: 0 = Open door\n")
        elif code == 11:
            print("[-] " + str(port3) + " --> code: 11 = Feature temporarily unavailable\n")
        elif code == 111:
            print("[-] " + str(port3) + " --> code: 111 = Connection refused\n")
        elif code == 4:
            print("[-] " + str(port3) + " --> code: 4 = System call interrupted\n")
        elif code == 13:
            print("[-] " + str(port3) + " --> code: 13 = Permission denied\n")
        elif code == 110:
            print("[-] " + str(port3) + " --> code: 110 = The network is inaccessible\n")
        elif code == 112:
            print("[-] " + str(port3) + " --> code: 112 = Host esta desativado\n")
        elif code == 101:
            print("[-] " + str(port3) + " --> code: 101 = The network is inaccessible\n")
        elif code == 93:
            print("[-] " + str(port3) + " --> code: 93 = Unsupported protocol\n")
        elif code == 92:
            print("[-] " + str(port3) + " --> code: 92 = Protocol not available\n")
        elif code == 91:
            print("[-] " + str(port3) + " --> code: 91 = Wrong protocol type for socket\n")
        pass


# Web Crawler de links
def Web_Crawler():
    to_crawl = [sys.argv[1]]
    crawled = set()

    header = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                            'AppleWebKit/537.36 (KHTML, like Gecko'
                            'Chrome/51.0.2704.103 Safari/537.36'}

    while True:
        url = to_crawl[0]
        try:
            req = requests.get(url, headers=header)
        except:
            to_crawl.remove(url)
            crawled.add(url)
            continue

        html = req.text
        links = re.findall(r'<a href="?\'?(https?:\/\/[^"\'>]*)', html)
        print('Crawling:', url)

        to_crawl.remove(url)
        crawled.add(url)

        for link in links:
            if link not in crawled and link not in to_crawl:
                to_crawl.append(link)


# Brute-Force de diretórios em aplicação web
def Brute_Force_Dyrectory():
    arquivo = open('common.txt')

    lines = arquivo.readlines()

    header = {'user-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'}

    for line in lines:
        requisicao = requests.get('https://' + sys.argv[1] + "/" + line, headers=header, allow_redirects=False)
        code = requisicao.status_code

        if code == 200:
            print("Foud :: " + 'https://' + sys.argv[1] + '/' + line + 'Code: ' + str(code), '\n')
        elif code == 403:
            print("Forbiden :: " + 'https://' + sys.argv[1] + '/' + line + 'Code: ' + str(code), '\n')
        else:
            continue


# Brute-Force de sub_diretorios
def Sub_Domain():
    argvs = sys.argv

    try:
        domain = argvs[1]
        sub_wordlist = argvs[3]
    except:
        print("Faltam argumentos no comando")
        sys.exit(1)

    try:
        arquivo = open(sub_wordlist)
        lines = arquivo.read().splitlines()
    except:
        print("Arquivo nao encontrao ou invalido")
        sys.exit(1)

    for line in lines:
        subdominio = line + '.' + domain
        try:
            req = dns.resolver.resolve(subdominio, 'a')
            for result in req:
                print(subdominio, result)
        except:
            pass


# Brute Force de serviço FTP
def Brute_Force_Ftp():
    if len(sys.argv) < 6 or sys.argv[3] != "-l" or sys.argv[5] != "-w":
        print("Use > python3.9 stelfdoor.py --ftp 127.0.0.1 -l [USER] -w [WORDLIST]")
        sys.exit()
    else:
        pass

    user: str = sys.argv[4]

    wordlist = open(sys.argv[6])

    for line in wordlist.readlines():
        line: str = line
        Connect()
        print("[.] Testando com Usuario %s com senha :: %s" % (user, line))
        s.connect((sys.argv[1], 21))
        s.recv(1024)
        time.sleep(0.10)
        s.send(b"USER %s\r\n" % user.encode())
        s.recv(1024)
        time.sleep(0.10)
        s.send(b"PASS %s\r\n" % line.encode())
        code = s.recv(1024)
        time.sleep(0.10)
        s.send(b"QUIT\r\n")

        if re.search(r"230", '%s' % code.decode()):
            print("[+] ====> SENHA ENCONTRADA :: %s" % line)
            break
        else:
            s.close()
            continue


# Ping Sweep
def Ping_Sweep():
    def checksum(source_string):
        sum1 = 0
        count_to = (len(source_string) / 2) * 2
        count = 0
        while count < count_to:
            this_val = source_string[count + 1] * 256 + source_string[count]
            sum1 = sum1 + this_val
            sum1 = sum1 & 0xffffffff
            count = count + 2
        if count_to < len(source_string):
            sum1 = sum1 + source_string[len(source_string) - 1]
            sum1 = sum1 & 0xffffffff
        sum1 = (sum1 >> 16) + (sum1 & 0xffff)
        sum1 = sum1 + (sum1 >> 16)
        answer = ~sum1
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def create_packet(id1):
        header = struct.pack('bbHHh', 8, 0, 0, id1, 1)
        data = 192 * 'Q'
        data = data.encode('utf-8')
        my_checksum = checksum(header + data)
        header = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), id1, 1)
        return header + data

    def ping(addr, timeout=1):
        global my_socket
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except Exception as e:
            print(e)
        packet_id = int((id(timeout) * random.random()) % 65535)
        packet = create_packet(packet_id)
        my_socket.connect((addr, 80))
        my_socket.sendall(packet)
        my_socket.close()

    def rotate(addr, file_name1, wait1, responses1):
        print("Sending Packets", time.strftime("%X %x %Z"))
        for ip in addr:
            ping(str(ip))
            time.sleep(wait1)
        print("All packets sent", time.strftime("%X %x %Z"))

        print("Waiting for all responses")
        time.sleep(2)

        # Stoping listen
        global SIGNAL
        SIGNAL = False
        ping('127.0.0.1')  # Final ping to trigger the false signal in listen

        print(len(responses1), "hosts found!")
        print("Writing File")

        for response in sorted(responses1):
            ip = struct.unpack('BBBB', response)
            ip = str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3])
            file = open(file_name1, 'a')
            file.write(str(ip) + '\n')

        print("Done", time.strftime("%X %x %Z"))

    def listen(responses1):
        s2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s2.bind(('', 1))
        print("Listening")
        while SIGNAL:
            packet = s2.recv(1024)[:20][-8:-4]
            responses1.append(packet)
        print("Stop Listening")
        s2.close()

    SIGNAL = True

    responses = []

    ips = str(sys.argv[1]) + '/20'  # Internet network
    wait = 0.002  # Adjust this based in your bandwidth (Faster link is Lower wait)
    file_name = 'log.txt'

    ip_network = ipaddress.ip_network(str(ips), strict=False)

    t_server = Thread(target=listen, args=[responses])
    t_server.start()

    t_ping = Thread(target=rotate, args=[ip_network, file_name, wait, responses])
    t_ping.start()


# Verificaçao de Argumentos
if sys.argv[2] == '-m_T1':
    Main_Dors()
elif sys.argv[2] == '-m_T2':
    Main_Dors()
elif sys.argv[2] == '-m_T3':
    Main_Dors()
elif sys.argv[2] == '-m_T4':
    Main_Dors()
elif sys.argv[2] == '-m_T5':
    Main_Dors()

if sys.argv[2] == '-a_T1':
    All_The_Dors()
elif sys.argv[2] == '-a_T2':
    All_The_Dors()
elif sys.argv[2] == '-a_T3':
    All_The_Dors()
elif sys.argv[2] == '-a_T4':
    All_The_Dors()
elif sys.argv[2] == '-a_T5':
    All_The_Dors()

if sys.argv[2] == '-c_T1':
    Choice_Of_Dors()
if sys.argv[2] == '-c_T2':
    Choice_Of_Dors()
if sys.argv[2] == '-c_T3':
    Choice_Of_Dors()
if sys.argv[2] == '-c_T4':
    Choice_Of_Dors()
if sys.argv[2] == '-c_T5':
    Choice_Of_Dors()

if sys.argv[2] == '--dir':
    Brute_Force_Dyrectory()
if sys.argv[2] == "--ftp":
    Brute_Force_Ftp()
if sys.argv[2] == "--sub":
    Sub_Domain()
if sys.argv[2] == '--help':
    Help()
if sys.argv[2] == '--dev':
    Info()
if sys.argv[2] == '--spider':
    Web_Crawler()
if sys.argv[2] == '--sweep':
    Ping_Sweep()
