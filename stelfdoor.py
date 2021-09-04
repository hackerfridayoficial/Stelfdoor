#!/usr/bin/python3.8
# -*- coding: utf-8 -*-

import re
import requests
import sys
import socket
import time
import os


# Ajuda
def Help():
    print("\n[?]--> Help <--[?]\n\nExample: python stelfdoor.py [-ARG] [HOST]\n\n[DOOR SCANNER]\n\n -m -> To scan "
          "main ports\n -a -> To scan all possible ports from 1 to 65535\n -c -> To scan only 20 ports of your "
          "choice\n")
    print("[DIRECTORY SCANNER]\n\n -D -> To search for directories\n")
    print("[BRUTE FORCE ATTACKE - FTP]\n\n --ftp -> With this option it is possible to perform a brute force attack "
          "based on a wordlist containing possible passwords in FTP services\n")


# Desenvolvedor
def Info():
    print("Developer - Matheus Carvalho Da Silva")


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
    print("Digite 20 portas personalizadas\n")

    while count < 20:
        ports3.append(int(input("Digite a porta: ")))

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


# Brute-Force de diretórios em aplicação web
def Brute_Force_Dyrectory():
    arquivo = open('common.txt')

    lines = arquivo.readlines()

    for line in lines:
        requisicao = requests.get(sys.argv[1] + "/" + line)
        code = requisicao.status_code

        if code == 200:
            print(sys.argv[1] + line + 'Code: ' + str(code), '\n')
        elif code == 403:
            print(sys.argv[1] + line + 'Code: ' + str(code), '\n')
        else:
            print("Not Foud" + sys.argv[1] + line + 'Code: ' + str(code), '\n')


# Brute-Force de serviço FTP
def Brute_Force_Ftp():
    if len(sys.argv) < 6 or sys.argv[3] != "-l" or sys.argv[5] != "-w":
        print("Use > python stelfdoor.py --ftp 127.0.0.1 -l ")
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

        if re.search("230", '%s' % code.decode()):
            print("[+] ====> SENHA ENCONTRADA :: %s" % line)
            break
        else:
            s.close()
            continue


# Argumentos
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

if sys.argv[2] == '-h':
    Help()
