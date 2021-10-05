#!/usr/bin/env python3

# imports block begins #
import argparse                                                     # CLI argument parser.
import datetime                                                     # date and time functioanlity.
import re                                                           # regular expression functionality to handle parsing port ranges from CLI.
import socket                                                       # importing socket to make connections for obvious reasons.
import sys                  			                            # system functionality.
import time
# imports block ends #

# constant declaration begins#
commonPorts = [1, 2, 4, 5, 6, 7, 9, 11, 13, 15, 17, 18, 19, 20, 21, 22, 23, 25, 37, 39, 42, 43, 49, 50, 53, 63, 67, 68, 69, 70, 71, 72, 73, 79, 80, 88, 95, 98, 101, 102, 105, 106, 107, 109, 110, 111, 113, 115, 117, 119, 123, 137, 138, 139, 143, 161, 162, 163, 164, 174, 177, 178, 179, 191, 194, 199, 201, 202, 204, 206, 209, 210, 213, 220, 245, 347, 363, 369, 370, 372, 389, 427, 434, 435, 443, 444, 445, 464, 465, 468, 487, 488, 496, 500, 512, 513, 514, 515, 517, 518, 519, 520, 521, 525, 526, 530, 531, 532, 533, 535, 538, 540, 543, 544, 546, 547, 548, 554, 556, 563, 565, 587, 610, 611, 612, 616, 631, 636, 674, 694, 749, 750, 751, 752, 754, 760, 765, 767, 808, 871, 873, 901, 953, 992, 993, 994, 995, 1080, 1109, 1127, 1178, 1236, 1300, 1313, 1433, 1434, 1494, 1512, 1524, 1525, 1529, 1645, 1646, 1649, 1701, 1718, 1719, 1720, 1758, 1759, 1789, 1812, 1813, 1911, 1985, 1986, 1997, 2003, 2049, 2053, 2102, 2103, 2104, 2105, 2150, 2401, 2430, 2431, 2432, 2433, 2600, 2601, 2602, 2603, 2604, 2605, 2606, 2809, 2988, 3128, 3130, 3306, 3346, 3455, 4011, 4321, 4444, 4557, 4559, 5002, 5232, 5308, 5354, 5355, 5432, 5680, 5999, 6000, 6010, 6667, 7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7100, 7666, 8008, 8080, 8081, 9100, 9359, 9876, 10080, 10081, 10082, 10083, 11371, 11720, 13720, 13721, 13722, 13724, 13782, 13783, 20011, 20012, 22273, 22289, 22305, 22321, 24554, 26000, 26208, 27374, 33434, 60177, 60179]
# list derived from https://web.mit.edu/rhel-doc/4/RH-DOCS/rhel-sg-en-4/ch-ports.html
fullRangeString = "1-65535"
# constant declaration ends#

# main function begins #
def main(argv):
    parser = argparse.ArgumentParser(prog="frogscanner", usage="%(prog)s [options] path", description="A toy portscanner written in Python 3.", allow_abbrev=False)
    parser.add_argument("-u", help="target host to scan.", dest="targetHost", type=str, required=True)
    parser.add_argument("-p", help="specified single port or ports to scan. Format: \"-p A, B, C, X-Z\" etc.", dest="targetRangePorts", type=str)
    parser.add_argument("-o", help="output file name. Defaults to \"targetURL/IP_starttime\".", type=str, dest="outputFile")
    parser.add_argument("-t", help="timeout for connection. Defaults to 10 seconds.", type=int, dest="timeout")
    # parse it all #
    args = parser.parse_args(argv)

    targetHost = args.targetHost                                        # set target host from args.
    targetRangePorts = args.targetRangePorts                            # set target port(s) from args.

    if (args.timeout):
        timeout = int(args.timeout)                                     # set timeout from args if exists.
    else:
        timeout = 10                                                    # else default to 10 seconds.
    print("Connection timeout set at {timeout} seconds".format(timeout=timeout))
    if (args.outputFile):
        outputFile = args.outputFile                                    # set output file name.
    else:
        startTime = datetime.datetime.now()
        runTimeString = startTime.strftime("%Y%m%d%H%M%S")
        outputFile = targetHost + "_" + runTimeString + "_" + ".txt"
    
    # start scanning #
    if (args.targetRangePorts == "ALL"):
        portArray = parseRange(fullRangeString)
        print("Scanning all ports on host: {host}".format(host = targetHost))
    elif(args.targetRangePorts == "COMMON"):
        portArray = commonPorts
        print("Scanning common ports on host: {host}".format(host = targetHost))
    else:
        print("Scanning ports {ports} on host: {host}".format(ports = targetRangePorts, host = targetHost))
        portArray = parseRange(args.targetRangePorts)
    for targetPort in portArray:
        portResponse = scanPort(targetHost, targetPort, timeout)
        if (portResponse):
            print(portResponse)
        else:
            print("No response from port: {port}".format(port = targetPort))
    sys.exit(0)
# main function ends #

# port scanner function begins #
def scanPort(targetHost, targetPort, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as testSocket:
        try:
            print("Scanning: {host} on port: {port}".format(host = targetHost, port = targetPort))
            testSocket.settimeout(timeout)
            testSocket.connect((targetHost, targetPort))
            print("Port {port} connected. Sending probe.".format(port = targetPort))
            testSocket.sendall(b'herp')
            portData = testSocket.recv(1024)
            print("Response received from port {port}: {response}".format(port = targetPort, response = repr(portData)))
            return portData
        except Exception as e:
            return False
        finally:
            testSocket.close()
# end scanPort #

# range parser begins #
# stolen from https://stackoverflow.com/a/6415823 #
def parseRange(rangeIn):
    return sum((i if len(i) == 1 else list(range(i[0], i[1]+1))
               for i in ([int(j) for j in i if j] for i in
               re.findall('(\d+),?(?:-(\d+))?', rangeIn))), [])
# range parser ends #

# run main #    
if __name__ == "__main__":
    main(sys.argv[1:])
# main ends#
