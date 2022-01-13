import os
import select
import socket
import struct
import sys

ICMP_ECHO_REQUEST = 8
TIMEOUT_SECONDS = 5
MAX_TTL = 30

def calculate_checksum(header):
    checksum = 0
    overflow = 0

    for i in range(0, len(header), 2):
        word = header[i] + (header[i + 1] << 8)

        checksum = checksum + word
        overflow = checksum >> 16

        while overflow > 0:
            checksum = checksum & 0xFFFF
            checksum = checksum + overflow
            overflow = checksum >> 16

    overflow = checksum >> 16

    while overflow > 0:
        checksum = checksum & 0xFFFF
        checksum = checksum + overflow
        overflow = checksum >> 16

    checksum = ~checksum
    checksum = checksum & 0xFFFF

    return checksum


def ping(destination_address, icmp_socket, time_to_live, id):
    initial_checksum = 0
    initial_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, initial_checksum, id, 1)

    calculated_checksum = calculate_checksum(initial_header)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, calculated_checksum, id, 1)

    icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, time_to_live)

    icmp_socket.sendto(header, (destination_address, 1))

    socketResponseReady = select.select([icmp_socket], [], [], TIMEOUT_SECONDS)

    if socketResponseReady[0] == []:
        print('{0}: Unknown (timeout)'.format(time_to_live))
        return False

    recv_packet, addr = icmp_socket.recvfrom(1024)

    print('{0}: {1}'.format(time_to_live, addr[0]))

    if addr[0] == destination_address:
        return True

    return False


def main():

    dest_host = input("Enter an address to trace: ")
    destination_address = socket.gethostbyname(dest_host)

    print("Tracing to {0}".format(destination_address))

    time_to_live = 1
    id = 1
    while(time_to_live < MAX_TTL):
        icmp_proto = socket.getprotobyname("icmp")

        try:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
        except socket.error as exception:
            print(exception)
            os._exit(1)

        if (ping(destination_address, icmp_socket, time_to_live, id)):
            icmp_socket.close()
            break

        time_to_live += 1
        id += 1
        icmp_socket.close()

    os._exit(0)


if __name__ == "__main__":
    main()
