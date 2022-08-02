import argparse
import pickle

from scapy.compat import raw
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader

from md4 import MD4
import sys
import os, tempfile

import subprocess

def status(*args,**kwargs):
    print(*args,file=sys.stderr,**kwargs)

def retrieve_safety_code(file):
    """
    Retrieve the first PDU with the safety code of a RaSTA packet
    :return:
        rasta_pdu: Hex values of the RaSTA packet PDU
        safety_code: Hex safety code of the RaSTA packet PDU
    """

    try:
        pcap_file = RawPcapReader()
    except FileNotFoundError:
        raise FileNotFoundError('Could not find the pcap file')

    status("Analyzing pcap file for RaSTA traffic and saving data to rasta.p")

    packets = []

    for (data, pkt_metadata,) in pcap_file:
        ether_pkt = Ether(data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type', disregard them
            continue
        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue
        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 17:
            # ignore non-UDP packet
            continue
        udp_pkt = ip_pkt[UDP]

        # todo add more error handling here

        rasta_pkt = raw(udp_pkt.payload)[8:]  # cut out first 8 bytes of redundancy layer
        rasta_pdu = rasta_pkt[:-8].hex()  # packet without safety code
        safety_code = rasta_pkt[-8:].hex()  # last 8 bytes safety code
        pdu = bytes.fromhex(rasta_pdu)

        packets.append({"pdu": pdu, "code": safety_code})

    if not packets:
        status("No RaSTA packets found")
        sys.exit(1)

    data = min(packets,key=lambda packet:len(packet["pdu"]))
    pickle.dump(data, open("rasta.p", "wb"))

    return data["pdu"], data["code"]

def calculate_safety_code(data, iv):
    """
    Calculate the MD4 hash out of the given byte data
    :param data: The data to calculate the hash
    :param iv: The IV for the MD4
    :return: Calculated MD4 hash
    """
    md = MD4()
    md.set_iv(iv)
    md.add(data)
    hexhash = md.finish().hex()
    pdu_hash = hexhash[:16]
    return pdu_hash


def iv_to_msb(iv_string):
    """
    Format a hex string to a list of four decimal values in most significant byte order
    :param iv_string: A hex string (todo how many bytes)
    :return: The formatted IV list for MD4 initialization
    """
    ivlist: list = [iv_string[i:i + 8] for i in range(0, len(iv_string), 8)]
    for i, s in enumerate(ivlist):
        barr = bytearray.fromhex(s)
        sd = bytearray(barr)
        sd.reverse()
        ivlist[i] = int(sd.hex(), 16)
    return ivlist

def run_hashcat(command):
    popen = subprocess.Popen(command, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ""):
        yield stdout_line
    popen.stdout.close()
    return_code = popen.wait()

    if return_code:
        status(f"hashcat failed with error code {return_code}")

if __name__ == "__main__":

    iv_input = '0123456789ABCDEFFEDCBA9876543210'
    #iv_input = sys.stdin.readline()

    if iv_input:
        IV = iv_to_msb(iv_input)
    else:
        IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-f', '--filepath', help='', required=True)
    parser.add_argument('-c', '--hashcat', help='Create hashcat hashes file on stdout', required=False, default=False, action='store_true',dest='hashcat')
    parser.add_argument('-w', '--wordlist', help='Perform hashcat wordlist attack with wordlist <arg>, example: '
                                                 '/tmp/rockyou.txt', required=False, default=False)
    parser.add_argument('-p', '--pattern', help='Perform hashcat pattern attack with pattern <arg>, example: ?a?a ('
                                                'aa-zz)', required=False, default=False)

    args = parser.parse_args()

    try:
        pkt_data = pickle.load(open("rasta.p", "rb"))
        pdu_bytes = pkt_data.get("pdu")
        safe_code = pkt_data.get("code")
    except (OSError, IOError, FileNotFoundError) as e:
        pdu_bytes, safe_code = retrieve_safety_code(args.filepath)

    hashcat_format=f"{pdu_bytes.hex()}${safe_code}"

    pdu_hash = calculate_safety_code(pdu_bytes, IV)

    if pdu_hash == safe_code:
        status("Woop woop hashes are matching!")
        exitcode = 0
    else:
        status("ERROR: Hashes not equal")
        exitcode = 1

    if args.hashcat:
        status("Writing hashcat hashes file to stdout!")
        print(hashcat_format)
    else:
        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            tmp.write(f"{hashcat_format}\n".encode("ascii"))
        finally:
            tmp.close()
            hashes_path = os.path.abspath(tmp.name)
            hashcat_code = 32500 if len(safe_code) == 32 else 32501
            if args.wordlist:
                for output_line in run_hashcat(["hashcat","-m",f"{hashcat_code}","-a0",hashes_path,args.wordlist]):
                    print(output_line,end='')
            if args.pattern:
                for output_line in run_hashcat(["hashcat","-m",f"{hashcat_code}","-a3","-w3",hashes_path,args.pattern]):
                    print(output_line,end='')
            os.unlink(hashes_path)

    sys.exit(exitcode)

