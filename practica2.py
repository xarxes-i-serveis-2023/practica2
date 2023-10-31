import socket
import argparse
from struct import pack, unpack



class TFTPController:
    TFPT_OPCODES = {"RRQ": 1, "WRQ": 2, "DATA": 3, "ACK": 4, "ERROR": 5}
    TFPT_MODES = {"octet"}
    
    HEADER_SIZE = 4
    DATA_SIZE = 512
    TIMEOUT = 1
    
    def __init__(self, server_ip: str, port: int) -> None:
        self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = (server_ip, port)


    # RRQ / WRQ
    def send_request(self, opcode: int, filename: str, mode: str = "octet", encoding: str = "utf-8"):  
        # 2 bytes | string | 1 byte | string | 1 byte
        _format=f"!H{len(filename)}sX{len(mode)}sX"
        packet_data = pack(_format, 
            opcode, 
            bytes(filename, encoding), 
            b"\0", 
            bytes(mode, encoding), 
            b"\0")

        self.socket_udp.sendto(packet_data, self.server_address)
        return packet_data

    # DATA
    def send_data(self, block: int, data: bytes): 
        _format=f"!HH{len(data)}s"
        packet_data = pack(_format, self.TFPT_OPCODES["DATA"], block, data)

        self.socket_udp.sendto(packet_data, self.server_address)

    # ACK
    def send_ack(self, block: int):  
        self.socket_udp.sendto(
            pack("!HH", self.TFPT_OPCODES["ACK"], block), self.server_address
        )

    # ERROR
    def send_error(self, code: int, message: str, encoding: str="utf-8"): 
        _format=f"!HH{len(message)}sX"
        
        packet_data = pack(_format, self.TFPT_OPCODES["ERROR"], code, bytes(message, encoding))
        self.socket_udp.sendto(packet_data, self.server_address)


    def receive_packet(self, timeout:int=TIMEOUT):
        self.socket_udp.settimeout(timeout)
        try:
            data, address = self.socket_udp.recvfrom(self.HEADER_SIZE + self.DATA_SIZE)

            return data, address
        except socket.timeout:
            print("Timeout!")
            return None, None
    