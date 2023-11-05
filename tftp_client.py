import logging
import socket
import argparse
import sys
from struct import pack, unpack
from os.path import exists, basename
from venv import create

logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)

class TFTPController:
    TFPT_OPCODES = {"RRQ": 1, "WRQ": 2, "DATA": 3, "ACK": 4, "ERROR": 5}

    HEADER_SIZE = 4
    DATA_SIZE = 512
    MAX_RETRIES = 3
    TIMEOUT = 1
    STRING_TERMINATOR = 0

    class Packet:
        code: int
        message: str
        block_number: int
        data: bytes

    class Error(Packet):
        def __init__(self, data: bytes, encoding: str = "utf-8") -> None:
            self.code: int = unpack("!H", data[2:4])[0]
            self.message: str = data[4:].decode(encoding)

    class Ack(Packet):
        def __init__(self, data: bytes) -> None:
            self.block_number: int = unpack("!H", data[2:4])[0]

    class Data(Packet):
        def __init__(self, data: bytes) -> None:
            self.block_number: int = unpack("!H", data[2:4])[0]
            self.data: bytes = data[4:]


    def __init__(self, server_ip: str, port: int, socket_timeout: float = TIMEOUT) -> None:
        self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_udp.settimeout(socket_timeout)
        self.server_address = (server_ip, port)

        self.logger = logging.getLogger(__name__)

    def send_request(self, opcode: int, filename: str, mode: str = "octet", encoding: str = "utf-8") -> None:
        self.logger.info(f"Sending {opcode} request: {filename}")

        packet_data = pack(
            f"!H{len(filename)}sB{len(mode)}sB", opcode, bytes(filename, encoding), self.STRING_TERMINATOR, bytes(mode, encoding), self.STRING_TERMINATOR)

        self.socket_udp.sendto(packet_data, self.server_address)

    def send_data(self, block: int, data: bytes) -> None:
        self.logger.info(f"Sending DATA block_number={block}, data_length={len(data)}")
        packet_data = pack(f"!HH{len(data)}s", self.TFPT_OPCODES["DATA"], block, data)

        self.socket_udp.sendto(packet_data, self.server_address)

    def send_ack(self, block: int) -> None:
        self.logger.info(f"Sending ACK[{block}]")
        self.socket_udp.sendto(pack("!HH", self.TFPT_OPCODES["ACK"], block), self.server_address)

    def receive_data(self) -> tuple:
        self.logger.info("Waiting for packet...")

        for _ in range(self.MAX_RETRIES):
            try:
                return self.socket_udp.recvfrom(self.HEADER_SIZE + self.DATA_SIZE)
            except socket.timeout:
                self.logger.info("Timeout exceeded!")
            except Exception as e:
                raise e

        self.logger.info("Max retries exceeded!")
        raise Exception("Max retries exceeded!")

    def transform_data(self, data: bytes) -> Packet:
        # transform the binary data into a packet object

        self.logger.info(f"Recieved data size: {len(data)}")

        opcode = unpack("!H", data[:2])[0]

        if opcode == self.TFPT_OPCODES["ERROR"]:
            return self.Error(data)
        elif opcode == self.TFPT_OPCODES["ACK"]:
            return self.Ack(data)
        elif opcode == self.TFPT_OPCODES["DATA"]:
            return self.Data(data)
        else:
            raise Exception("Invalid packet!")

    def listen_packet(self)->Packet:
        # wait for UDP answer from the server and return a packet object
        data, _ = self.receive_data()
        return self.transform_data(data)

    def split_file(self, local_filename: str):
        self.logger.info(f"Splitting file: {local_filename}")

        try:
            with open(local_filename, "rb") as f:
                while True:
                    data = f.read(self.DATA_SIZE)
                    if not data: break
                    yield data

        except PermissionError:
            raise Exception(f"Permission denied! ({local_filename})")

        except FileNotFoundError:
            raise Exception(f"File not found! ({local_filename})")

        except Exception as e: raise e

    def expect_packet(self, block_number: int, packet_type):
        # receive a packet and return it. If its not an expected one, throw an exception.
        
        self.logger.info(
            f"Expecting {packet_type.__name__.upper()} with block_number = {block_number}"
        )

        answer_packet = self.listen_packet()
        if type(answer_packet) is self.Error:
            raise Exception(f"ServerError[{answer_packet.code}]: {answer_packet.message}")

        elif type(answer_packet) is not packet_type:
            raise Exception(f"Invalid packet received! ({type(answer_packet)})")

        elif answer_packet.block_number != block_number:
            raise Exception(
                f"Invalid block number received! ({answer_packet.block_number}, expeted {block_number})"
            )

        return answer_packet
    
    def send_slice(self, block_number: int, data: bytes)->None:
        # send a slice of data and wait for ACK. If the ACK is not the expected one, throw an exception.
        
        self.send_data(block_number, data)
        
        # SERVER ERROR: the first ACK after first DATA, it's empty.
        if block_number == 0: return
        
        self.expect_packet(block_number, self.Ack)
    
    def get_slice(self, block_number: int)->Packet:
        data_packet = self.expect_packet(block_number, self.Data)
        self.send_ack(data_packet.block_number)
        
        return data_packet

    def put(self, local_filename: str) -> None:
        # send file to server

        if not exists(local_filename):
            raise Exception(f"File '{local_filename}' not found!")

        self.send_request(self.TFPT_OPCODES["WRQ"], local_filename)
        self.expect_packet(0, self.Ack)

        for block_number, data in enumerate(self.split_file(local_filename)):  # ,start=1): # SERVER ERROR: Data should start from 1. RFC1350
            self.send_slice(block_number, data)
        else:
            if len(data)==self.DATA_SIZE: 
                self.send_slice(block_number+1, b"")
                # file could be exactly multiple of 512 bytes, so we need to send an empty packet to signal the end of the file.

        self.logger.info(f"File uploaded: {local_filename}")

    def get(self, remote_filename: str) -> None:
        # get file from server

        block_number = 1
        
        self.send_request(self.TFPT_OPCODES["RRQ"], remote_filename)
        data_packet = self.get_slice(block_number)

        with open(basename(remote_filename), "wb") as f:
            f.write(data_packet.data)
            
            while True:
                data_packet = self.get_slice(block_number)

                f.write(data_packet.data)
                if len(data_packet.data) < self.DATA_SIZE:
                    break

                block_number += 1
        
        self.logger.info(f"File downloaded: {remote_filename}")

    def close(self):
        self.socket_udp.close()

def create_parser()->argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='TFTP client.')
    parser.add_argument('action', choices=['get', 'put'], help="The action to be performed. 'get' to download a file and 'put' to upload a file.")
    parser.add_argument('filename', help="The name of the file to upload/download.")
    parser.add_argument('server', help="The IP address or hostname of the TFTP server.")
    parser.add_argument('-p', '--port', type=int, default=69, help="The port number of the TFTP server. Default is 69.")
    parser.add_argument('-t', '--timeout', type=float, default=TFTPController.TIMEOUT, help="Socket timeout in seconds. Default is 1 second.")
    
    return parser.parse_args()

if __name__ == "__main__":
    args=create_parser()
    
    client = TFTPController(args.server, args.port, args.timeout)
    try:
        if args.action == "put":
            client.put(args.filename)
        elif args.action == "get":
            client.get(args.filename)
    except Exception as e:
        client.logger.error(e)
    finally: 
        client.close()