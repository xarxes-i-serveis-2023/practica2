import logging
import socket
import argparse
import sys
from struct import pack, unpack
from os.path import exists, basename

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)

class TFTPController:
    TFPT_OPCODES = {"RRQ": 1, "WRQ": 2, "DATA": 3, "ACK": 4, "ERROR": 5}
    TFPT_MODES = {"octet"}

    HEADER_SIZE = 4
    DATA_SIZE = 512
    MAX_RETRIES = 3
    TIMEOUT = 1
    
    class Packet:
        code:int
        message:str
        block_number:int
        data:bytes

    class Error(Packet):
        def __init__(self, data: bytes, encoding: str = "utf-8") -> None:
            self.code:int = unpack("!H", data[2:4])[0]
            self.message:str = data[4:].decode(encoding)

    class Ack(Packet):
        def __init__(self, data: bytes) -> None:
            self.block_number:int = unpack("!H", data[2:4])[0]

    class Data(Packet):
        def __init__(self, data: bytes) -> None:
            self.block_number:int = unpack("!H", data[2:4])[0]
            self.data:bytes = data[4:]

    ##########################################################################################

    def __init__(self, server_ip: str, port: int, socket_timeout:float=TIMEOUT) -> None:
        self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_udp.settimeout(socket_timeout) 
        self.server_address = (server_ip, port)
        
        self.logger = logging.getLogger(__name__)

    # RRQ / WRQ
    def send_request(
        self, opcode: int, filename: str, mode: str = "octet", encoding: str = "utf-8"
    ) -> None:
        _format = f"!H{len(filename)}sB{len(mode)}sB"
        self.logger.debug(f"Sending {opcode} request: {filename}; format: {_format}")
        
        packet_data = pack(
            _format,
            opcode,
            bytes(filename, encoding),
            0,
            bytes(mode, encoding),
            0,
        )

        self.socket_udp.sendto(packet_data, self.server_address)

    # DATA
    def send_data(self, block: int, data: bytes) -> None:
        self.logger.debug(f"Sending DATA block_number={block}, data_length={len(data)}")

        _format = f"!HH" # {len(data)}s
        packet_data = pack(_format, self.TFPT_OPCODES["DATA"], block) + data
        
        print(packet_data)

        self.socket_udp.sendto(packet_data, self.server_address)

    # ACK
    def send_ack(self, block: int) -> None:
        self.logger.debug(f"Sending ACK[{block}]")

        self.socket_udp.sendto(
            pack("!HH", self.TFPT_OPCODES["ACK"], block), self.server_address
        )

    ##########################################################################################

    def receive_data(self) -> tuple:
        self.logger.debug("Waiting for packet...")

        for _ in range(self.MAX_RETRIES):
            try:
                return self.socket_udp.recvfrom(self.HEADER_SIZE + self.DATA_SIZE)
            except socket.timeout:
                self.logger.debug("Timeout exceeded!")
            except Exception as e:
                raise e

        self.logger.debug("Max retries exceeded!")
        raise Exception("Max retries exceeded!")

    def transform_data(self, data: bytes):
        self.logger.debug(f"Recieved data size: {len(data)}")
        
        opcode = unpack("!H", data[:2])[0]

        if opcode == self.TFPT_OPCODES["ERROR"]:
            return self.Error(data)
        elif opcode == self.TFPT_OPCODES["ACK"]:
            return self.Ack(data)
        elif opcode == self.TFPT_OPCODES["DATA"]:
            return self.Data(data)
        else:
            raise Exception("Invalid packet!")

    def get_packet(self):
        data, _ = self.receive_data()
        return self.transform_data(data)

    def split_file(self, local_filename: str):
        self.logger.debug(f"Splitting file: {local_filename}")

        splitted_file = []
        try:
            with open(local_filename, "rb") as f:
                while True:
                    data = f.read(self.DATA_SIZE)
                    if not data:
                        break
                    splitted_file.append(data)
            return splitted_file

        except PermissionError:
            raise Exception(f"Permission denied! ({local_filename})")

        except FileNotFoundError:
            raise Exception(f"File not found! ({local_filename})")

        except Exception as e:
            raise e

    def expect_packet(self, block_number: int, packet_type):
        self.logger.debug(f"Expecting {packet_type.__name__.upper()} with block_number = {block_number}")

        answer_packet = self.get_packet()
        if type(answer_packet) is self.Error:
            raise Exception(f"Error[{answer_packet.code}]: {answer_packet.message}")

        elif type(answer_packet) is not packet_type:
            raise Exception(f"Invalid packet received! ({type(answer_packet)})")

        elif answer_packet.block_number != block_number:
            raise Exception(
                f"Invalid block number received! ({answer_packet.block_number}, expeted {block_number})"
            )

        return answer_packet


    def put(self, local_filename: str) -> None:
        if not exists(local_filename):
            raise Exception(f"File '{local_filename}' not found!")

        self.send_request(self.TFPT_OPCODES["WRQ"], local_filename)
        self.expect_packet(0, self.Ack)

        for block_number, data in enumerate(self.split_file(local_filename)): # ,start=1): # SERVER ERROR: Data should start from 1. RFC1350
            self.send_data(block_number, data)

            # SERVER ERROR: first ACK after first DATA, is empty.
            try:
                self.expect_packet(block_number, self.Ack)
            except Exception as e:
                if not block_number==0:
                    raise e

    def get(self, remote_filename: str) -> None:
        self.send_request(self.TFPT_OPCODES["RRQ"], remote_filename)

        block_number = 1
        file_contents = b""

        while True:
            data_packet = self.expect_packet(block_number, self.Data)

            file_contents+=data_packet.data
            self.send_ack(data_packet.block_number)

            if len(data_packet.data) < self.DATA_SIZE:
                break

            block_number = data_packet.block_number + 1
        
        with open(basename(remote_filename), "wb") as f:
            f.write(file_contents)
    
    
    def close(self):
        self.socket_udp.close()
    
if __name__=="__main__":
    t=TFTPController("127.0.0.1", 6969)
    # t.get("as.txt")
    t.put("data.txt")
    t.close()