# TFTP Client Implementation

This repository contains a Python implementation of a Trivial File Transfer Protocol (TFTP) client based on the specifications outlined in the course "Networks and Services" practice assignment.

## Overview

The TFTP client in this repository is designed to interact with TFTP servers for transferring files using the TFTP protocol. TFTP operates on top of the UDP protocol and is used for simple file transfer scenarios where minimal complexity is desired.

## Features

- Read request (RRQ) to download files from a server
- Write request (WRQ) to upload files to a server
- Proper handling of acknowledgment (ACK) packets
- Error control with appropriate error messages (ERROR packets)
- Supports the end-of-file condition based on TFTP protocol specifications

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before running the TFTP client, ensure you have the following installed:
- Python 3.x
- Access to a TFTP server (local or remote)

### Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/xarxes-i-serveis-2023/practica2.git
cd tftp-client
```

No additional libraries are required beyond the Python Standard Library.

### Usage

To run the TFTP client, execute the `tftp_client.py` script with the appropriate command-line arguments.

For example, to download a file from the server:

```bash
python tftp_client.py -g <filename> -h <server_hostname>
```

To upload a file to the server:

```bash
python tftp_client.py -p <filename> -h <server_hostname>
```

Replace `<filename>` with the name of the file you wish to transfer and `<server_hostname>` with the hostname or IP address of the TFTP server.

## Wireshark Captures

This project includes Wireshark captures demonstrating the packet exchange between the client and the TFTP server. These captures provide insight into the underlying operations of the TFTP protocol.

## Documentation

Please refer to the `memoria.pdf` file for a detailed explanation of the TFTP client implementation, examples of execution, Wireshark captures, and discussion of development challenges.

## Contribution

Contributions are what make the open-source community an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request