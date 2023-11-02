# Python TFTP Client

This repository contains a Python implementation of a TFTP (Trivial File Transfer Protocol) Client that can send (PUT) and receive (GET) files to and from a remote TFTP server.

## Features

- Command-line interface to interact with TFTP server
- Send and receive files using TFTP protocol
- Support for binary (octet) mode transfer
- Built-in logging for transaction progress
- Error handling for common TFTP errors
- Customizable server, port, and timeout settings

## Prerequisites

- Python 3.x

## Installation

To use the TFTP client, you can clone this repository to your local machine:

```sh
git clone https://github.com/xarxes-i-serveis-2023/practica2.git
cd practica2
```

No external Python packages are required, as it only uses modules from the Python Standard Library.

## Usage

The TFTP client is a command-line tool. Below are the options available:

```sh
python tftp_client.py <action> <filename> <server> [options]
```

- `<action>`: The action to perform: 'get' to download a file or 'put' to upload a file.
- `<filename>`: The name of the file to upload or download.
- `<server>`: The IP address or hostname of the TFTP server.
- `-p`, `--port`: (Optional) The port number on the TFTP server (default is 69).
- `-t`, `--timeout`: (Optional) The timeout in seconds for socket operations (default is 1 second).

Example of downloading a file from a TFTP server:

```sh
python3 tftp_client.py get myfile.txt 192.168.1.10
```

Example of uploading a file to a TFTP server:

```sh
python3 tftp_client.py put myfile.txt 192.168.1.10
```

## Logging

This TFTP client is configured with logging to provide informational output on the console. It logs all the essential steps of the file transfer process, including the sending and receiving of packets, and errors.

## Contributions

Contributions are welcome! If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

Don't forget to give the project a star! Thanks again!
