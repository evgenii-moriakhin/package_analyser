import threading
import time
from io import BytesIO

import click
import requests
from scapy.sendrecv import AsyncSniffer
from scapy.utils import wrpcap

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
SEND_TIME_INTERVAL = 5  # sec


class CustomBytesIO(BytesIO):
    def close(self) -> None:
        # avoiding auto close with scapy.utils.wrpcap
        ...

    def real_close(self):
        super().close()


class Sniffer:
    def __init__(self, send_to_server: bool, server_host: str, server_port: int):
        self._send_to_server = send_to_server
        self._server_host = server_host
        self._server_port = server_port
        self._lock = threading.Lock()
        self._packets = []
        self._session = requests.Session()

    def run(self):
        t = AsyncSniffer(prn=self.sniffed_packet_callback)
        t.start()
        while True:
            time.sleep(SEND_TIME_INTERVAL)
            self.send_to_server()

    def sniffed_packet_callback(self, packet):
        with self._lock:
            self._packets.append(packet)

    def send_to_server(self):
        with self._lock:
            bytes_io_buffer = CustomBytesIO()
            wrpcap(bytes_io_buffer, self._packets)
            self._packets = []
        bytes_io_buffer.seek(0)
        if self._send_to_server:
            try:
                response = requests.post(
                    f"http://{self._server_host}:{self._server_port}",
                    data=bytes_io_buffer,
                    verify=False,
                )
                response.raise_for_status()
            except requests.exceptions.HTTPError as err:
                print(err)
            else:
                print("send to server")
        else:
            with open("packets.pcap", "a+b") as f:
                f.write(bytes_io_buffer.getbuffer())
        bytes_io_buffer.real_close()


@click.command()
@click.option(
    "--host", default=DEFAULT_HOST, help="Host for server of packet analyser app"
)
@click.option(
    "--port", default=DEFAULT_PORT, help="Host for server of packet analyser app"
)
@click.option("--send", default=1, help="Send package to server")
def main(host: str, port: int, send: int):
    sniffer = Sniffer(bool(send), host, port)
    sniffer.run()


if __name__ == "__main__":
    main()
