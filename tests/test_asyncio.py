import asyncio
import random
import socket
from unittest import TestCase
from unittest.mock import patch

from aioquic.asyncio.client import connect
from aioquic.asyncio.server import QuicServer, serve
from aioquic.configuration import QuicConfiguration

from .utils import SERVER_CERTIFICATE, SERVER_PRIVATE_KEY, run

real_sendto = socket.socket.sendto


def sendto_with_loss(self, data, addr=None):
    """
    Simulate 25% packet loss.
    """
    if random.random() > 0.25:
        real_sendto(self, data, addr)


class SessionTicketStore:
    def __init__(self):
        self.tickets = {}

    def add(self, ticket):
        self.tickets[ticket.ticket] = ticket

    def pop(self, label):
        return self.tickets.pop(label, None)


async def run_client(host, port=4433, request=b"ping", **kwargs):
    async with connect(host, port, **kwargs) as client:
        reader, writer = await client.create_stream()
        assert writer.can_write_eof() is True
        assert writer.get_extra_info("stream_id") == 0

        writer.write(request)
        writer.write_eof()

        return await reader.read()


def handle_stream(reader, writer):
    async def serve():
        data = await reader.read()
        writer.write(bytes(reversed(data)))
        writer.write_eof()

    asyncio.ensure_future(serve())


async def run_server(**kwargs):
    return await serve(
        host="::",
        port="4433",
        certificate=SERVER_CERTIFICATE,
        private_key=SERVER_PRIVATE_KEY,
        stream_handler=handle_stream,
        **kwargs
    )


class HighLevelTest(TestCase):
    def test_connect_and_serve(self):
        server, response = run(asyncio.gather(run_server(), run_client("127.0.0.1")))
        self.assertEqual(response, b"gnip")
        server.close()

    def test_connect_and_serve_large(self):
        """
        Transfer enough data to require raising MAX_DATA and MAX_STREAM_DATA.
        """
        data = b"Z" * 2097152
        server, response = run(
            asyncio.gather(run_server(), run_client("127.0.0.1", request=data))
        )
        self.assertEqual(response, data)
        server.close()

    def test_connect_and_serve_writelines(self):
        async def run_client_writelines(host, port=4433, **kwargs):
            async with connect(host, port, **kwargs) as client:
                reader, writer = await client.create_stream()
                assert writer.can_write_eof() is True

                writer.writelines([b"01234567", b"89012345"])
                writer.write_eof()

                return await reader.read()

        server, response = run(
            asyncio.gather(run_server(), run_client_writelines("127.0.0.1"))
        )
        self.assertEqual(response, b"5432109876543210")
        server.close()

    def test_connect_and_serve_with_connection_handler(self):
        server_conn = None

        def connection_handler(conn):
            nonlocal server_conn
            server_conn = conn

        server, response = run(
            asyncio.gather(
                run_server(connection_handler=connection_handler),
                run_client("127.0.0.1"),
            )
        )
        self.assertEqual(response, b"gnip")
        self.assertIsNotNone(server_conn)
        server.close()

    @patch("socket.socket.sendto", new_callable=lambda: sendto_with_loss)
    def test_connect_and_serve_with_packet_loss(self, mock_sendto):
        """
        This test ensures handshake success and stream data is successfully sent
        and received in the presence of packet loss (randomized 25% in each direction).
        """
        data = b"Z" * 65536
        server, response = run(
            asyncio.gather(
                run_server(idle_timeout=300.0, stateless_retry=True),
                run_client("127.0.0.1", idle_timeout=300.0, request=data),
            )
        )
        self.assertEqual(response, data)
        server.close()

    def test_connect_and_serve_with_session_ticket(self):
        client_ticket = None
        store = SessionTicketStore()

        def save_ticket(t):
            nonlocal client_ticket
            client_ticket = t

        # first request
        server, response = run(
            asyncio.gather(
                run_server(session_ticket_handler=store.add),
                run_client("127.0.0.1", session_ticket_handler=save_ticket),
            )
        )
        self.assertEqual(response, b"gnip")
        server.close()

        self.assertIsNotNone(client_ticket)

        # second request
        server, response = run(
            asyncio.gather(
                run_server(session_ticket_fetcher=store.pop),
                run_client("127.0.0.1", session_ticket=client_ticket),
            )
        )
        self.assertEqual(response, b"gnip")
        server.close()

    def test_connect_and_serve_with_sni(self):
        server, response = run(asyncio.gather(run_server(), run_client("localhost")))
        self.assertEqual(response, b"gnip")
        server.close()

    def test_connect_and_serve_with_stateless_retry(self):
        server, response = run(
            asyncio.gather(run_server(stateless_retry=True), run_client("127.0.0.1"))
        )
        self.assertEqual(response, b"gnip")
        server.close()

    @patch("aioquic.asyncio.server.QuicServer._validate_retry_token")
    def test_connect_and_serve_with_stateless_retry_bad(self, mock_validate):
        mock_validate.side_effect = ValueError("Decryption failed.")

        server = run(run_server(stateless_retry=True))
        with self.assertRaises(ConnectionError):
            run(run_client("127.0.0.1", idle_timeout=4.0))
        server.close()

    def test_connect_and_serve_with_version_negotiation(self):
        server, response = run(
            asyncio.gather(
                run_server(), run_client("127.0.0.1", protocol_version=0x1A2A3A4A)
            )
        )
        self.assertEqual(response, b"gnip")
        server.close()

    def test_connect_timeout(self):
        with self.assertRaises(ConnectionError):
            run(run_client("127.0.0.1", port=4400, idle_timeout=5))

    def test_change_connection_id(self):
        async def run_client_key_update(host, **kwargs):
            async with connect(host, 4433, **kwargs) as client:
                await client.ping()
                client.change_connection_id()
                await client.ping()

        server, _ = run(
            asyncio.gather(
                run_server(stateless_retry=False), run_client_key_update("127.0.0.1")
            )
        )
        server.close()

    def test_key_update(self):
        async def run_client_key_update(host, **kwargs):
            async with connect(host, 4433, **kwargs) as client:
                await client.ping()
                client.request_key_update()
                await client.ping()

        server, _ = run(
            asyncio.gather(
                run_server(stateless_retry=False), run_client_key_update("127.0.0.1")
            )
        )
        server.close()

    def test_ping(self):
        async def run_client_ping(host, **kwargs):
            async with connect(host, 4433, **kwargs) as client:
                await client.ping()
                await client.ping()

        server, _ = run(
            asyncio.gather(
                run_server(stateless_retry=False), run_client_ping("127.0.0.1")
            )
        )
        server.close()


class ServerTest(TestCase):
    def test_retry_token(self):
        addr = ("127.0.0.1", 1234)
        cid = b"\x08\x07\x06\05\x04\x03\x02\x01"

        server = QuicServer(
            configuration=QuicConfiguration(is_client=False), stateless_retry=True
        )

        # create token
        token = server._create_retry_token(addr, cid)
        self.assertIsNotNone(token)

        # validate token - ok
        self.assertEqual(server._validate_retry_token(addr, token), cid)

        # validate token - empty
        with self.assertRaises(ValueError) as cm:
            server._validate_retry_token(addr, b"")
        self.assertEqual(
            str(cm.exception), "Ciphertext length must be equal to key size."
        )

        # validate token - wrong address
        with self.assertRaises(ValueError) as cm:
            server._validate_retry_token(("1.2.3.4", 12345), token)
        self.assertEqual(str(cm.exception), "Remote address does not match.")
