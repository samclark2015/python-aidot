import asyncio
import json
import logging
import os
import socket
import time
from typing import Any

from .aes_utils import aes_decrypt, aes_encrypt
from .const import CONF_ID, CONF_IPADDRESS
from .exceptions import AidotOSError

_LOGGER = logging.getLogger(__name__)
_DISCOVER_TIME = 5
_BROADCAST_PORT = 6666
_BROADCAST_ADDRESS = "255.255.255.255"
_AES_KEY_STRING = "T54uednca587"


class BroadcastProtocol(asyncio.DatagramProtocol):
    """UDP broadcast protocol for device discovery."""

    def __init__(self, callback, user_id: str) -> None:
        super().__init__()
        self._is_closed = False
        self.aes_key = self._create_aes_key()
        self._discover_cb = callback
        self.user_id = user_id
        self.transport = None

    def _create_aes_key(self) -> bytearray:
        """Create AES key from predefined string."""
        aes_key = bytearray(32)
        key_bytes = _AES_KEY_STRING.encode()
        aes_key[: len(key_bytes)] = key_bytes
        return aes_key

    def connection_made(self, transport) -> None:
        """Called when a connection is made."""
        self.transport = transport
        sock: socket.socket = transport.get_extra_info("socket")
        _LOGGER.debug("Discovery listening on: %s", sock.getsockname())
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def send_broadcast(self) -> None:
        """Send a broadcast discovery message."""
        if self._is_closed:
            _LOGGER.error("%s: Connection is closed", self.user_id)
            return

        if self.transport is None:
            _LOGGER.error("%s: Transport not available", self.user_id)
            return

        current_timestamp_milliseconds = int(time.time() * 1000)
        seq = str(current_timestamp_milliseconds + 1)[-9:]
        message = {
            "protocolVer": "2.0.0",
            "service": "device",
            "method": "devDiscoveryReq",
            "seq": seq,
            "srcAddr": f"0.{self.user_id}]",
            "tst": current_timestamp_milliseconds,
            "payload": {
                "extends": {},
                "localCtrFlag": 1,
                "timestamp": str(current_timestamp_milliseconds),
            },
        }
        send_data = aes_encrypt(json.dumps(message).encode(), self.aes_key)
        try:
            self.transport.sendto(send_data, (_BROADCAST_ADDRESS, _BROADCAST_PORT))
        except OSError as error:
            _LOGGER.error("%s: Connection lost due to error: %s", self.user_id, error)

    def datagram_received(self, data, addr) -> None:
        """Process received UDP datagram."""
        _LOGGER.debug("Received %d bytes from %s", len(data), addr)
        try:
            data_str = aes_decrypt(data, self.aes_key)
            data_json = json.loads(data_str)

            if "payload" in data_json and "mac" in data_json["payload"]:
                dev_id = data_json["payload"]["devId"]
                if self._discover_cb:
                    self._discover_cb(dev_id, {CONF_IPADDRESS: addr[0]})
        except (json.JSONDecodeError, KeyError) as error:
            _LOGGER.warning(
                "%s: Failed to parse discovery response: %s", self.user_id, error
            )
        except Exception as error:
            _LOGGER.error(
                "%s: Unexpected error processing discovery response: %s",
                self.user_id,
                error,
            )

    def error_received(self, exc) -> None:
        """Handle protocol errors."""
        _LOGGER.error("%s: Error occurred: %s", self.user_id, exc)

    def close(self) -> None:
        """Close the transport connection."""
        if self.transport is not None:
            try:
                self.transport.close()
            except Exception as error:
                _LOGGER.error("Connection lost due to error: %s", error)

    def connection_lost(self, exc) -> None:
        """Called when connection is lost."""
        self._is_closed = True
        if exc:
            _LOGGER.error("%s: Connection lost due to error: %s", self.user_id, exc)
        else:
            _LOGGER.info("%s: Connection closed", self.user_id)


class Discover:
    """Device discovery service using UDP broadcast."""

    def __init__(self, login_info: dict[str, Any], callback=None) -> None:
        self._login_info = login_info
        self._callback = callback
        self._port = int(os.environ.get("AIDOT_DISCOVER_PORT", "0"))
        self._broadcast_protocol: BroadcastProtocol | None = None
        self.discovered_device: dict[str, str] = {}
        self._is_close = False

    async def try_create_broadcast(self) -> None:
        """Create broadcast protocol if not already created."""
        if self._broadcast_protocol is None:
            try:
                (
                    transport,
                    protocol,
                ) = await asyncio.get_event_loop().create_datagram_endpoint(
                    lambda: BroadcastProtocol(
                        self._discover_callback, self._login_info[CONF_ID]
                    ),
                    local_addr=("0.0.0.0", self._port),
                )
                # Store the actual protocol instance returned
                self._broadcast_protocol = protocol
            except OSError as error:
                raise AidotOSError from error

    async def send_broadcast(self) -> None:
        """Send a single broadcast message."""
        await self.try_create_broadcast()
        if self._broadcast_protocol is not None:
            self._broadcast_protocol.send_broadcast()

    async def repeat_broadcast(self) -> None:
        """Continuously send broadcast messages until stopped."""
        self._is_close = False
        while not self._is_close:
            await self.send_broadcast()
            for _ in range(_DISCOVER_TIME):
                await asyncio.sleep(1)
                if self._is_close:
                    return

    async def fetch_devices_info(self) -> dict[str, str]:
        """Fetch device information by sending broadcast and waiting."""
        await self.try_create_broadcast()
        if self._broadcast_protocol is not None:
            self._broadcast_protocol.send_broadcast()
        await asyncio.sleep(2)
        return self.discovered_device

    def _discover_callback(self, dev_id: str, event: dict[str, str]) -> None:
        """Handle discovered device callback."""
        self.discovered_device[dev_id] = event[CONF_IPADDRESS]
        if self._callback:
            self._callback(dev_id, event)

    def close(self) -> None:
        """Close the discovery service."""
        self._is_close = True
        if self._broadcast_protocol is not None:
            self._broadcast_protocol.close()
            self._broadcast_protocol = None
