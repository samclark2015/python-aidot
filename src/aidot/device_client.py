"""The aidot integration."""

import asyncio
import ctypes
import json
import logging
import socket
import struct
import time
from datetime import datetime
from typing import Any

from .aes_utils import aes_decrypt, aes_encrypt
from .const import (
    CONF_AES_KEY,
    CONF_ASCNUMBER,
    CONF_ATTR,
    CONF_CCT,
    CONF_DIMMING,
    CONF_HARDWARE_VERSION,
    CONF_ID,
    CONF_IDENTITY,
    CONF_MAC,
    CONF_MAXVALUE,
    CONF_MINVALUE,
    CONF_MODEL_ID,
    CONF_NAME,
    CONF_ON_OFF,
    CONF_PASSWORD,
    CONF_PAYLOAD,
    CONF_PRODUCT,
    CONF_PROPERTIES,
    CONF_RGBW,
    CONF_SERVICE_MODULES,
    Identity,
)
from .exceptions import AidotNotLogin

_LOGGER = logging.getLogger(__name__)


class DeviceStatusData:
    """Device status data container."""

    def __init__(self) -> None:
        self.online: bool = False
        self.on: bool = False
        self.rgdb: int | None = None
        self.rgbw: tuple[int, int, int, int] | None = None
        self.cct: int | None = None
        self.dimming: int | None = None

    def update(self, attr: dict[str, Any] | None) -> None:
        """Update status from attribute dictionary."""
        if attr is None:
            return

        if attr.get(CONF_ON_OFF) is not None:
            self.on = bool(attr.get(CONF_ON_OFF))

        if attr.get(CONF_DIMMING) is not None:
            dimming_value = attr.get(CONF_DIMMING)
            if dimming_value is not None:
                self.dimming = int(dimming_value * 255 / 100)

        if attr.get(CONF_RGBW) is not None:
            self.rgdb = attr.get(CONF_RGBW)
            if self.rgdb is not None:
                rgbw = ctypes.c_uint32(self.rgdb).value
                r = (rgbw >> 24) & 0xFF
                g = (rgbw >> 16) & 0xFF
                b = (rgbw >> 8) & 0xFF
                w = rgbw & 0xFF
                self.rgbw = (r, g, b, w)

        if attr.get(CONF_CCT) is not None:
            self.cct = attr.get(CONF_CCT)


class DeviceInformation:
    """Device information container."""

    def __init__(self, device: dict[str, Any]) -> None:
        self.enable_rgbw: bool = False
        self.enable_dimming: bool = True
        self.enable_cct: bool = False
        self.cct_min: int = 0
        self.cct_max: int = 0

        self.dev_id: str = device.get(CONF_ID) or ""
        self.mac: str = device.get(CONF_MAC) or ""
        self.model_id: str = device.get(CONF_MODEL_ID) or ""
        self.name: str = device.get(CONF_NAME) or ""
        self.hw_version: str = device.get(CONF_HARDWARE_VERSION) or ""

        if CONF_PRODUCT in device and CONF_SERVICE_MODULES in device[CONF_PRODUCT]:
            for service in device[CONF_PRODUCT][CONF_SERVICE_MODULES]:
                if service[CONF_IDENTITY] == Identity.RGBW:
                    self.enable_rgbw = True
                    self.enable_cct = True
                elif service[CONF_IDENTITY] == Identity.CCT:
                    if CONF_PROPERTIES in service and service[CONF_PROPERTIES]:
                        properties = service[CONF_PROPERTIES][0]
                        self.cct_min = int(properties.get(CONF_MINVALUE, 0))
                        self.cct_max = int(properties.get(CONF_MAXVALUE, 0))
                    self.enable_cct = True


class DeviceClient:
    """Client for communicating with Aidot devices."""

    def __init__(self, device: dict[str, Any], user_info: dict[str, Any]) -> None:
        # Instance attributes initialization
        self.status = DeviceStatusData()
        self.info = DeviceInformation(device)
        self.user_id: str = user_info.get(CONF_ID) or ""
        self.discovered = asyncio.Event()

        # Connection state
        self._login_uuid = 0
        self._connect_and_login: bool = False
        self._connecting: bool = False
        self._is_close: bool = False

        # Device info
        self.device_id: str = device.get(CONF_ID) or ""
        self._simple_version: str = device.get("simpleVersion") or ""
        self._ip_address: str | None = None

        # Network objects (initialized in connect)
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

        # Protocol state
        self.ping_count = 0
        self.seq_num = 1
        self.asc_number = 0

        # Encryption
        self.aes_key: bytearray | None = None
        if CONF_AES_KEY in device:
            key_string = device[CONF_AES_KEY][0]
            if key_string is not None:
                self.aes_key = bytearray(16)
                key_bytes = key_string.encode()
                self.aes_key[: len(key_bytes)] = key_bytes

        self.password: str = device.get(CONF_PASSWORD) or ""

    @property
    def connect_and_login(self) -> bool:
        """Return whether device is connected and logged in."""
        return self._connect_and_login

    @property
    def connecting(self) -> bool:
        """Return whether device is currently connecting."""
        return self._connecting

    async def connect(self, ip_address: str) -> None:
        """Connect to device at given IP address."""
        self.reader = self.writer = None
        self._connecting = True
        try:
            self.reader, self.writer = await asyncio.open_connection(ip_address, 10000)
            sock: socket.socket = self.writer.get_extra_info("socket")
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.seq_num = 1
            await self.login()
            self._connect_and_login = True
        except Exception as e:
            self._connect_and_login = False
            _LOGGER.error(
                "Failed to connect to device %s at %s: %s",
                self.device_id,
                ip_address,
                e,
            )
        finally:
            self._connecting = False

    def update_ip_address(self, ip: str) -> None:
        """Update device IP address and signal discovery."""
        self._ip_address = ip
        if ip is not None:
            self.discovered.set()

    async def async_login(self) -> None:
        """Login to device if IP address is available."""
        if self._ip_address is None:
            return
        if not self._connecting and not self._connect_and_login:
            _LOGGER.info(
                "Connecting to device %s at %s", self.info.name, self._ip_address
            )
            await self.connect(self._ip_address)

    def get_send_packet(self, message: bytes, msgtype: int) -> bytes:
        """Create packet for sending to device."""
        magic = struct.pack(">H", 0x1EED)
        _msgtype = struct.pack(">h", msgtype)

        if self.aes_key is not None:
            send_data = aes_encrypt(message, self.aes_key)
        else:
            send_data = message

        bodysize = struct.pack(">i", len(send_data))
        packet = magic + _msgtype + bodysize + send_data

        return packet

    async def login(self) -> None:
        """Login to the device."""
        if self.writer is None or self.reader is None:
            raise RuntimeError("Connection not established")

        login_seq = str(int(time.time() * 1000) + self._login_uuid)[-9:]
        self._login_uuid += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        message = {
            "service": "device",
            "method": "loginReq",
            "seq": login_seq,
            "srcAddr": self.user_id,
            "deviceId": self.device_id,
            "payload": {
                "userId": self.user_id,
                "password": self.password,
                "timestamp": timestamp,
                "ascNumber": 1,
            },
        }
        try:
            self.writer.write(self.get_send_packet(json.dumps(message).encode(), 1))
            await self.writer.drain()
            data = await self.reader.read(1024)
        except (BrokenPipeError, ConnectionResetError) as e:
            _LOGGER.error(f"{self.device_id} login read status error {e}")
            return
        except Exception as e:
            _LOGGER.error(f"recv data error {e}")
            return

        data_len = len(data)
        if data_len <= 0:
            return

        try:
            magic, msgtype, bodysize = struct.unpack(">HHI", data[:8])
            encrypted_data = data[8:]
            if self.aes_key is not None:
                decrypted_data = aes_decrypt(encrypted_data, self.aes_key)
            else:
                decrypted_data = encrypted_data

            json_data = json.loads(decrypted_data)
            _LOGGER.debug(
                "Login response from device %s: %s", self.info.name, json_data
            )
            payload = json_data.get(CONF_PAYLOAD, {})
            self.asc_number = payload.get(CONF_ASCNUMBER, 0)
            self.asc_number += 1
            self.status.online = True
            await self.send_action({}, "getDevAttrReq")
        except Exception as e:
            _LOGGER.error(f"Login response processing error: {e}")

    async def read_status(self) -> DeviceStatusData:
        """Read device status from connection."""
        if not self._connect_and_login:
            await asyncio.sleep(2)
            raise AidotNotLogin

        if self.reader is None:
            _LOGGER.error(f"{self.device_id} reader not available")
            self.status.online = False
            return self.status

        try:
            _LOGGER.debug("Reading status for device %s", self.info.name)
            data = await self.reader.read(1024)
        except (BrokenPipeError, ConnectionResetError) as e:
            _LOGGER.error(f"{self.device_id} read status error {e}")
            await self.reset()
            self.status.online = False
            return self.status
        except Exception as e:
            _LOGGER.error(f"recv data error {e}")
            return self.status

        data_len = len(data)
        if data_len <= 0:
            _LOGGER.error("recv data error len")
            await self.reset()
            self.status.online = False
            return self.status

        try:
            magic, msgtype, bodysize = struct.unpack(">HHI", data[:8])
            if self.aes_key is not None:
                decrypted_data = aes_decrypt(data[8:], self.aes_key)
            else:
                decrypted_data = data[8:]
            json_data = json.loads(decrypted_data)
        except Exception as e:
            _LOGGER.error(f"recv json error : {e}")
            return await self.read_status()

        _LOGGER.debug("Received data from device %s: %s", self.info.name, json_data)
        if "service" in json_data:
            if "test" == json_data["service"]:
                self.ping_count = 0
                return await self.read_status()

        payload = json_data.get(CONF_PAYLOAD)
        if payload is not None:
            _LOGGER.debug("Payload from device %s: %s", self.info.name, payload)
            asc_number = payload.get(CONF_ASCNUMBER)
            if asc_number is not None:
                self.asc_number = asc_number
            self.status.update(payload.get(CONF_ATTR))
        return self.status

    async def ping_task(self) -> None:
        """Background task to ping device periodically."""
        while not self._is_close:
            await asyncio.sleep(5)
            await self.send_ping_action()
            await asyncio.sleep(5)

    async def send_dev_attr(self, dev_attr: dict[str, Any]) -> None:
        """Send device attributes."""
        await self.send_action(dev_attr, "setDevAttrReq")

    async def async_turn_off(self) -> None:
        """Turn device off."""
        await self.send_dev_attr({CONF_ON_OFF: 0})

    async def async_turn_on(self) -> None:
        """Turn device on."""
        await self.send_dev_attr({CONF_ON_OFF: 1})

    async def async_set_brightness(self, brightness: int) -> None:
        """Set device brightness (0-255)."""
        final_dimming = int(brightness * 100 / 255)
        await self.send_dev_attr({CONF_DIMMING: final_dimming})

    async def async_set_rgbw(self, rgbw: tuple[int, int, int, int]) -> None:
        """Set RGBW color values."""
        final_rgbw = (rgbw[0] << 24) | (rgbw[1] << 16) | (rgbw[2] << 8) | rgbw[3]
        await self.send_dev_attr({CONF_RGBW: ctypes.c_int32(final_rgbw).value})

    async def async_set_cct(self, cct: int) -> None:
        """Set color temperature."""
        await self.send_dev_attr({CONF_CCT: cct})

    async def send_action(self, attr: dict[str, Any], method: str) -> None:
        """Send action to device."""
        if self.writer is None:
            _LOGGER.error(f"{self.device_id} writer not available")
            return

        current_timestamp_milliseconds = int(time.time() * 1000)
        self.seq_num += 1
        seq = "ha93" + str(self.seq_num).zfill(5)

        if not self.status.on and CONF_ON_OFF not in attr:
            self.status.on = True
            attr[CONF_ON_OFF] = 1

        if self._simple_version:
            action = {
                "method": method,
                "service": "device",
                "clientId": f"ha-{self.user_id}",
                "srcAddr": f"0.{self.user_id}",
                "seq": seq,
                "payload": {
                    "devId": self.device_id,
                    "parentId": self.device_id,
                    "userId": self.user_id,
                    "password": self.password,
                    "attr": attr,
                    "channel": "tcp",
                    "ascNumber": self.asc_number,
                },
                "tst": current_timestamp_milliseconds,
                "deviceId": self.device_id,
            }
        else:
            action = {
                "method": method,
                "service": "device",
                "seq": seq,
                "srcAddr": f"0.{self.user_id}",
                "payload": {
                    "attr": attr,
                    "ascNumber": self.asc_number,
                },
                "tst": current_timestamp_milliseconds,
                "deviceId": self.device_id,
            }

        try:
            self.writer.write(self.get_send_packet(json.dumps(action).encode(), 1))
            await self.writer.drain()
        except (BrokenPipeError, ConnectionResetError) as e:
            _LOGGER.error(f"{self.device_id} send action error {e}")
            await self.reset()
        except Exception as e:
            _LOGGER.error(f"{self.device_id} send action error {e}")

    async def send_ping_action(self) -> int:
        """Send ping action to device."""
        ping = {
            "service": "test",
            "method": "pingreq",
            "seq": "123456",
            "srcAddr": "x.xxxxxxx",
            CONF_PAYLOAD: {},
        }
        try:
            if self.ping_count >= 2:
                _LOGGER.error(
                    f"Last ping did not return within 20 seconds. device id:{self.device_id}"
                )
                await self.reset()
                return -1

            if not self._connect_and_login:
                return -1

            if self.writer is None:
                _LOGGER.error(f"{self.device_id} writer not available for ping")
                return -1

            self.writer.write(self.get_send_packet(json.dumps(ping).encode(), 2))
            await self.writer.drain()
            self.ping_count += 1
            return 1
        except Exception as e:
            _LOGGER.error(f"{self.device_id} ping error {e}")
            await self.reset()
            return -1

    async def reset(self) -> None:
        """Reset connection state."""
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception as e:
            _LOGGER.error(f"{self.device_id} writer close error {e}")

        self._connect_and_login = False
        self.status.online = False
        self.ping_count = 0
        self.reader = None
        self.writer = None

    async def close(self) -> None:
        """Close connection by user request."""
        self._is_close = True
        await self.reset()
        _LOGGER.info(f"{self.device_id} connect close by user")

    async def async_wait_discovered(self) -> None:
        """Wait for device to be discovered and then login."""
        if not self.discovered.is_set():
            await self.discovered.wait()
        _LOGGER.debug(f"{self.device_id} device discovered")
        # self._is_close = False
        # asyncio.create_task(self.ping_task())
        await self.async_login()
        _LOGGER.info("%s device login complete", self.info.name)
