"""Aidot client for device communication."""

import asyncio
import base64
import logging
from typing import Any, Optional

import aiohttp
from aiohttp import ClientSession
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .const import (
    CONF_ACCESS_TOKEN,
    CONF_APP_ID,
    CONF_CODE,
    CONF_COUNTRY,
    CONF_DEVICE_LIST,
    CONF_ID,
    CONF_IPADDRESS,
    CONF_PASSWORD,
    CONF_PRODUCT,
    CONF_PRODUCT_ID,
    CONF_REFRESH_TOKEN,
    CONF_REGION,
    CONF_TERMINAL,
    CONF_TOKEN,
    CONF_USERNAME,
    DEFAULT_COUNTRY_NAME,
    SUPPORTED_COUNTRYS,
    ServerErrorCode,
)
from .device_client import DeviceClient
from .discover import Discover
from .exceptions import AidotAuthFailed, AidotUserOrPassIncorrect
from .login_const import APP_ID, BASE_URL, PUBLIC_KEY_PEM

_LOGGER = logging.getLogger(__name__)


def rsa_password_encrypt(message: str) -> str:
    """Encrypt password using RSA public key encryption."""
    public_key: RSAPublicKey = serialization.load_pem_public_key(  # type: ignore[assignment]
        PUBLIC_KEY_PEM, backend=default_backend()
    )

    encrypted = public_key.encrypt(
        message.encode("utf-8"),
        padding.PKCS1v15(),
    )

    return base64.b64encode(encrypted).decode("utf-8")


class AidotClient:
    """Client for communicating with Aidot devices and services."""

    def __init__(
        self,
        session: Optional[ClientSession],
        country_name: str | None = None,
        username: str | None = None,
        password: str | None = None,
        token: dict | None = None,
    ) -> None:
        """Initialize the Aidot client.

        Args:
            session: The aiohttp client session to use for requests
            country_name: Country name for regional API selection
            username: Username for authentication
            password: Password for authentication
            token: Existing token data for authentication
        """
        self.session = session
        self.country_name = country_name or DEFAULT_COUNTRY_NAME
        self.username = username or ""
        self.password = password or ""
        self._base_url = BASE_URL
        self._region = "us"
        self.login_info: dict[str, Any] = {}
        self._device_clients: dict[str, DeviceClient] = {}
        self._discover: Optional[Discover] = None
        self._token_fresh_cb: Optional[Any] = None

        # Set region and base URL based on country
        self._initialize_region()

        # Initialize with existing token if provided
        if token is not None:
            self._initialize_from_token(token)

    def _initialize_region(self) -> None:
        """Initialize region and base URL based on country name."""
        for item in SUPPORTED_COUNTRYS:
            if item["name"] == self.country_name:
                self._region = item["region"].lower()
                self._base_url = f"https://prod-{self._region}-api.arnoo.com/v17"
                break

    def _initialize_from_token(self, token: dict[str, Any]) -> None:
        """Initialize client state from existing token data."""
        self.login_info = token.copy()
        self.username = token[CONF_USERNAME]
        self.password = token[CONF_PASSWORD]
        self._region = token[CONF_REGION]
        self.country_name = token[CONF_COUNTRY]

    def set_token_fresh_cb(self, callback: Any) -> None:
        """Set callback function for token refresh notifications."""
        self._token_fresh_cb = callback

    def get_identifier(self) -> str:
        """Get unique identifier for this client instance."""
        return f"{self._region}-{self.username}"

    def update_password(self, password: str) -> None:
        """Update the password for authentication."""
        self.password = password

    def _get_default_headers(self) -> dict[str, str]:
        """Get default headers for API requests."""
        return {CONF_APP_ID: APP_ID, CONF_TERMINAL: "app"}

    def _get_auth_headers(self) -> dict[str, str]:
        """Get headers with authentication token."""
        token = self.login_info.get(CONF_ACCESS_TOKEN)
        if not token:
            raise AidotAuthFailed("No access token available")
        return {
            CONF_TERMINAL: "app",
            CONF_TOKEN: token,
            CONF_APP_ID: APP_ID,
        }

    async def async_post_login(self) -> dict[str, Any]:
        """Login using username and password credentials.

        Returns:
            Login response data containing tokens and user information

        Raises:
            AidotUserOrPassIncorrect: When credentials are invalid
            AidotAuthFailed: When authentication fails for other reasons
        """
        if not self.session:
            raise AidotAuthFailed("No session available")

        url = f"{self._base_url}/users/loginWithFreeVerification"
        headers = self._get_default_headers()
        data = {
            "countryKey": "region:UnitedStates",
            "username": self.username,
            "password": rsa_password_encrypt(self.password),
            "terminalId": "gvz3gjae10l4zii00t7y0",
            "webVersion": "0.5.0",
            "area": "Asia/Shanghai",
            "UTC": "UTC+8",
        }

        response_data: dict[str, Any] = {}
        try:
            response = await self.session.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()

            self.login_info = response_data.copy()
            self.login_info[CONF_PASSWORD] = self.password
            self.login_info[CONF_REGION] = self._region
            self.login_info[CONF_COUNTRY] = self.country_name
            return self.login_info

        except aiohttp.ClientError as e:
            _LOGGER.info("Login request failed: %s", e)
            code = response_data.get(CONF_CODE)
            if code == ServerErrorCode.USER_PWD_INCORRECT:
                raise AidotUserOrPassIncorrect("Invalid username or password") from e
            raise AidotAuthFailed(f"Login failed: {e}") from e

    async def async_refresh_token(self) -> dict[str, Any]:
        """Refresh the authentication token.

        Returns:
            Token refresh response data

        Raises:
            AidotAuthFailed: When token refresh fails
        """
        if not self.session:
            raise AidotAuthFailed("No session available")

        url = f"{self._base_url}/users/refreshToken"
        headers = self._get_default_headers()
        data = {
            CONF_REFRESH_TOKEN: self.login_info[CONF_REFRESH_TOKEN],
        }

        response_data: dict[str, Any] = {}
        try:
            response = await self.session.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()

            self.login_info[CONF_ACCESS_TOKEN] = response_data[CONF_ACCESS_TOKEN]
            if response_data.get(CONF_REFRESH_TOKEN):
                self.login_info[CONF_REFRESH_TOKEN] = response_data[CONF_REFRESH_TOKEN]

            _LOGGER.debug("Token refreshed successfully")
            if self._token_fresh_cb:
                self._token_fresh_cb()
            return response_data

        except aiohttp.ClientError as e:
            _LOGGER.info("Token refresh failed: %s", e)
            code = response_data.get(CONF_CODE)
            if code == ServerErrorCode.LOGIN_INVALID:
                raise AidotAuthFailed("Login session invalid") from e
            raise AidotAuthFailed(f"Token refresh failed: {e}") from e

    async def async_session_get(
        self, params: str, headers: Optional[dict[str, str]] = None
    ) -> dict[str, Any]:
        """Make authenticated GET request to API.

        Args:
            params: URL path parameters
            headers: Optional custom headers

        Returns:
            API response data

        Raises:
            AidotAuthFailed: When authentication fails or token is invalid
        """
        if not self.session:
            raise AidotAuthFailed("No session available")

        url = f"{self._base_url}{params}"

        if headers is None:
            headers = self._get_auth_headers()

        response_data: dict[str, Any] = {}
        try:
            response = await self.session.get(url, headers=headers)
            response_data = await response.json()
            response.raise_for_status()
            return response_data

        except aiohttp.ClientError as e:
            _LOGGER.info("API request failed: %s", e)
            code = response_data.get(CONF_CODE)

            if code == ServerErrorCode.TOKEN_EXPIRED:
                try:
                    await self.async_refresh_token()
                    return await self.async_session_get(params, headers)
                except AidotAuthFailed:
                    raise
            elif code in (ServerErrorCode.LOGIN_INVALID, 21027, 21041):
                self.login_info[CONF_ACCESS_TOKEN] = None
                raise AidotAuthFailed("Authentication session invalid") from e

            raise AidotAuthFailed(f"API request failed: {e}") from e

    async def async_get_products(self, product_ids: str) -> list[dict[str, Any]]:
        """Get product information for given product IDs.

        Args:
            product_ids: Comma-separated product IDs

        Returns:
            List of product information dictionaries
        """
        params = f"/products/{product_ids}"
        response = await self.async_session_get(params)
        # API returns a list directly for this endpoint
        return response if isinstance(response, list) else []

    async def async_get_devices(self, house_id: str) -> list[dict[str, Any]]:
        """Get device list for a specific house.

        Args:
            house_id: House identifier

        Returns:
            List of device information dictionaries
        """
        params = f"/devices?houseId={house_id}"
        response = await self.async_session_get(params)
        # API returns a list directly for this endpoint
        return response if isinstance(response, list) else []

    async def async_get_houses(self) -> list[dict[str, Any]]:
        """Get list of houses for the authenticated user.

        Returns:
            List of house information dictionaries
        """
        params = "/houses"
        response = await self.async_session_get(params)
        # API returns a list directly for this endpoint
        return response if isinstance(response, list) else []

    async def async_get_all_device(self) -> dict[str, Any]:
        """Get all devices with their product information.

        Returns:
            Dictionary containing device list with product information

        Raises:
            AidotAuthFailed: When authentication fails
        """
        final_device_list: list[dict[str, Any]] = []

        houses = await self.async_get_houses()
        for house in houses:
            device_list = await self.async_get_devices(house[CONF_ID])
            if device_list:
                final_device_list.extend(device_list)

        if final_device_list:
            # Get product information for all devices
            product_ids = ",".join([
                item[CONF_PRODUCT_ID] for item in final_device_list
                if CONF_PRODUCT_ID in item
            ])

            if product_ids:
                product_list = await self.async_get_products(product_ids)

                # Associate product info with devices
                for product in product_list:
                    for device in final_device_list:
                        if device.get(CONF_PRODUCT_ID) == product.get(CONF_ID):
                            device[CONF_PRODUCT] = product

        return {CONF_DEVICE_LIST: final_device_list}

    def get_device_client(self, device: dict[str, Any]) -> DeviceClient:
        """Get or create a device client for the given device.

        Args:
            device: Device information dictionary

        Returns:
            DeviceClient instance for the device
        """
        device_id = device.get(CONF_ID)
        if not device_id:
            raise ValueError("Device ID is required")

        device_client = self._device_clients.get(device_id)
        if device_client is None:
            device_client = DeviceClient(device, self.login_info)
            self._device_clients[device_id] = device_client
            asyncio.get_running_loop().create_task(device_client.ping_task())

        if self._discover is not None:
            ip = self._discover.discovered_device.get(device_id)
            if ip:
                device_client.update_ip_address(ip)
        return device_client

    def start_discover(self) -> None:
        """Start device discovery service."""
        if self._discover is not None:
            return

        def _discover_callback(dev_id: str, event: dict[str, str]) -> None:
            """Handle device discovery events."""
            device_ip = event.get(CONF_IPADDRESS)
            if not device_ip:
                return

            device_client = self._device_clients.get(dev_id)
            if device_client is not None:
                device_client.update_ip_address(device_ip)

        self._discover = Discover(self.login_info, _discover_callback)
        asyncio.get_running_loop().create_task(self._discover.repeat_broadcast())

    def stop_discover(self) -> None:
        """Stop device discovery service."""
        if self._discover is not None:
            self._discover.close()
            self._discover = None

    def cleanup(self) -> None:
        """Clean up all resources and connections."""
        self.stop_discover()
        for client in self._device_clients.values():
            asyncio.get_running_loop().create_task(client.close())
        self._device_clients.clear()
