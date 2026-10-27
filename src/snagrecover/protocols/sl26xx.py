# This file is part of Snagboot
# Copyright (C) 2026 Bootlin
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

import logging
import struct
import time

logger = logging.getLogger("snagrecover")


class Sl26xxError(Exception):
	pass


class Sl26xxProtocol:
	SYNC = b"\x5b\x5a"
	SERVICE_BOOT = 0x33
	SERVICE_HOST_API = 0x0D
	OP_VERSION = 0x0A
	OP_RUN_IMAGE = 0x0B
	OP_EXEC = 0x0C
	OP_UPLOAD = 0x12
	OP_UPLOAD_KEY = 0x01
	OP_UPLOAD_SPK = 0x02
	OP_UPLOAD_M52BL = 0x04
	IMG_BL = 0x00020017
	IMG_SYSMGR = 0x00000012
	IMG_TZK = 0x00020014
	ADDR_SYSMGR = 0xB4A00000
	ADDR_ACORE = 0xBA100000
	STREAM_CHUNK = 3 * 1024 * 1024

	def __init__(self, port, timeout: float = 5.0):
		self.port = port
		self.timeout = timeout
		self._rx = bytearray()

	def _read_exact(self, size: int, timeout: float) -> bytes:
		deadline = time.monotonic() + timeout
		while len(self._rx) < size and time.monotonic() < deadline:
			chunk = self.port.read(size - len(self._rx))
			if chunk:
				self._rx.extend(chunk)
			else:
				time.sleep(0.01)
		if len(self._rx) < size:
			raise Sl26xxError(f"timeout waiting for {size} bytes")
		result = bytes(self._rx[:size])
		del self._rx[:size]
		return result

	def _response_code(self, raw: bool, timeout: float) -> int:
		header = self._read_exact(8, timeout)
		if header[:2] != self.SYNC:
			raise Sl26xxError(f"invalid response sync: {header[:2].hex()}")
		if raw:
			return struct.unpack_from("<I", header, 4)[0]
		size = struct.unpack_from("<I", header, 4)[0]
		if size > 4 * 1024 * 1024:
			raise Sl26xxError(f"response payload is too large: {size}")
		payload = self._read_exact(size, timeout)
		if len(payload) < 4:
			raise Sl26xxError("response payload is too short")
		return struct.unpack_from("<I", payload)[0]

	def _write_all(self, data: bytes) -> None:
		offset = 0
		while offset < len(data):
			written = self.port.write(data[offset:])
			if written is None:
				written = len(data) - offset
			if written <= 0:
				raise Sl26xxError("serial write made no progress")
			offset += written

	def _send_packet(
		self,
		service: int,
		opcode: int,
		payload: bytes = b"",
		host_opcode: int = OP_UPLOAD,
		address: int = 0,
		image_type: int = 0,
		raw: bool = False,
		wait: bool = True,
		num_words: int | None = None,
	) -> int:
		padding = (-len(payload)) % 4
		padded = payload + b"\xff" * padding
		inner = struct.pack(
			"<BBBBIIIIIII",
			*self.SYNC,
			service,
			opcode,
			0,
			len(padded) // 4 if num_words is None else num_words,
			0,
			address,
			image_type,
			0,
			0,
		) + padded
		packet = inner if raw else (
			struct.pack(
				"<BBBBI",
				*self.SYNC,
				self.SERVICE_HOST_API,
				host_opcode,
				len(inner),
			)
			+ inner
		)
		self._rx.clear()
		self._write_all(packet)
		return self._response_code(raw, self.timeout) if wait else 0

	def send_spk(self, payload: bytes, opcode: int) -> None:
		header = struct.pack(
			"<BBBBIIIIIII",
			*self.SYNC,
			self.SERVICE_BOOT,
			opcode,
			len(payload),
			0,
			0,
			0,
			0,
			0,
			0,
		)
		self._rx.clear()
		self._write_all(header + payload)
		if self._response_code(True, self.timeout) != 0:
			raise Sl26xxError(f"SPK upload failed, opcode 0x{opcode:02x}")

	def upload(self, payload: bytes, image_type: int, address: int, raw: bool = False) -> None:
		code = self._send_packet(
			self.SERVICE_BOOT,
			self.OP_UPLOAD,
			address=address,
			image_type=image_type,
			raw=raw,
			num_words=len(payload),
		)
		if code != 0:
			raise Sl26xxError(f"upload setup failed: {code}")
		for offset in range(0, len(payload), self.STREAM_CHUNK):
			self._write_all(payload[offset : offset + self.STREAM_CHUNK])
		verify_code = self._response_code(raw, 20.0)
		if verify_code != 0:
			raise Sl26xxError(f"upload verification failed: {verify_code:#x}")

	def run_image(self, address: int) -> None:
		if self._send_packet(
			self.SERVICE_BOOT,
			self.OP_RUN_IMAGE,
			address=address,
			raw=True,
		) != 0:
			raise Sl26xxError("run image failed")

	def execute(self, wait: bool = True) -> None:
		if self._send_packet(
			self.SERVICE_BOOT,
			self.OP_EXEC,
			host_opcode=self.OP_EXEC,
			raw=False,
			wait=wait,
		) != 0:
			raise Sl26xxError("execute failed")
