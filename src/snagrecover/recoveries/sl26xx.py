# This file is part of Snagboot
# Copyright (C) 2026 Bootlin
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2 of the License.

import logging
import time

import serial
from serial.tools import list_ports

from snagrecover.config import recovery_config
from snagrecover.firmware.firmware import run_firmware
from snagrecover.utils import get_usb

logger = logging.getLogger("snagrecover")

BOOTROM = (0x06CB, 0x019E)
SYSMGR = (0xCAFE, 0x4002)
FASTBOOT = (0x18D1, 0x4EE0)
SERIAL_PORT_TIMEOUT = 5.0


def _find_serial_port(usb_dev) -> str:
	target = f"{usb_dev.bus}-" + "-".join(str(p) for p in usb_dev.port_numbers)
	deadline = time.monotonic() + SERIAL_PORT_TIMEOUT
	while True:
		matches = []
		for info in list_ports.comports():
			if info.vid != usb_dev.idVendor or info.pid != usb_dev.idProduct:
				continue
			if info.location is None or info.location == target or info.location.startswith(
				(target + "-", target + ":")
			):
				matches.append(info.device)
		if len(matches) == 1:
			return matches[0]
		if time.monotonic() >= deadline:
			raise RuntimeError(
				f"expected one CDC serial port for {usb_dev.idVendor:04x}:{usb_dev.idProduct:04x}, "
				f"found {matches}"
			)
		time.sleep(0.05)


def _open_serial(usb_dev):
	path = _find_serial_port(usb_dev)
	logger.info("Opening CDC serial port %s", path)
	return serial.Serial(path, baudrate=230400, bytesize=8, parity="N", stopbits=1, timeout=0.2)


def _wait_for_stage(vid: int, pid: int):
	def ready(dev):
		return dev.idVendor == vid and dev.idProduct == pid

	return get_usb(recovery_config["usb_path"], ready_check=ready)


def _run_serial_stage(usb_dev, name: str) -> None:
	port = _open_serial(usb_dev)
	try:
		run_firmware(port, name)
	finally:
		port.close()


def main():
	usb_dev = _wait_for_stage(*BOOTROM)
	for name in ("key", "spk", "m52bl"):
		_run_serial_stage(usb_dev, name)

	logger.info("Waiting for M52BL re-enumeration...")
	usb_dev = _wait_for_stage(*BOOTROM)
	_run_serial_stage(usb_dev, "sysmgr")

	logger.info("Waiting for SysMgr re-enumeration...")
	usb_dev = _wait_for_stage(*SYSMGR)
	for name in ("bl", "tzk"):
		_run_serial_stage(usb_dev, name)

	logger.info("Waiting for Fastboot re-enumeration...")
	fastboot_dev = _wait_for_stage(*FASTBOOT)
	run_firmware(fastboot_dev, "uenv")
	logger.info("SL26xx U-Boot Fastboot handoff complete")
