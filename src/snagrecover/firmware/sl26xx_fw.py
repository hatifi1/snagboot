# This file is part of Snagboot
# Copyright (C) 2026 Bootlin
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# of the Free Software Foundation; either version 2 of the License.

from snagrecover.protocols.fastboot import Fastboot
from snagrecover.protocols.sl26xx import Sl26xxProtocol
from snagrecover.utils import cli_error


def sl26xx_run(port, fw_name: str, fw_blob: bytes):
	if fw_name in ("key", "spk", "m52bl", "sysmgr", "bl", "tzk"):
		protocol = Sl26xxProtocol(port)
		if fw_name == "key":
			protocol.send_spk(fw_blob, protocol.OP_UPLOAD_KEY)
		elif fw_name == "spk":
			protocol.send_spk(fw_blob, protocol.OP_UPLOAD_SPK)
		elif fw_name == "m52bl":
			protocol.send_spk(fw_blob, protocol.OP_UPLOAD_M52BL)
		elif fw_name == "sysmgr":
			protocol.upload(fw_blob, protocol.IMG_SYSMGR, protocol.ADDR_SYSMGR, raw=True)
			protocol.run_image(protocol.ADDR_SYSMGR)
		elif fw_name == "bl":
			protocol.upload(fw_blob, protocol.IMG_BL, protocol.ADDR_ACORE)
			protocol.execute()
		else:
			protocol.upload(fw_blob, protocol.IMG_TZK, protocol.ADDR_ACORE)
			protocol.execute(wait=False)
		return

	if fw_name == "uenv":
		fastboot = Fastboot(port)
		fastboot.send(fw_blob)
		fastboot.oem_run("setenv fb_ret OKAY")
		fastboot.oem_run_no_wait("setenv fb_exit 1")
		return

	cli_error(f"unsupported firmware {fw_name}")
