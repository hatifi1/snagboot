import struct
import unittest
from unittest.mock import MagicMock

from snagrecover.protocols.sl26xx import Sl26xxProtocol


class TestSl26xxProtocol(unittest.TestCase):
	def test_packet_padding_and_header(self):
		port = MagicMock()
		port.write.side_effect = lambda data: len(data)
		port.read.side_effect = [
			b"\x5b\x5a\x00\x00\x04\x00\x00\x00",
			b"\x00\x00\x00\x00",
		]
		Sl26xxProtocol(port)._send_packet(
			Sl26xxProtocol.SERVICE_BOOT,
			Sl26xxProtocol.OP_UPLOAD,
			payload=b"abc",
		)
		packet = port.write.call_args.args[0]
		self.assertEqual(packet[:4], b"\x5b\x5a\x0d\x12")
		inner = packet[8:]
		self.assertEqual(struct.unpack_from("<I", inner, 8)[0], 1)
		self.assertEqual(inner[-4:], b"abc\xff")

	def test_spk_header(self):
		port = MagicMock()
		port.write.side_effect = lambda data: len(data)
		port.read.return_value = b"\x5b\x5a\x00\x00\x00\x00\x00\x00"
		Sl26xxProtocol(port).send_spk(b"image", Sl26xxProtocol.OP_UPLOAD_SPK)
		packet = port.write.call_args.args[0]
		self.assertEqual(packet[:4], b"\x5b\x5a\x33\x02")
		self.assertEqual(struct.unpack_from("<I", packet, 4)[0], 5)

	def test_upload_header_uses_byte_size(self):
		port = MagicMock()
		port.write.side_effect = lambda data: len(data)
		port.read.side_effect = [
			b"\x5b\x5a\x00\x00\x00\x00\x00\x00",
			b"\x5b\x5a\x00\x00\x00\x00\x00\x00",
		]
		payload = b"12345678"
		Sl26xxProtocol(port).upload(payload, Sl26xxProtocol.IMG_SYSMGR, 0xB4A00000, raw=True)
		packet = port.write.call_args_list[0].args[0]
		self.assertEqual(struct.unpack_from("<I", packet, 8)[0], len(payload))

	def test_run_image_does_not_wait_for_disconnect(self):
		port = MagicMock()
		port.write.side_effect = lambda data: len(data)
		Sl26xxProtocol(port).run_image(0xB4A00000)
		port.read.assert_not_called()
