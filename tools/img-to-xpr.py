#!/usr/bin/env python3
"""
Tool to convert an image to an 'Xbox Packed Resource' for display on Xbox.
"""
#
# Copyright (c) 2022 Matt Borgerson
#
# Swizzle code derived from swizzle.c
#
# Copyright (c) 2015 Jannik Vogel
# Copyright (c) 2013 espes
# Copyright (c) 2007-2010 The Nouveau Project.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see <http://www.gnu.org/licenses/>.

import ctypes
import argparse
from PIL import Image


def generate_swizzle_masks(width, height, depth):
	x = y = z = 0
	bit = 1
	mask_bit = 1

	done = False
	while not done:
		done = True
		if (bit < width):
			x |= mask_bit
			mask_bit <<= 1
			done = False
		if (bit < height):
			y |= mask_bit
			mask_bit <<= 1
			done = False
		if (bit < depth):
			z |= mask_bit
			mask_bit <<= 1
			done = False
		bit <<= 1

	assert x ^ y ^ z == (mask_bit - 1)
	return x, y, z


def fill_pattern(pattern, value):
	'''
	This fills a pattern with a value if your value has bits abcd and your
	pattern is 11010100100 this will return: 0a0b0c00d00
	'''
	result = 0
	bit = 1
	while (value):
		if (pattern & bit):
			result |= bit if (value & 1) else 0
			value >>= 1
		bit <<= 1
	return result


def get_swizzled_offset(x, y, z, mask_x, mask_y, mask_z):
	return fill_pattern(mask_x, x) | fill_pattern(mask_y, y) | fill_pattern(mask_z, z)


def swizzle_box(src_buf, width, height, depth, dst_buf, row_pitch, slice_pitch):
	mask_x, mask_y, mask_z = generate_swizzle_masks(width, height, depth)
	for z in range(depth):
		for y in range(height):
			for x in range(width):
				dst_buf[get_swizzled_offset(x, y, z, mask_x, mask_y, mask_z)] = src_buf[y * row_pitch + x]
		# src_buf += slice_pitch


class XprImageHeader(ctypes.LittleEndianStructure):
	_pack_ = 1
	_fields_ = [
		# XPR Header
		('magic',       ctypes.c_uint32), # XPR0
		('total_size',  ctypes.c_uint32),
		('header_size', ctypes.c_uint32),
		# D3D Texture
		('common',      ctypes.c_uint32),
		('data',        ctypes.c_uint32),
		('lock',        ctypes.c_uint32),
		('format',      ctypes.c_uint32),
		('size',        ctypes.c_uint32),
		('eoh',         ctypes.c_uint32), # 0xffffffff
		]


def main():
	ap = argparse.ArgumentParser(description='Packs an image into Xbox Packed Resource (XPR) format for loading on Xbox')
	ap.add_argument('input', help='Input image')
	ap.add_argument('output', help='Output file')
	args = ap.parse_args()

	im = Image.open(args.input)
	assert im.width == 64
	assert im.height == 64
	assert im.mode == 'RGBA'

	pixels_in = list(im.getdata())
	pixels_out = [(0, 0, 0, 0) for i in range(im.width*im.height)]
	assert len(pixels_in) == len(pixels_out)
	swizzle_box(pixels_in, im.width, im.height, 1, pixels_out, im.width, 0)
	im.putdata(pixels_out)
	data = im.tobytes('raw', 'BGRA')

	hdr = XprImageHeader()
	hdr.magic = 0x30525058
	hdr.header_size = ctypes.sizeof(hdr)
	hdr.total_size = hdr.header_size + len(data)
	hdr.common = 0x40001
	hdr.data = 0
	hdr.lock = 0
	hdr.format = 0x6610629
	hdr.size = 0
	hdr.eoh = 0xffffffff

	with open(args.output, 'wb') as f:
		f.write(bytes(hdr))
		f.write(data)


if __name__ == '__main__':
	main()
