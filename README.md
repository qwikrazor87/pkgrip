# pkgrip
Fast linux alternative for decrypting PS3/PSP pkgs.

pkgrip by qwikrazor87
<br/>
Modified by TachiCola

## Note from TachiCola

I have modified pkgrip.c to have a larger file size limit.
The pkg size limit pointer has increased from a 32-bit uint.
to a 64-bit uint. The extraction progress readout has been
updated to match. It's not pretty in the slightest, but it
can now handle files larger than 4 GB with no fuss.

I have not tested the effects of this change in depth. All I
know is that it works for its intended purpose with files up
to 16 GB in size.

I hope you find it useful!

## Original README

This is a PC app to decrypt PSP/PS3 pkgs.
It has support for extracting PS1 KEYS.BIN and decrypting PTF themes.
The reason I wrote this is for a native and faster pkg dumping alternative on linux.
Most other pkg decrypters dump the decrypted pkg to a file first before extracting the files.
This app extracts the files directly from the pkg through a small buffer with the exception of KEYS.BIN and PTF themes, which are small.
This app:
	pkg -> buffer -> extracted files.
Other apps:
	pkg -> buffer -> decrypted pkg -> buffer -> extracted files.

Usage:
	pkgrip [options] pathtopkg

Options: (optional)
	-psp - extract PSP files only
	-ps3 - extract PS3 files only
	Both enabled by default when no options are provided.

