# pkgrip
Fast linux alternative for decrypting PS3/PSP pkgs.

pkgrip by qwikrazor87

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

