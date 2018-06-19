#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "libkirk/aes.h"
#include "libkirk/amctrl.h"
#include "libkirk/kirk_engine.h"

#define PKGRIP_VERSION "1.0"

/* NOTE: only supports files under 4GB */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

char *exec;
char *pkgfile;
u8 public_key[16], static_public_key[16], pkg_key[16], xor_key[16], title_id[10], *pkg_header, *pkg_file_name;
u32 *pkg_file_name_offset, *pkg_file_name_length, *pkg_file_offset, *pkg_file_size, *pkg_is_file, *pkg_entry_type;
u32 pkg_enc_start, pkg_enc_size, pkg_file_count;
int xpsp = 0;
int xps3 = 0;

u8 PSPAESKey[16] = {
	0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C, 0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B
};

u8 PS3AESKey[16] = {
	0x2E, 0x7B, 0x71, 0xD7, 0xC9, 0xC9, 0xA1, 0x4E, 0xA3, 0x22, 0x1F, 0x18, 0x88, 0x28, 0xB8, 0xF8
};

void usage(const char *fmt, ...)
{
	va_list list;
	char msg[256];

	va_start(list, fmt);
	vsprintf(msg, fmt, list);
	va_end(list);

	printf("%s", msg);

	printf("\nUsage:\n\t%s [options] pathtopkg\n\n", exec);
	printf("Options: (optional)\n\t-psp - extract PSP files only\n\t-ps3 - extract PS3 files only\n\tBoth enabled by default.\n\n");
	exit(0);
}

void dumpPS1key(const char *path)
{
	int flag = 2;
	PGD_HEADER PGD;
	memset(&PGD, 0, sizeof(PGD_HEADER));
	MAC_KEY mkey;
	u8 buf[1024];

	kirk_init();

	FILE *fd = fopen(path, "rb");
	fseek(fd, 0x24, 0);
	u32 psar, pgdoff = 0;

	if (fread(&psar, 1, 4, fd)){};
	fseek(fd, psar, 0);
	if (fread(buf, 1, 16, fd)){};

	if (!memcmp(buf, "PSTITLE", 7))
		pgdoff = psar + 0x200;
	else if (!memcmp(buf, "PSISO", 5))
		pgdoff = psar + 0x400;
	else {
		fclose(fd);
		return;
	}

	fseek(fd, pgdoff, 0);
	if (fread(buf, 1, sizeof(buf), fd)){};
	fclose(fd);

	PGD.buf = buf;
	PGD.key_index = *(u32*)(buf + 4);
	PGD.drm_type = *(u32*)(buf + 8);

	// Set the hashing, crypto and open modes.
	if (PGD.drm_type == 1) {
		PGD.mac_type = 1;
		flag |= 4;

		if (PGD.key_index > 1) {
			PGD.mac_type = 3;
			flag |= 8;
		}

		PGD.cipher_type = 1;
	} else {
		PGD.mac_type = 2;
		PGD.cipher_type = 2;
	}

	PGD.open_flag = flag;

	int rt = sceDrmBBMacInit(&mkey, PGD.mac_type);
printf("0x%08X\n", rt);
	rt = sceDrmBBMacUpdate(&mkey, buf, 0x70);
printf("0x%08X\n", rt);
	rt = bbmac_getkey(&mkey, buf + 0x70, PGD.vkey);
printf("0x%08X\n", rt);
	char Path[1024];
	strcpy(Path, path);
	int len = strlen(Path);

	while (Path[len] != '/')
		len--;

	Path[len + 1] = 0;
	strcat(Path, "KEYS.BIN");
	fd = fopen(Path, "wb");
	fwrite(PGD.vkey, 1, 16, fd);
	fclose(fd);
}

void printhex(u8 *buf)
{
	int i;
	for (i = 0; i < 16; i++)
		printf("%02X ", buf[i]);
	printf("\n");
}

u32 tou32(u8 *buf)
{
	return (u32)((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]);
}

void xor128(u8 *dst, u8 *xor1, u8 *xor2)
{
	int i;
	for (i = 0; i < 16; i++)
		dst[i] = xor1[i] ^ xor2[i];
}

void iter128(u8 *buf)
{
	int i;
	for (i = 15; i >= 0; i--) {
		buf[i]++;

		if (buf[i])
			break;
	}
}

void setiter128(u8 *dst, int size)
{
	memcpy(dst, static_public_key, 16);

	int i;
	for (i = 0; i < size; i++)
		iter128(dst);
}

void check_pkg_exist(const char *file)
{
	FILE *fd = fopen(file, "rb");

	if (fd == NULL)
		usage("Could not locate file \"%s\"\n", file);

	fclose(fd);
}

void check_pkg_supported(const char *file)
{
	u8 buf[4];

	FILE *fd = fopen(file, "rb");
	if (fread(buf, 1, sizeof(buf), fd)){};
	fclose(fd);

	if (memcmp(buf, "\x7FPKG", 4))
		usage("Unknown PKG detected!\n");
}

void check_pkg_retail(const char *file)
{
	u8 buf[1];

	FILE *fd = fopen(file, "rb");
	fseek(fd, 4, 0);
	if (fread(buf, 1, sizeof(buf), fd)){};
	fclose(fd);

	if (buf[0] != 0x80)
		usage("Non-retail PKG type detected!\n");
}

void check_pkg_type(const char *file)
{
	u8 buf[1];

	FILE *fd = fopen(file, "rb");
	fseek(fd, 7, 0);
	if (fread(buf, 1, sizeof(buf), fd)){};
	fclose(fd);

	if (buf[0] != 0x01 && buf[0] != 0x02)
		usage("File is not a PS3/PSP PKG!\n");
}

void check_pkg_size(const char *file)
{
	u8 buf[4];
	u32 size, pkgsize;

	FILE *fd = fopen(file, "rb");
	fseek(fd, 0x1C, 0);
	if (fread(buf, 1, sizeof(buf), fd)){};
	pkgsize = tou32(buf);
	fseek(fd, 0x18, 0);
	if (fread(buf, 1, sizeof(buf), fd)){};
	fseek(fd, 0, 2);
	size = ftell(fd);
	fclose(fd);

	if (size != pkgsize)
		usage("Corrupt PKG detected!\ndetected size: %d\nexpected size: %d\n", size, tou32(buf));

	if (tou32(buf))
		usage("PKG size too large, must be less than 4GB (4294967296 bytes)!\n");
}

void get_pkg_info(const char *file)
{
	pkg_header = malloc(0x80);

	FILE *fd = fopen(file, "rb");
	if (fread(pkg_header, 1, 0x80, fd)){};
	fclose(fd);

	memcpy(title_id, pkg_header + 0x37, 9);
	title_id[9] = 0;
	memcpy(public_key, pkg_header + 0x70, 16);
	memcpy(static_public_key, pkg_header + 0x70, 16);

	memcpy(pkg_key, pkg_header[0x07] == 0x01 ? PS3AESKey : PSPAESKey, sizeof(pkg_key));

	pkg_file_count = tou32(pkg_header + 0x14);
	pkg_enc_start = tou32(pkg_header + 0x24);
	pkg_enc_size = tou32(pkg_header + 0x2C);

	pkg_file_name_offset = malloc(pkg_file_count * sizeof(u32));
	pkg_file_name_length = malloc(pkg_file_count * sizeof(u32));
	pkg_file_offset = malloc(pkg_file_count * sizeof(u32));
	pkg_file_size = malloc(pkg_file_count * sizeof(u32));
	pkg_is_file = malloc(pkg_file_count * sizeof(u32));
	pkg_entry_type = malloc(pkg_file_count * sizeof(u32));

	printf("PKG info:\n");
	printf("\tPKG type:       %s\n", pkg_header[0x07] == 0x01 ? "PS3" : "PSP");
	printf("\tContent ID:     %s\n", pkg_header + 0x30);
	printf("\tTitle ID:       %s\n", title_id);
	printf("\tPKG file count: %d\n", pkg_file_count);
	printf("\tPKG size:       %d\n\n", tou32(pkg_header + 0x1C));
}

void extract_pkg(const char *file)
{
	int i, j, extracted = 0;
	u32 MB = 1024 * 1024;
	u8 buf[16], *decbuf = malloc(MB);
	char path[512];
	AES_ctx ctx;
	memset(&ctx, 0, sizeof(AES_ctx));
	AES_set_key(&ctx, pkg_key, AES_KEY_LEN_128);

	sprintf(path, "./%s_dec", title_id);
#ifdef __linux__
	mkdir(path, 0777);
#else
	mkdir(path);
#endif

	FILE *fd = fopen(file, "rb");
	fseek(fd, pkg_enc_start, 0);

	for (i = 0; i < (int)pkg_file_count * 2; i++) {
		if (fread(buf, 1, sizeof(buf), fd)){};

		AES_encrypt(&ctx, public_key, xor_key);
		xor128(buf, buf, xor_key);
		iter128(public_key);

		if (!(i & 1)) {
			pkg_file_name_offset[i / 2] = tou32(buf);
			pkg_file_name_length[i / 2] = tou32(buf + 4);
			pkg_file_offset[i / 2] = tou32(buf + 12);
		} else {
			pkg_file_size[(i - 1) / 2] = tou32(buf + 4);
			pkg_entry_type[(i - 1) / 2] = tou32(buf + 8);
		}
	}

	for (i = 0; i < (int)pkg_file_count; i++) {
		if (!xpsp && (pkg_entry_type[i] >> 24) == 0x90)
			continue;
		if (!xps3 && ((pkg_entry_type[i] >> 24) != 0x90) && ((pkg_entry_type[i] & 0xFF) != 0x04))
			continue;

		int namelength = (pkg_file_name_length[i] + 15) & -16;
		int isfile = !((pkg_entry_type[i] & 0xFF) == 0x04 && !pkg_file_size[i]);
		pkg_file_name = malloc(namelength);
		fseek(fd, pkg_enc_start + pkg_file_name_offset[i], 0);
		if (fread(pkg_file_name, 1, namelength, fd)){};
		setiter128(public_key, pkg_file_name_offset[i] >> 4);
		AES_set_key(&ctx, (pkg_entry_type[i] >> 24) == 0x90 ? PSPAESKey : PS3AESKey, AES_KEY_LEN_128);

		for (j = 0; j < (namelength >> 4); j++) {
			AES_encrypt(&ctx, public_key, xor_key);
			xor128(pkg_file_name + (j * 16), pkg_file_name + (j * 16), xor_key);
			iter128(public_key);
		}

		sprintf(path, "%s_dec/%s", title_id, pkg_file_name);
		char tmpstr[21];
		sprintf(tmpstr, "Extracting %s file:", ((pkg_entry_type[i] >> 24) == 0x90) ? "PSP" : "PS3");
		printf("\n%s\n%s\n", isfile ? tmpstr : "Creating directory:", path);

		if (isfile) {
			u32 szcheck = 0, mincheck = 0;
			FILE *dst = fopen(path, "wb");
			fseek(fd, pkg_enc_start + pkg_file_offset[i], 0);
			if (fread(decbuf, 1, (pkg_file_size[i] >= MB) ? MB : pkg_file_size[i], fd)){};
			setiter128(public_key, pkg_file_offset[i] >> 4);

			printf("%d/%d bytes written\r", 0, pkg_file_size[i]);

			for (j = 0; j < (int)(pkg_file_size[i] >> 4); j++) {
				if (szcheck == MB) {
					szcheck = 0;
					mincheck += MB;
					fwrite(decbuf, 1, MB, dst);
					printf("%d/%d bytes written\r", mincheck, pkg_file_size[i]);
					if (fread(decbuf, 1, ((pkg_file_size[i] - (j << 4)) >= MB) ? MB : pkg_file_size[i] - (j << 4), fd)){};
				}

				AES_encrypt(&ctx, public_key, xor_key);
				xor128(decbuf + ((j << 4) - mincheck), decbuf + ((j << 4) - mincheck), xor_key);
				iter128(public_key);

				szcheck += 16;
			}

			if (mincheck < pkg_file_size[i]) {
				printf("%d/%d bytes written", pkg_file_size[i], pkg_file_size[i]);
				fwrite(decbuf, 1, pkg_file_size[i] - mincheck, dst);
			}

			fclose(dst);
			printf("\n");
			extracted++;

			int pathlen = strlen(path);
			if (!strcmp(path + pathlen - 9, "EBOOT.PBP")) {
				dst = fopen(path, "rb");
				fseek(dst, 0x24, 0);
				u32 psar;
				if (fread(&psar, 1, 4, dst)){};
				fseek(dst, psar, 0);
				u8 block[16];
				if (fread(block, 1, sizeof(block), dst)){};

				if (!memcmp(block, "PSTITLE", 7))
					fseek(dst, psar + 0x200, 0);
				else if (!memcmp(block, "PSISO", 5))
					fseek(dst, psar + 0x400, 0);

				if (fread(block, 1, 4, dst)){};

				if (!memcmp(block, "\x00PGD", 4)) {
					dumpPS1key(path);
					printf("PS1 KEYS.BIN dumped.\n");
					extracted++;
				}

				fclose(dst);
			} else if (!strcmp(path + pathlen - 4, ".PTF")) {
				u8 *pgdbuf = malloc(pkg_file_size[i] - 0x80);
				dst = fopen(path, "rb");
				fseek(dst, 0x80, 0);
				if (fread(pgdbuf, 1, pkg_file_size[i] - 0x80, dst)){};
				fclose(dst);
				kirk_init();
				u32 pgdsize = decrypt_pgd(pgdbuf, pkg_file_size[i] - 0x80, 2, NULL);
				path[pathlen - 4] = 0;
				strcat(path, "_DEC.PTF");
				dst = fopen(path, "wb");
				fwrite(pgdbuf + 0x90, 1, pgdsize, dst);
				fclose(dst);
				printf("PTF theme decrypted.\nDecrypted size: %d bytes\n", pgdsize);
				extracted++;
			}
		} else {
#ifdef __linux__
			mkdir(path, 0777);
#else
			mkdir(path);
#endif
		}

		free(pkg_file_name);
	}

	free(decbuf);
	fclose(fd);

	printf("\nFiles extracted: %d\n", extracted);
}

void free_mallocs()
{
	if (pkg_header)
		free(pkg_header);

	if (pkg_file_name_offset)
		free(pkg_file_name_offset);

	if (pkg_file_name_length)
		free(pkg_file_name_length);

	if (pkg_file_offset)
		free(pkg_file_offset);

	if (pkg_file_size)
		free(pkg_file_size);

	if (pkg_is_file)
		free(pkg_is_file);

	if (pkg_entry_type)
		free(pkg_entry_type);
}

int main(int argc, char **argv)
{
	printf("=================\n== pkgrip v%s == <by qwikrazor87>\n=================\n\n", PKGRIP_VERSION);
	exec = argv[0];

	if (argc < 2)
		usage("");

	int i;
	for (i = 1; i < (argc - 1); i++) {
		if (!strcmp(argv[i], "-psp"))
			xpsp = 1;
		else if (!strcmp(argv[i], "-ps3"))
			xps3 = 1;
	}

	if (!xpsp && !xps3) {
		xpsp = 1;
		xps3 = 1;
	}

	pkgfile = argv[argc - 1];

	check_pkg_exist(pkgfile);
	check_pkg_supported(pkgfile);
	check_pkg_retail(pkgfile);
	check_pkg_type(pkgfile);
	check_pkg_size(pkgfile);
	get_pkg_info(pkgfile);
	extract_pkg(pkgfile);

	free_mallocs();

	return 0;
}

