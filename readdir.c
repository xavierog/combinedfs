// Dummy program to test whether dirent->d_type was set by the underlying filesystem.

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

const char *pr_d_type(unsigned char d_type) {
	switch (d_type) {
		case DT_BLK: return "DT_BLK";
		case DT_CHR: return "DT_CHR";
		case DT_DIR: return "DT_DIR";
		case DT_FIFO: return "DT_FIFO";
		case DT_LNK: return "DT_LNK";
		case DT_REG: return "DT_REG";
		case DT_SOCK: return "DT_SOCK";
		case DT_UNKNOWN: return "DT_UNKNOWN";
	}
	return "DT_UNKNOWN?";
}

int main(int argc, char **argv) {
	DIR *directory;
	struct dirent *entry;

	if (argc != 2) return 0;

	directory = opendir(argv[1]);
	if (!directory) {
		fprintf(stderr, "Error opening directory %s: %s\n", argv[1], strerror(errno));
		return 2;
	}

	for (;;) {
		errno = 0;
		entry = readdir(directory);
		if (!entry && errno) {
			fprintf(stderr, "Error listing directory %s: %s\n", argv[1], strerror(errno));
			return 1;
		}
		if (!entry) {
			break;
		}
		printf("%d %d %d=%s %s\n", entry->d_ino, entry->d_off, entry->d_type, pr_d_type(entry->d_type), entry->d_name);
	}
	return 0;
}
