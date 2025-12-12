// AFL++ fuzzing harness for Capstone disassembly engine
// Based on Capstone's fuzz_disasm.c but adapted for AFL++ file-based fuzzing

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <capstone/capstone.h>
#include "platform.h"

// Read input from file (AFL++ style)
static uint8_t *read_file(const char *filename, size_t *size)
{
	FILE *f = fopen(filename, "rb");
	if (!f) {
		*size = 0;
		return NULL;
	}

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (fsize < 0 || fsize > 0x1000) {
		// Limit input to 4KB
		fsize = (fsize < 0) ? 0 : 0x1000;
	}

	uint8_t *buffer = malloc(fsize + 1);
	if (!buffer) {
		fclose(f);
		*size = 0;
		return NULL;
	}

	*size = fread(buffer, 1, fsize, f);
	fclose(f);
	
	return buffer;
}

// Main fuzzing function (similar to LLVMFuzzerTestOneInput)
static int fuzz_disasm(const uint8_t *Data, size_t Size)
{
	csh handle;
	cs_insn *all_insn;
	cs_detail *detail;
	cs_err err;
	unsigned int i;

	if (Size < 1) {
		// Need at least 1 byte for arch choice
		return 0;
	} else if (Size > 0x1000) {
		// Limit input to 4KB
		Size = 0x1000;
	}

	// First byte determines the architecture and mode
	i = get_platform_entry((uint8_t)Data[0]);

	err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
	if (err) {
		return 0;
	}

	// Enable detailed instruction info
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	
	// Use ATT syntax if bit 7 is set
	if (Data[0] & 0x80) {
		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	}

	// Disassemble the rest of the data
	uint64_t address = 0x1000;
	size_t count = cs_disasm(handle, Data + 1, Size - 1, address, 0, &all_insn);

	if (count) {
		size_t j;
		unsigned int n;

		for (j = 0; j < count; j++) {
			cs_insn *insn = &(all_insn[j]);
			
			// Access instruction details to exercise more code paths
			detail = insn->detail;

			if (detail) {
				// Read implicit registers
				for (n = 0; n < detail->regs_read_count; n++) {
					cs_reg_name(handle, detail->regs_read[n]);
				}

				// Read modified registers
				for (n = 0; n < detail->regs_write_count; n++) {
					cs_reg_name(handle, detail->regs_write[n]);
				}

				// Read instruction groups
				for (n = 0; n < detail->groups_count; n++) {
					cs_group_name(handle, detail->groups[n]);
				}
			}

			// Get instruction name
			cs_insn_name(handle, insn->id);
		}

		cs_free(all_insn, count);
	}

	cs_close(&handle);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
		return 1;
	}

	size_t size;
	uint8_t *data = read_file(argv[1], &size);
	
	if (!data) {
		// Empty file is ok, just skip
		return 0;
	}

	int ret = fuzz_disasm(data, size);
	
	free(data);
	return ret;
}
