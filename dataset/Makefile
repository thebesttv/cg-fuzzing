# Makefile for generating project-specific fuzz.sh files from template
# Usage: make update-fuzz-scripts

TEMPLATE := fuzz.sh
PROJECTS := $(sort $(dir $(wildcard */fuzz.dockerfile)))

.PHONY: all update-fuzz-scripts clean help

help:
	@echo "Available targets:"
	@echo "  update-fuzz-scripts  - Generate fuzz.sh for all projects with fuzz.dockerfile"
	@echo "  clean                - Remove all generated fuzz/fuzz.sh files"
	@echo "  help                 - Show this help message"

all: update-fuzz-scripts

update-fuzz-scripts: $(TEMPLATE)
	@echo "Updating fuzz.sh for all projects..."
	@for proj_dir in $(PROJECTS); do \
		proj=$$(basename $$proj_dir); \
		if [ -f "$$proj_dir/afl-cmd.template" ]; then \
			echo "Processing $$proj..."; \
			cmd=$$(cat "$$proj_dir/afl-cmd.template"); \
			mkdir -p "$$proj_dir/fuzz"; \
			sed "s|AFL_CMD_REPLACE_ME|$$cmd|g" $(TEMPLATE) > "$$proj_dir/fuzz/fuzz.sh"; \
			chmod +x "$$proj_dir/fuzz/fuzz.sh"; \
		else \
			echo "Warning: $$proj has fuzz.dockerfile but no afl-cmd.template"; \
		fi; \
	done
	@echo "Done!"

clean:
	@echo "Removing generated fuzz.sh files..."
	@for proj_dir in $(PROJECTS); do \
		if [ -f "$$proj_dir/fuzz/fuzz.sh" ]; then \
			rm -f "$$proj_dir/fuzz/fuzz.sh"; \
			echo "Removed $$proj_dir/fuzz/fuzz.sh"; \
		fi; \
	done
	@echo "Done!"
