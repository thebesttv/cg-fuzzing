# Makefile for generating project-specific 1-run-cov.sh from template

# Find all projects that have cmd.template file
PROJECTS_WITH_CMD := $(shell find . -maxdepth 2 -name "cmd.template" | sed 's|^\./||' | sed 's|/fuzz/cmd.template$$||')

# Generate target list: for each project, we want to generate <proj>/fuzz/1-run-cov.sh
TARGETS := $(addsuffix /fuzz/1-run-cov.sh,$(PROJECTS_WITH_CMD))

.PHONY: all clean list

all: $(TARGETS)

# Rule to generate 1-run-cov.sh from template and cmd.template
%/fuzz/1-run-cov.sh: 1-run-cov.template %/fuzz/cmd.template
	@echo "Generating $@ from template..."
	@sed '/CMD_REPLACE_ME/r $*/fuzz/cmd.template' 1-run-cov.template | \
		sed '/CMD_REPLACE_ME/d' > $@
	@chmod +x $@

# List all projects with cmd.template
list:
	@echo "Projects with cmd.template:"
	@echo $(PROJECTS_WITH_CMD) | tr ' ' '\n'

# Clean generated files
clean:
	@echo "Removing generated 1-run-cov.sh files..."
	@for proj in $(PROJECTS_WITH_CMD); do \
		if [ -f "$$proj/fuzz/1-run-cov.sh" ]; then \
			rm -v "$$proj/fuzz/1-run-cov.sh"; \
		fi; \
	done
