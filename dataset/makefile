# Makefile for generating project-specific scripts from templates

# Find all projects that have cmd.template file
PROJECTS_WITH_CMD := $(shell find . -maxdepth 3 -path "*/fuzz/cmd.template" | sed 's|^\./||' | sed 's|/fuzz/cmd.template$$||')

# Generate target lists
TARGETS_1_RUN_COV := $(addsuffix /fuzz/1-run-cov.sh,$(PROJECTS_WITH_CMD))
TARGETS_2_GEN_BRANCH := $(addsuffix /fuzz/2-gen-branch.sh,$(PROJECTS_WITH_CMD))
TARGETS_3_GEN_UFTRACE := $(addsuffix /fuzz/3-gen-uftrace.sh,$(PROJECTS_WITH_CMD))
TARGETS_COLLECT_BRANCH := $(addsuffix /fuzz/collect-branch.py,$(PROJECTS_WITH_CMD))
TARGETS_UFTRACE_CALLGRAPH := $(addsuffix /fuzz/uftrace-callgraph.py,$(PROJECTS_WITH_CMD))

.PHONY: all clean list

all: $(TARGETS_1_RUN_COV) $(TARGETS_2_GEN_BRANCH) $(TARGETS_3_GEN_UFTRACE) $(TARGETS_COLLECT_BRANCH) $(TARGETS_UFTRACE_CALLGRAPH)

# Rule to generate 1-run-cov.sh from template and cmd.template
%/fuzz/1-run-cov.sh: 1-run-cov.template %/fuzz/cmd.template
	@echo "Generating $@ from template..."
	@perl -pe 'BEGIN{ open $$f, "<", "$(word 2,$^)"; $$c = join("", <$$f>); chomp $$c } s/CMD_REPLACE_ME/$$c/g' $< > $@
	@chmod +x $@

# Rule to generate 2-gen-branch.sh (direct copy, no substitution)
%/fuzz/2-gen-branch.sh: 2-gen-branch.template
	@echo "Generating $@ from template..."
	@cp $< $@
	@chmod +x $@

# Rule to generate 3-gen-uftrace.sh from template and cmd.template
%/fuzz/3-gen-uftrace.sh: 3-gen-uftrace.template %/fuzz/cmd.template
	@echo "Generating $@ from template..."
	@perl -pe 'BEGIN{ open $$f, "<", "$(word 2,$^)"; $$c = join("", <$$f>); chomp $$c } s/CMD_REPLACE_ME/$$c/g' $< > $@
	@chmod +x $@

# Rule to copy collect-branch.py (direct copy)
%/fuzz/collect-branch.py: collect-branch.py
	@echo "Copying $@ from template..."
	@cp $< $@
	@chmod +x $@

# Rule to copy uftrace-callgraph.py (direct copy)
%/fuzz/uftrace-callgraph.py: uftrace-callgraph.py
	@echo "Copying $@ from template..."
	@cp $< $@
	@chmod +x $@

# List all projects with cmd.template
list:
	@echo "Projects with cmd.template:"
	@echo $(PROJECTS_WITH_CMD) | tr ' ' '\n'

# Clean generated files
clean:
	@echo "Removing generated files..."
	@for proj in $(PROJECTS_WITH_CMD); do \
		if [ -f "$$proj/fuzz/1-run-cov.sh" ]; then \
			rm -v "$$proj/fuzz/1-run-cov.sh"; \
		fi; \
		if [ -f "$$proj/fuzz/2-gen-branch.sh" ]; then \
			rm -v "$$proj/fuzz/2-gen-branch.sh"; \
		fi; \
		if [ -f "$$proj/fuzz/3-gen-uftrace.sh" ]; then \
			rm -v "$$proj/fuzz/3-gen-uftrace.sh"; \
		fi; \
		if [ -f "$$proj/fuzz/collect-branch.py" ]; then \
			rm -v "$$proj/fuzz/collect-branch.py"; \
		fi; \
		if [ -f "$$proj/fuzz/uftrace-callgraph.py" ]; then \
			rm -v "$$proj/fuzz/uftrace-callgraph.py"; \
		fi; \
	done
