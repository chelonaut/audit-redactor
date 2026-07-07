IMAGE := audit-redactor:dev

.PHONY: build test run

build:
	docker build -t $(IMAGE) .

test: build
	docker run --rm --entrypoint pytest $(IMAGE) -v

# Usage: make run ARGS="redact /data/input.pdf /data/output.pdf --offline"
# -e ANTHROPIC_API_KEY (bare, no '=value') forwards the variable's current
# value from the invoking shell's environment if set, so the Claude
# augmentation pass can run inside the container without baking a key into
# the image; if it's unset on the host, this is simply a no-op.
run: build
	docker run --rm -e ANTHROPIC_API_KEY -v "$(PWD):/data" $(IMAGE) $(ARGS)
