IMAGE := audit-redactor:dev

.PHONY: build test run

build:
	docker build -t $(IMAGE) .

test: build
	docker run --rm --entrypoint pytest $(IMAGE) -v

# Usage: make run ARGS="redact /data/input.pdf /data/output.pdf --offline"
run: build
	docker run --rm -v "$(PWD):/data" $(IMAGE) $(ARGS)
