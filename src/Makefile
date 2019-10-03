# Copyright 2018 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# --------- General build rules

.PHONY: all
all: fnat46

.PHONY: debug
debug: | .set-debug all

.PHONY: .set-debug
.set-debug:
	$(eval GO_COMPILE_FLAGS := -gcflags=all='-N -l')

.check-downloads:
	go mod download

fnat64: Makefile fnat64.go util.go $(wildcard util/*.go)
	go build $(GO_COMPILE_FLAGS) fnat46.go util.go

.PHONY: clean
clean:
	-rm fnat46

# --------- Utility rules

.PHONY: .check-env
.check-env: 					\
	.check-defined-RTE_TARGET		\
	.check-defined-RTE_SDK			\
	.check-defined-CGO_LDFLAGS_ALLOW	\
	.check-defined-CGO_CFLAGS		\
	.check-defined-CGO_LDFLAGS

.PHONY: .check-defined-%
.check-defined-%:
	@if [ -z '${${*}}' ]; then echo "!!! Variable $* is undefined" && exit 1; fi
