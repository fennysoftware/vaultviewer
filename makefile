.DEFAULT_GOAL := build
VERSION=1.0
FILEOUT=vault_viewer
BUILD_DIR=bin
ifeq ($(OS),Windows_NT)
    RM=del /o
    ENVUPDATE=export
    DIRSEP=/
    BINARY=exe
    GOOS=windows
    ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
        GOARCH=amd64
    else
        ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
            GOARCH=amd64       
        endif
    endif
else
    RM=rm -f
    DIRSEP=/
    ENVUPDATE=set
    BINARY=bin
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        GOOS=linux
        UNAME_P := $(shell uname -p)
        ifeq ($(UNAME_P),x86_64)
            GOARCH=amd64
        endif
        ifneq ($(filter %86,$(UNAME_P)),)
            GOARCH=x86
        endif
        ifneq ($(filter arm%,$(UNAME_P)),)
            GOOS=arm
            GOARCH=arm64
        endif
    endif
    ifeq ($(UNAME_S),Darwin)
        GOOS=Darwin
        GOARCH=amd64
    endif
endif

vendor:
	go mod tidy -compat=1.19

clean:
	$(RM) $(BUILD_DIR)$(DIRSEP)*.$(BINARY)

test:
	go test -v .$(DIRSEP)...

#all: setwindows clean setlinux clean setwindowsamd64 buildraw setamd64 setlinux buildraw setdarwin buildraw

build:
	$(ENVUPDATE) GOOS=$(GOOS)
	$(ENVUPDATE) GOARCH=$(GOARCH)
	go build -o $(BUILD_DIR)$(DIRSEP)$(FILEOUT).$(GOOS)-$(GOARCH).$(BINARY)
