
TARGETS=pam_piv.so

build: $(TARGETS)

pam_piv.so:
	go build -o pam_piv.so -buildmode=c-shared .

clean:
	rm -rf $(TARGETS)

.PHONY: pam_piv.so
