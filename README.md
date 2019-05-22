

## Building the shim

```
$ go build -o pam_piv.so -buildmode=c-shared *.go
$ make
```

```
sudo mkdir -p /etc/pam-piv
sudo cp config.yaml /etc/pam-piv/config.yaml
sudo cp pam_piv.so /lib/x86_64-linux-gnu/security/
sudo cp pam-config /usr/share/pam-configs/piv
```

## Testing

```
LD_PRELOAD=libpam_wrapper.so \
PAM_WRAPPER=1 \
PAM_WRAPPER_SERVICE_DIR=/home/paultag/pam-test/ \
pamtester -v pamtester paultag authenticate
```
