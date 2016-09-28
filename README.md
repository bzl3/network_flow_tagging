# network_flow_tagging

I am testing this on a ubuntu 16.04 VM.

build kernel module by issue command "make" in the project directory.

once the module has been build, insert the module by issuing command "ismod nf_kmod.ko".

check to see if module has been loaded by running:

lsmod | grep nf_kmod

monitor kernel log for any debug information (ubuntu):

tail -f /var/log/kern.log

exit module by running command:

rmmod nf_kmod

## Notes

List of protocol number

http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

skbuff.h

http://lxr.free-electrons.com/source/include/linux/skbuff.h

