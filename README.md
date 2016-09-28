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

##### inserting module 

if you see the below error:

     Required key not available

you will need to disable Secure Boot in UEFI (BIOS) settings by running:

sudo mokutil --disable-validation

It will require to create a password. The password should be at least 8 characters long. After you reboot, UEFI will ask if you want to change security settings. Choose "Yes".

Then you will be asked to enter the previously created password. Some UEFI firmware asks not for the full password, but to enter some characters of it, like 1st, 3rd, etc.



## Notes

List of protocol number

http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

skbuff.h

http://lxr.free-electrons.com/source/include/linux/skbuff.h

