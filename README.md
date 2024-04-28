# CamFTPD

CamFTPD is a put-only FTP server that doesn't support overwriting old files.
Directories aren't supported, the CWD command is emulated and doesn't actually
do anything. So all files put go to the directory where they are configured to
be put.

The intention is that CamFTPD should be used as the FTP server for surveillance
cameras. For some reason, many surveillance cameras want to use FTP, probably
because we don't have a better protocol. FTP has a vulnerability that
credentials are sent as clear text. An attacker that gains FTP credentials, if
the FTP server is a normal one, could delete all files the surveillance camera
has sent.

CamFTPD solves this vulnerability: since the only operation is a put of a new
file, an attacker can only fabricate false images but never delete anything
that has already been stored. However, do note that an attacker can fill the
disk and cause a denial of service. This is too late, though: once the attacker
has gained physical access to the network connection of the surveillance
camera, images of the attacker has already been stored for evidence, if the
connection is a local connection and doesn't go through an Internet link the
attacker can access nonlocally.

For simplicity, only a single user account is allowed. The password is hashed
using Argon2, but sent to CamFTPD via command line and stored into a world
readable file. The reasoning is that with FTP, snooping passwords is easy
anyway and an attacker needs to gain local access to be able to access the
password hash, so the most realistic attack is snooping the cleartext password
over the wire.

CamFTPD binds only to a single IP address and checks that all client
connections come from the single allowed IP address of the surveillance camera.
Multiple surveillance cameras with their own IP addresses are thus not yet
supported.

## Installation

CamFTPD is built using stirmake. How to build: first install byacc and flex.
Then install stirmake:

```
git clone https://github.com/Aalto5G/stirmake
cd stirmake
git submodule init
git submodule update
cd stirc
make
./install.sh
```

This installs stirmake to `~/.local`. If you want to install to `/usr/local`,
run `./install.sh` by typing `sudo ./install.sh /usr/local` (and you may want
to run `sudo mandb` also).

If the installation told `~/.local` is missing, create it with `mkdir` and try
again. If the installation needed to create `~/.local/bin`, you may need to
re-login for the programs to appear in your `PATH`.

Then build and install CamFTPD by:

```
cd camftpd
git submodule init
git submodule update
smka
./install.sh
```

This installs stirmake to `/usr/local`.

Then run camftpdpwenc, type your password and get its hash.

Then edit /usr/local/etc/startcamftpd.sh.sample and change SRVADDR and CLIADDR
accordingly, and change "ftp" to the Linux account of the user, and change "us"
to the FTP account of the user. Also change the pasword hash and change
/home/ftp to point to the directory where you want the files.

Then change the name /usr/local/etc/startcamftpd.sh.sample into
/usr/local/etc/startcamftpd.sh and run:

```
systemctl start camftpd.service
systemctl enable camftpd.service
```
