#!/bin/sh

# Default Linux account: ftp
# Default username: "us"
# Default password: "pw"

SRVADDR=127.0.0.1
CLIADDR=127.0.0.1

camftpd /home/ftp "$SRVADDR" "$CLIADDR" ftp us '$argon2id$v=19$m=512,t=4,p=1$SMqxrhHVfAAXCpzB2FZySA$ax7lDCAfbH6zplWJOSd163wa1esxD4qsQqR8JDQ+CBrORGB2Ei8PzfAKgMRkKGrpP6/ApAlgNcjdwuvUQhAJVA'
