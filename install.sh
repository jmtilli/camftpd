#!/bin/sh

if [ '!' -x "camftpd" ]; then
  echo "camftpd not made"
  exit 1
fi

PREFIX="$1"

if [ "a$PREFIX" = "a" ]; then
  PREFIX=/usr/local
fi

P="$PREFIX"
H="`hostname`"

if [ '!' -w "$P" ]; then
  echo "No write permissions to $P"
  exit 1
fi
if [ '!' -d "$P" ]; then
  echo "Not a valid directory: $P"
  exit 1
fi

instsbin()
{
  if [ -e "$P/sbin/$1" ]; then
    ln "$P/sbin/$1" "$P/sbin/.$1.cftinstold.$$.$H" || exit 1
  fi
  cp "$1" "$P/sbin/.$1.cftinstnew.$$.$H" || exit 1
  mv "$P/sbin/.$1.cftinstnew.$$.$H" "$P/sbin/$1" || exit 1
  if [ -e "$P/sbin/.$1.cftinstold.$$.$H" ]; then
    # If you mount binaries across NFS, and run this command on the NFS server,
    # you might want to comment out this rm command.
    rm "$P/sbin/.$1.cftinstold.$$.$H" || exit 1
  fi
}

instetcsample()
{
  cp "$1" "$P/etc/.$1.cftinstnew.$$.$H" || exit 1
  mv "$P/etc/.$1.cftinstnew.$$.$H" "$P/etc/$1.sample" || exit 1
}
instsystemd()
{
  cp "$1" "/etc/systemd/system/.$1.cftinstnew.$$.$H" || exit 1
  mv "/etc/systemd/system/.$1.cftinstnew.$$.$H" "/etc/systemd/system/$1" || exit 1
}


# Ensure bin directory is there
mkdir -p "$P/sbin" || exit 1
mkdir -p "$P/etc" || exit 1

instsbin camftpdpwenc
instsbin camftpd
instetcsample startcamftpd.sh

if [ "a$PREFIX" = "a/usr/local" ]; then
  instsystemd camftpd.service
  systemctl daemon-reload
fi

echo "All done, camftpd has been installed to $P"
if [ "a$PREFIX" = "a/usr/local" ]; then
  echo "Systemd service also installed"
fi
echo "Copy $P/etc/startcamftpd.sh.sample to $P/etc/startcamftpd.sh"
if [ "a$PREFIX" = "a/usr/local" ]; then
  echo "Then run systemctl start camftpd.service"
  echo "And maybe systemctl enable camftpd.service"
fi
