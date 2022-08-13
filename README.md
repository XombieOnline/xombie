Xombie
======

Replacement Original Xbox Live Infrastructure

Notes
-----

**This is a proof of concept!  Some keys are chosen by fair dice rolls,
databases are exposed on default ports with default credentials, etc. Run at
your own risk.**

Running
-------

```docker-compose up -d```

Notes:

Ubuntu 20.04 runs dnsmasq by default.  To disable dnsmasq first disable systemd-resolved with

```$ sudo service systemd-resolved stop```


Then edit systemd's config to remove it by adding ```DNSStubListener=no``` to ```/etc/systemd/resolved.conf```.

Then keep NetworkManager from overwriting your /etc/resolv.conf by adding
```dns=none``` to the ```[main]``` section of ```/etc/NetworkManager/NetworkManager.conf```.

Then remove the symlink to systemctl's ```/etc/resolv.conf``` with 
```$ rm /etc/resolv.conf```

Then write your own resolv.conf containing (for instance to use google's DNS
servers)

```nameserver  8.8.8.8```
