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
Install Docker with [Compose](https://github.com/docker/compose/releases). It's recommended to use BuildKit. For this,
set these environment variables (e.g. in your .bashrc):

```bash
COMPOSE_DOCKER_CLI_BUILD=1
DOCKER_BUILDKIT=1
```

When services are brought up for the first time, the database will be initialized from `db.sql`, which contains
hardcoded service IP addresses and a test account. Importantly, check that the IP addresses match expected deployment
configuration.

Build and bring up services with:

```bash
docker compose up --build --detach
```

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

Development
-----------
If you want to use containers for development, but also want incremental builds for a fast workflow, adjust `Dockerfile`
to copy service binaries into place during image build instead of building from scratch. Check `.dockerignore` and make
sure binaries aren't filtered. Then build locally or with another container:

```bash
docker run -it --rm -v $PWD:/work -w /work -eCARGO_HOME=/work/cargo rust:1.62-slim-buster cargo build --release
```

Testing with xemu
-----------------
You can easily create a test network experiment with [xemu](https://xemu.app).

* Create a bridge:
```bash
sudo ip link add br0 type bridge
sudo ip addr add 192.168.5.1/24 dev br0
sudo ip link set br0 up
```
* Edit `docker-compose.yml` to bind to the bridge IP. e.g. replace `88:88/udp` with `192.168.5.1:88:88/udp`
* Start services: `docker compose up --build` (we'll leave out `--detach` to see log messages)
* You can check that the DNS server is responsive with: `dig @192.168.5.1 macs.xboxlive.com`
* Start xemu, enable NAT networking (Settings > Machine > Network)
* In Xbox dashboard, go to network settings and set DNS server to `192.168.5.1`
