# VulnLab SMB track

## What ships with VulnLab

VulnLab ships a **simulated** SMB service on `127.0.0.1:4450`
(`services/smb_service.py`). It models the same share trees, the same
credentials and the same five challenges (`smb-01` .. `smb-05`) as a real
Samba install, but it speaks a small line protocol instead of SMB2.

Two reasons for the default:

1. **Port 445 collides.** On any Windows workstation the host's own file
   sharing already holds 445, and VulnLab binds 127.0.0.1 only.
2. **`smbclient` speaks SMB2.** On a lab VM you want the real dialect so
   `smbclient -L`, `enum4linux` and `crackmapexec` all behave normally, which
   a line protocol cannot offer.

The simulator is still worth using on Windows: it teaches share enumeration,
null sessions, credential reuse and hidden shares without needing Samba.

## Using the simulator

```
nc 127.0.0.1 4450
```

Commands:

```
negprot                            null (anonymous) session
negprot <user> <pass>              authenticated session
treeconn public                    attach a share  (\\host\share)
treeconn dev$                      attach the unadvertised share
readdir                            list the share
read <file>                        fetch a file
quit
```

Example session:

```
$ nc 127.0.0.1 4450
SMB 3.1.1 VulnLab server - workgroup VULNLAB
smb-01: VULNLAB{smb_enumeration}
negprot svc_backup BackupSmb1!
session setup ok for svc_backup
treeconn backup
connected to \\127.0.0.1\backup
readdir
  id_rsa.pub
  old_backup.txt
read old_backup.txt
smb-03: VULNLAB{smb_old_backup}
```

| share | access | challenge |
| --- | --- | --- |
| `public` | anonymous | `smb-02` |
| `backup` | `svc_backup` / `BackupSmb1!` | `smb-03` |
| `engineering` | `engineering` / `EngBuild2020!` | `smb-04` |
| `dev$` | anonymous, not advertised | `smb-05` |

## Running real Samba instead (Linux lab VM)

The share trees are materialised on disk by `app.py`, so Samba can serve the
exact same content:

```
$ ls data/smb
backup  dev$  engineering  public
```

`/etc/samba/smb.conf`:

```ini
[global]
   workgroup = VULNLAB
   server string = VulnLab file server
   # smb-01 wants enumeration to work without credentials
   guest ok = yes
   map to guest = Bad User
   # smb-05 wants a share that is missing from the share list
   hide unreadable = no

[public]
   path = /opt/vulnlab/data/smb/public
   read only = yes
   guest ok = yes

[backup]
   path = /opt/vulnlab/data/smb/backup
   read only = yes
   valid users = svc_backup

[engineering]
   path = /opt/vulnlab/data/smb/engineering
   read only = yes
   valid users = engineering

[dev$]
   path = /opt/vulnlab/data/smb/dev$
   read only = yes
   guest ok = yes
```

Then create the accounts and start the daemon:

```
sudo useradd -M svc_backup
sudo useradd -M engineering
sudo smbpasswd -a svc_backup
sudo smbpasswd -a engineering
sudo systemctl restart smbd
```

Students then use the tooling they would use on a real engagement:

```
smbclient -L //127.0.0.1 -N
smbclient //127.0.0.1/public -N
smbclient //127.0.0.1/backup -U svc_backup%BackupSmb1!
smbclient //127.0.0.1/dev$ -N
enum4linux 127.0.0.1
```

Turn the simulator off so it does not compete for the student's attention:

```
VULNLAB_PORT_SMB_SIM=4451 python recon_services.py     # move it aside
```

or simply stop `recon_services.py` and run `smbd` instead - the five SMB
challenges live in the share files, not in the simulator.