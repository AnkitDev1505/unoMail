#!/bin/sh
# Creates the persistent directories with ownership matching each unprivileged service.
set -eu
umask 077
# A new image can give a service another user id: its files then follow along.
adopt() {
    if [ -d "$2" ] && [ "$(stat -c %u "$2")" != "$(id -u "$1")" ]; then
        chown -R "$1:$1" "$2"
    fi
}
adopt unomail /data/unomail
adopt redis /data/redis
adopt rspamd /data/rspamd
adopt clamav /data/clamav
adopt unomail /data/backups
mkdir -p /data/unomail /data/redis /data/rspamd /data/clamav /run/clamav /run/rspamd /run/redis
chown rspamd:rspamd /run/rspamd && chmod 750 /run/rspamd
chown redis:redis /run/redis && chmod 750 /run/redis
chown unomail:unomail /data/unomail && chmod 700 /data/unomail
# The backup directory the example configuration names; only used when it is switched on.
mkdir -p /data/backups && chown unomail:unomail /data/backups && chmod 700 /data/backups
chown redis:redis /data/redis && chmod 700 /data/redis
chown rspamd:rspamd /data/rspamd
chown clamav:clamav /data/clamav /run/clamav
chown clamav:mailfilter /run/clamav && chmod 750 /run/clamav
chmod 700 /data/clamav /data/rspamd
# Rspamd keeps its statistics and caches here.
rm -rf /var/lib/rspamd && ln -s /data/rspamd /var/lib/rspamd
