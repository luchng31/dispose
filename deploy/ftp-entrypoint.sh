#!/bin/sh
# vsftpd entrypoint: create the dedicated RSAS user from env, expand the
# vsftpd.conf template, then exec vsftpd in the foreground.
set -eu

: "${FTP_USER:?FTP_USER is not set}"
: "${FTP_PASS:?FTP_PASS is not set}"
: "${PASV_ADDRESS:?PASV_ADDRESS must be the host intranet IP (not 127.0.0.1)}"
FTP_UID="${FTP_UID:-1001}"
FTP_GID="${FTP_GID:-1001}"
PASV_MIN_PORT="${PASV_MIN_PORT:-40000}"
PASV_MAX_PORT="${PASV_MAX_PORT:-40100}"

mkdir -p /rsas-drop /var/run/vsftpd/empty /var/log

if ! getent group rsasdrop >/dev/null 2>&1; then
  groupadd -r -g "$FTP_GID" rsasdrop 2>/dev/null || groupadd -r rsasdrop
fi
if ! id "$FTP_USER" >/dev/null 2>&1; then
  useradd -r -m -d /rsas-drop -g rsasdrop -u "$FTP_UID" -s /usr/sbin/nologin "$FTP_USER" 2>/dev/null \
    || useradd -r -m -d /rsas-drop -g rsasdrop -s /usr/sbin/nologin "$FTP_USER"
fi
echo "${FTP_USER}:${FTP_PASS}" | chpasswd
chown "$FTP_USER":rsasdrop /rsas-drop
chmod 755 /rsas-drop

# Only this user may log in.
echo "$FTP_USER" > /etc/vsftpd.userlist
chmod 600 /etc/vsftpd.userlist

# Expand the ${VAR} placeholders in the canonical vsftpd.conf.
sed -e "s|\${PASV_ADDRESS}|${PASV_ADDRESS}|g" \
    -e "s|\${PASV_MIN_PORT}|${PASV_MIN_PORT}|g" \
    -e "s|\${PASV_MAX_PORT}|${PASV_MAX_PORT}|g" \
    /etc/vsftpd.conf.template > /etc/vsftpd.conf
chmod 600 /etc/vsftpd.conf

echo "ftp-ready user=${FTP_USER} pasv=${PASV_ADDRESS}:${PASV_MIN_PORT}-${PASV_MAX_PORT}"
exec /usr/sbin/vsftpd /etc/vsftpd.conf
