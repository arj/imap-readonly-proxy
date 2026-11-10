#!/usr/bin/env bash
# Runs the end-to-end tests against a throwaway Dovecot instance.
# Requires: dovecot (2.4+), go. Runs entirely on 127.0.0.1 as the current user.
set -euo pipefail

cd "$(dirname "$0")/../.."
DV_VERSION="${IRP_DOVECOT_VERSION:-$(dovecot --version | grep -oE "^[0-9]+\.[0-9]+\.[0-9]+")}"
PORT="${IRP_E2E_PORT:-10143}"
WORK="$(mktemp -d)"
U="$(id -un)"
G="$(id -gn)"
trap 'kill "$(cat "$WORK/run/master.pid" 2>/dev/null)" 2>/dev/null || true; rm -rf "$WORK"' EXIT

mkdir -p "$WORK"/{run,state,home}
cat >"$WORK/dovecot.conf" <<EOF
dovecot_config_version = $DV_VERSION
dovecot_storage_version = $DV_VERSION
base_dir = $WORK/run
state_dir = $WORK/state
log_path = $WORK/dovecot.log
default_internal_user = $U
default_internal_group = $G
default_login_user = $U
protocols = imap
listen = 127.0.0.1
ssl = no
auth_allow_cleartext = yes
mail_driver = maildir
mail_path = $WORK/mail/%{user}
mail_home = $WORK/home/%{user}
first_valid_uid = 0
passdb passwd-file {
  passwd_file_path = $WORK/passwd
}
userdb static {
  fields {
    uid = $U
    gid = $G
    home = $WORK/home/%{user}
  }
}
service imap-login {
  inet_listener imap {
    port = $PORT
  }
  inet_listener imaps {
    port = 0
  }
}
service anvil {
  chroot =
}
service imap-login {
  chroot =
}
namespace inbox {
  inbox = yes
  separator = /
  mailbox Drafts {
    auto = subscribe
  }
  mailbox Secret {
    auto = create
  }
  mailbox Reports {
    auto = create
  }
}
EOF
echo "alice:{PLAIN}alicepw::::::" >"$WORK/passwd"

# Seed mailboxes: INBOX with 3 messages, Secret with 1, Drafts empty.
M="$WORK/mail/alice"
mkdir -p "$M"/{cur,new,tmp} "$M"/.Drafts/{cur,new,tmp} "$M"/.Secret/{cur,new,tmp} "$M"/.Reports/{cur,new,tmp}
msg() { printf 'From: a@example.com\r\nTo: b@example.com\r\nSubject: %s\r\nDate: Mon, 9 Nov 2026 10:00:00 +0100\r\nMessage-ID: <%s@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n' "$1" "$2" "$3"; }
msg "Message 1" m1 "Body one" >"$M/new/1.m1.host"
msg "Message 2" m2 "Body two" >"$M/new/2.m2.host"
msg "Message 3 Grüße" m3 "Body three" >"$M/new/3.m3.host"
msg "Secret" s1 "Top secret" >"$M/.Secret/new/4.s1.host"
# Reports: one multipart message (alternative text/html + PDF attachment).
printf '%s\r\n' \
  'From: =?UTF-8?Q?J=C3=BCrgen?= <j@example.org>' 'To: a@example.org' \
  'Subject: =?ISO-8859-1?Q?Monatsbericht_f=FCr_Oktober?=' 'Date: Mon, 9 Nov 2026 10:00:00 +0100' \
  'Message-ID: <r1@example.org>' 'MIME-Version: 1.0' 'Content-Type: multipart/mixed; boundary=outer' '' \
  '--outer' 'Content-Type: multipart/alternative; boundary=inner' '' \
  '--inner' 'Content-Type: text/plain; charset=iso-8859-1' 'Content-Transfer-Encoding: quoted-printable' '' 'Gr=FC=DFe aus dem Bericht' \
  '--inner' 'Content-Type: text/html; charset=utf-8' '' '<p>Report</p>' '--inner--' \
  '--outer' 'Content-Type: application/pdf; name="bericht.pdf"' 'Content-Disposition: attachment; filename="bericht.pdf"' \
  'Content-Transfer-Encoding: base64' '' 'JVBERi0xLjQK' '--outer--' >"$M/.Reports/new/5.r1.host"

dovecot -c "$WORK/dovecot.conf"
for _ in $(seq 50); do
  (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
  sleep 0.1
done

IRP_UPSTREAM_PORT="$PORT" IRP_UPSTREAM_USER=alice IRP_UPSTREAM_PASS=alicepw \
  go test -tags e2e -count=1 "$@" ./test/e2e/
