#!/usr/bin/env python3
import smtplib
import email
import gpgit
import sys
import copy

SOCKET="/var/run/dovecot/lmtp"

destination = sys.argv[1]
recipients = sys.argv[2:]

lmtp = smtplib.LMTP(host=SOCKET)
msg = sys.stdin.read()
msg_parsed = email.message_from_string(msg)
sender = email.utils.parseaddr(msg_parsed["From"])[1]

res = str(gpgit.wrap_message(msg, copy.deepcopy(msg_parsed), recipients))
lmtp.sendmail(sender, [destination], res)

res = str(gpgit.encrypt_message(msg, copy.deepcopy(msg_parsed), recipients))
lmtp.sendmail(sender, [destination], res)
lmtp.quit()
