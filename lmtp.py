#!/usr/bin/env python3
import smtplib
import email
import gpgit
import sys
import copy

SOCKET="/var/run/dovecot/lmtp"

destination = sys.argv[1]
recipients = sys.argv[2:]

blob = sys.stdin.buffer.read()
msg_parsed = email.message_from_bytes(blob)

lmtp = smtplib.LMTP(host=SOCKET)
        
sender = email.utils.parseaddr(msg_parsed["From"])[1]

res = str(gpgit.wrap_message(blob, copy.deepcopy(msg_parsed), recipients))
lmtp.sendmail(sender, [destination], res)

res = str(gpgit.encrypt_message(blob, copy.deepcopy(msg_parsed), recipients))
lmtp.sendmail(sender, [destination], res)
lmtp.quit()
