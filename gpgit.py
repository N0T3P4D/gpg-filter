#!/usr/bin/env python
# GPGIt : Automatically GPG-encrypt incoming email
# Aeris <aeris@imirhil.fr>
# Licensed under AGPLv3 or later

from __future__ import print_function
import email
import sys, os
import re
import pyme
from pyme.core import Data, Context
from email.mime.base import MIMEBase
from email.mime.application import MIMEApplication
import email.encoders

class GPG:
    def __init__(self):
        pyme.core.check_version(None)
        self.__context = Context()
        self.__context.set_armor(1)

    def __get_keys(self, recipients):
        return [self.__context.get_key(recipient, 0) for recipient in recipients]

    def encrypt(self, plain, recipients):
        cipher = Data()
        self.__context.op_encrypt(self.__get_keys(recipients), 1, Data(plain), cipher)
        cipher.seek(0,0)
        return cipher.read()

    def decrypt(self, ciphertext):
        plaintext = Data()
        self.__context.op_decrypt(Data(ciphertext), plaintext)
        plaintext.seek(0,0)
        return plaintext.read()

def set_header(message, name, value, **params):
    if value is None:
        del message[name]
    else:
        if name in message:
            message.replace_header(name, value)
        else:
            message.add_header(name, value, **params)

class Message:
    def __init__(self, message):
        self._message = message

    def __str__(self):
        return self._message.as_string()

    def _mime_encrypt(self, payload, gpg, keys):
        payload = gpg.encrypt(payload, keys)

        self._message.set_type("multipart/encrypted");
        self._message.set_param("protocol", "application/pgp-encrypted");
        self._message.del_param("micalg");
        set_header(self._message, "Content-Transfer-Encoding", None)
        set_header(self._message, "X-GPGIt", "true")
        self._message.preamble = ""
        self._message.set_payload(None)

        pgp_encrypted = MIMEApplication("Version: 1", "pgp-encrypted", email.encoders.encode_7or8bit)
        set_header(pgp_encrypted, "Content-Disposition", "attachment")
        set_header(pgp_encrypted, "MIME-Version", None)
        self._message.attach(pgp_encrypted)

        octet_stream = MIMEApplication(payload, "octet-stream", email.encoders.encode_7or8bit)
        set_header(octet_stream, "Content-Disposition", "inline", filename="msg.asc")
        set_header(octet_stream, "MIME-Version", None)
        self._message.attach(octet_stream)

class PlainTextMessage(Message):
    def __init__(self, message):
        Message.__init__(self, message)
        self.__content = message.get_payload(decode=True)

    def is_encrypted(self):
        return re.search(b"-----BEGIN PGP MESSAGE-----", self.__content, flags = re.MULTILINE) is not None

    def is_signed(self):
        return re.search(b"-----BEGIN PGP SIGNED MESSAGE-----", self.__content, flags = re.MULTILINE) is not None

    def encode(self):
        encoding = self._message["Content-Transfer-Encoding"]
        if encoding is "quoted-printable":
            return email.encoders.encode_quopri(self._message)
        elif encoding in ["7bit", "8bit"]:
            return email.encoders.encode_7or8bit(self._message)
        elif encoding is "base64":
            return email.encoders.encode_base64(self._message)

    def encrypt(self, gpg, keys):
        if self.is_encrypted() or self.is_signed():
            return

        if self._message.get_content_type() == "text/plain":
            self._message.set_payload(gpg.encrypt(self.__content, keys))
            set_header(self._message, "Content-Transfer-Encoding", None)
            set_header(self._message, "X-GPGIt", "true")
        else:
            payload = email.message.Message()
            payload.set_type(self._message.get_content_type())
            payload.set_charset(self._message.get_content_charset())
            payload.set_payload(self._message.get_payload())
            set_header(payload, "Content-Transfer-Encoding", self._message.get("Content-Transfer-Encoding"))
            set_header(payload, "MIME-Version", None)
            self._mime_encrypt(payload.as_string(), gpg, keys)

class MimeMessage(Message):
    def __init__(self, message):
        Message.__init__(self, message)

    def is_encrypted(self):
        return self._message.get_content_type() == "multipart/encrypted"

    def is_signed(self):
        return self._message.get_content_type() == "multipart/signed"

    def encrypt(self, gpg, keys):
        if self.is_encrypted():
            return

        payload = MIMEBase(self._message.get_content_maintype(), self._message.get_content_subtype())
        payload.set_charset(self._message.get_charset())
        payload.set_payload(self._message.get_payload())
        payload.set_boundary(self._message.get_boundary())
        self._mime_encrypt(payload.as_string(), gpg, keys)

class WrapperMessage(PlainTextMessage):

    def __init__(self, message, plaintext):
        self.plaintext = plaintext
        PlainTextMessage.__init__(self, message)

    def encrypt(self, gpg, keys):
        payload = gpg.encrypt(self.plaintext, keys)
        self._message.set_payload(payload)
        set_header(self._message, "Content-Transfer-Encoding", None)
        set_header(self._message, "X-GPGIt-Wrapped", "true")

    def decrypt(self, gpg):
        assert("X-GPGIt-Wrapped" in self._message)
        ciphertext = self._message.get_payload() #.get_payload()
        plaintext = gpg.decrypt(ciphertext)
        return plaintext


def wrap_message(message_, message, recipients):
    gpg = GPG()
    m = WrapperMessage(message, message_)
    m.encrypt(gpg, recipients)
    return(m)

def encrypt_message(message_, message, recipients):
    gpg = GPG()
    if message.is_multipart():
        m = MimeMessage(message)
    else:
        m = PlainTextMessage(message)
    m.encrypt(gpg, recipients)
    return(m)


if __name__ == "__main__":
    gpg = GPG()
    message_ = sys.stdin.read()
    message = email.message_from_string(message_)
    mode = sys.argv[1]
    recipients = sys.argv[2:]

    if (mode == "--encrypt"):
        if message.is_multipart():
            message = MimeMessage(message)
        else:
            message = PlainTextMessage(message)

        message.encrypt(gpg, recipients)
        print(message)
    elif (mode == "--wrap"):
        m = WrapperMessage(message, message_)
        m.encrypt(gpg, recipients)
        print(m)
    elif (mode == "--decrypt"):
        try:
            m = WrapperMessage(message, message_)
            res = m.decrypt(gpg)
            print(res,end="")
        except:
            print(message_,end="")
    else:
        assert(False)
