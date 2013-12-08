#!/usr/bin/env python

import email
import sys, os
import re
from pyme.core import Data, Context
from email.mime.base import MIMEBase
from email.mime.application import MIMEApplication

class GPG:
	def __init__(self):
		self.__context = Context()
		self.__context.set_armor(1)
	
	def __get_keys(self, recipients):
		return [self.__context.get_key(recipient, 0) for recipient in recipients]
	
	def encrypt(self, plain, recipients):
		cipher = Data()
		self.__context.op_encrypt(self.__get_keys(recipients), 1, Data(plain), cipher)
		cipher.seek(0,0)
		return cipher.read()

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
		self.__content = message.get_payload()
		
	def is_encrypted(self):
		return re.search("-----BEGIN PGP MESSAGE-----", self.__content, flags = re.MULTILINE) is not None
	
	def is_signed(self):
		return re.search("-----BEGIN PGP SIGNED MESSAGE-----", self.__content, flags = re.MULTILINE) is not None

	def encrypt(self, gpg, keys):
		if self.is_encrypted() or self.is_signed():
			return
		
		if self._message.get_content_type() == "text/plain":
			self._message.set_payload(gpg.encrypt(self.__content, keys))
		else:
			message = email.message.Message()
			message.set_type(self._message.get_content_type())
			message.set_charset(self._message.get_content_charset())
			message.set_payload(self._message.get_payload())
			set_header(message, "Content-Transfer-Encoding", self._message.get("Content-Transfer-Encoding"))
			set_header(message, "MIME-Version", None)
			self._mime_encrypt(message.as_string(), gpg, keys)
	
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
		

gpg = GPG()
message = sys.stdin.read()
message = email.message_from_string(message)
recipients = sys.argv[1:]


if message.is_multipart():
	message = MimeMessage(message)
else:
	message = PlainTextMessage(message)

message.encrypt(gpg, recipients)
print message
