require ["fileinto", "copy", "vnd.dovecot.pipe", "variables", "envelope"];

if header :contains "X-Spam-Flag" "YES" {
  fileinto "Spam";
  stop;
}

if envelope :matches "To" ["X@Y.Z", "D@E.F"] {
  if header :contains "X-GPGIt-Wrapped" "true" {
      fileinto "wrapped";
    } elsif header :contains "X-GPGIt" "true" {
    fileinto "encrypted";
  }  else {
    pipe "lmtp.py" ["${0}", "A@B.C"]; # replace A@B.C with the PGP key id or the respective mail address
  }
}

