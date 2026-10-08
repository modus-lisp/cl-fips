#!/bin/sh
# Load the system and run the tests under SBCL.  Exits non-zero on failure.
# The Noise tests drive tools/oracle (built with cargo on first use); set
# CL_FIPS_NO_ORACLE=1 to skip those arms explicitly.  NATRIUM_DIR and
# SECP256K1_DIR locate the two pure-CL dependencies.
cd "$(dirname "$0")" && sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval "(push #p\"${NATRIUM_DIR:-$HOME/natrium}/\" asdf:*central-registry*)" \
  --eval "(push #p\"${SECP256K1_DIR:-$HOME/secp256k1-fast}/\" asdf:*central-registry*)" \
  --eval '(asdf:load-system "cl-fips/test")' \
  --eval '(unless (cl-fips.test:run-all) (sb-ext:exit :code 1))'
