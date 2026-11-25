#!/bin/sh
# Load the system and run the tests under SBCL.  Exits non-zero on failure.
# The Noise tests drive tools/oracle (built with cargo on first use); set
# CL_FIPS_NO_ORACLE=1 to skip those arms explicitly.  NATRIUM_DIR and
# SECP256K1_DIR locate the two pure-CL dependencies.
# The TCP arms (test/tcp-test.lisp) need the cl-fips/transport adapter, on
# cl-transport/sockets (CL_TRANSPORT_DIR).  If it does not load, those arms are
# reported as SKIPPED.
cd "$(dirname "$0")" && sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval "(push #p\"${NATRIUM_DIR:-$HOME/natrium}/\" asdf:*central-registry*)" \
  --eval "(push #p\"${SECP256K1_DIR:-$HOME/secp256k1-fast}/\" asdf:*central-registry*)" \
  --eval "(push #p\"${CL_TRANSPORT_DIR:-$HOME/cl-transport}/\" asdf:*central-registry*)" \
  --eval '(asdf:load-system "cl-fips/test")' \
  --eval '(handler-case
              (asdf:load-system "cl-fips/transport-test")
            (error (e) (format t "~&;; cl-fips/transport-test not loaded: ~a~%" e)))' \
  --eval '(unless (cl-fips.test:run-all) (sb-ext:exit :code 1))'
