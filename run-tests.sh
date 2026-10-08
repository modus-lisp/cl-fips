#!/bin/sh
# Load the system and run the tests under SBCL.  Exits non-zero on failure.
# The Noise tests drive tools/oracle (built with cargo on first use); set
# CL_FIPS_NO_ORACLE=1 to skip those arms explicitly.  NATRIUM_DIR and
# SECP256K1_DIR locate the two pure-CL dependencies.
# The TCP arms (test/tcp-test.lisp) need the cl-fips/transport adapter, which
# needs usocket: it is taken from Quicklisp (~/quicklisp/setup.lisp) when that
# exists, else from ASDF.  Without usocket those arms are reported as SKIPPED.
cd "$(dirname "$0")" && sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval "(push #p\"${NATRIUM_DIR:-$HOME/natrium}/\" asdf:*central-registry*)" \
  --eval "(push #p\"${SECP256K1_DIR:-$HOME/secp256k1-fast}/\" asdf:*central-registry*)" \
  --eval '(asdf:load-system "cl-fips/test")' \
  --eval '(let ((ql (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
            (when (probe-file ql) (load ql)))' \
  --eval '(handler-case
              (progn (if (find-package "QL")
                         (funcall (find-symbol "QUICKLOAD" "QL") "usocket" :silent t)
                         (asdf:load-system "usocket"))
                     (asdf:load-system "cl-fips/transport-test"))
            (error (e) (format t "~&;; cl-fips/transport-test not loaded: ~a~%" e)))' \
  --eval '(unless (cl-fips.test:run-all) (sb-ext:exit :code 1))'
