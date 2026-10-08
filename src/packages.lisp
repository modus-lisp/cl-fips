(defpackage #:cl-fips
  (:use #:common-lisp)
  (:export #:encode-u16le #:decode-u16le #:encode-u32le #:decode-u32le
           #:encode-u64le #:decode-u64le
           #:encode-prefix #:decode-prefix #:prefix-phase #:prefix-version
           #:stream-frame-length
           #:encode-fmp-established-header #:decode-fmp-established-header
           #:encode-fsp-header #:decode-fsp-header
           #:+phase-established+ #:+phase-msg1+ #:+phase-msg2+
           #:+fmp-established-header-size+ #:+fsp-header-size+ #:+aead-tag-size+
           ;; the FIPS suite (fips-noise.lisp); the protocol is natrium.noise's
           #:generate-keypair #:normalize-for-premessage
           #:fips-make-ik-initiator #:fips-make-ik-responder))

(defpackage #:cl-fips.test
  (:use #:common-lisp #:cl-fips #:natrium.noise #:secp256k1-fast.ecdh)
  (:export #:run-all))
