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
           #:fips-make-ik-initiator #:fips-make-ik-responder
           #:fips-make-xk-initiator #:fips-make-xk-responder
           ;; FMP established frames (fmp.lisp)
           #:+flag-key-epoch+ #:+flag-ce+ #:+flag-sp+ #:+inner-header-size+
           #:fmp-seal-frame #:fmp-open-frame #:fmp-frame-payload-len-ok-p
           ;; identity (identity.lisp)
           #:node-addr #:fips-address #:fips-address-string
           ;; FMP link rekey (rekey.lisp)
           #:+drain-window-secs+ #:+rekey-dampening-secs+ #:+rekey-jitter-secs+
           #:rekey-config #:make-rekey-config #:rekey-config-after-secs
           #:rekey-config-after-messages #:rekey-config-pending-hold-ms #:rekey-config-enabled
           #:build-msg1 #:build-msg2 #:parse-msg1 #:parse-msg2
           #:node-addr< #:rekey-tie-break-winner-p
           #:fmp-link #:make-link #:rekey-snapshot #:make-rekey-snapshot #:rekey-decide
           #:link-snapshot #:link-tick #:link-send #:link-receive
           #:link-cutover #:link-adopt-pending #:link-complete-drain #:link-retire-pending
           #:link-abandon-rekey #:link-initiate-rekey
           #:link-session #:link-previous-session #:link-pending-session #:link-pending-role
           #:link-our-index #:link-their-index #:link-previous-our-index
           #:link-pending-our-index #:link-k-bit #:link-rekey-in-progress
           #:link-our-addr #:link-peer-addr #:link-drain-started #:link-config
           ;; FMP over a byte stream (link.lisp)
           #:+default-stream-mtu+ #:link-error #:link-error-reason #:link-error-detail
           #:link-error-fatal-p #:make-byte-port #:byte-port-close #:byte-port-closed
           #:fmp-packet-remaining #:read-fmp-packet #:write-fmp-packet #:deadline-after-ms
           #:stream-link #:stream-link-initiate #:stream-link-accept
           #:stream-link-send #:stream-link-receive #:stream-link-close
           #:stream-link-port #:stream-link-role #:stream-link-session
           #:stream-link-our-index #:stream-link-their-index #:stream-link-handshake-hash
           #:stream-link-remote-static #:stream-link-remote-epoch #:stream-link-mtu
           #:random-session-index #:make-octet-source-port))

(defpackage #:cl-fips.test
  (:use #:common-lisp #:cl-fips #:natrium.noise #:secp256k1-fast.ecdh)
  (:export #:run-all))
