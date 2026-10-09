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
           ;; spanning tree (stp.lisp, tree.lisp) and bloom filter (bloom.lisp)
           #:+tree-announce-msg-type+ #:+filter-announce-msg-type+
           #:make-coord-entry #:coord-entry-node #:coord-entry-seq #:coord-entry-ts
           #:make-parent-declaration #:parent-declaration-node #:parent-declaration-parent
           #:parent-declaration-seq #:parent-declaration-ts #:parent-declaration-sig
           #:parent-declaration-root-p #:declaration-signing-bytes #:declaration-signing-hash
           #:sign-declaration #:verify-declaration
           #:encode-tree-announce #:decode-tree-announce #:validate-tree-semantics
           #:make-tree-state #:tree-state-node #:tree-state-declaration #:tree-state-entries
           #:tree-register-peer-key #:tree-observe-announce #:tree-recompute
           #:tree-current-announce
           #:make-bloom #:bloom-bit-indices #:bloom-insert #:bloom-contains-p
           #:bloom-union #:encode-filter-announce #:decode-filter-announce
           ;; end-to-end data plane (fsp.lisp)
           #:encode-session-datagram #:decode-session-datagram
           #:encode-coords #:decode-coords
           #:encode-fsp-setup-or-ack #:decode-fsp-setup-or-ack
           #:encode-fsp-msg3 #:decode-fsp-msg3
           #:fsp-seal-data #:fsp-open-data
           #:make-fsp-initiator #:fsp-initiator-phase #:fsp-initiator-session
           #:fsp-setup-datagram #:fsp-handle-ack #:fsp-data-datagram #:fsp-initiator-our-addr
           #:fsp-handle-rekey-setup #:fsp-handle-rekey-msg3 #:fsp-open-any
           #:fsp-initiator-previous-session #:fsp-initiator-pending-session #:fsp-initiator-k
           #:fsp-start-rekey #:fsp-handle-rekey-ack #:fsp-resend-setup #:fsp-initiator-setup-tries
           #:fsp-expire-previous #:fsp-previous-live-p
           ;; transit forwarding (route.lisp) and the link's filter hooks
           #:sd-ttl #:sd-path-mtu #:sd-src #:sd-dest #:sd-forward-header
           #:route-next-hop #:route-filter-for
           #:stream-link-peer-filter #:stream-link-filter-source #:stream-link-tree-dirty
           #:make-tree-state #:tree-state-p
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
           #:stream-link-port #:stream-link-role #:stream-link-session #:stream-link-tree
           #:stream-link-our-index #:stream-link-their-index #:stream-link-handshake-hash
           #:stream-link-remote-static #:stream-link-remote-epoch #:stream-link-mtu
           #:random-session-index #:make-octet-source-port
           #:stream-link-poll #:stream-link-fmp #:stream-link-mmp #:stream-link-k-bit
           #:stream-link-elapsed-ms
           ;; MMP link reports (mmp.lisp)
           #:+msg-type-sender-report+ #:+msg-type-receiver-report+
           #:+sender-report-size+ #:+receiver-report-size+
           #:sender-report #:make-sender-report #:receiver-report #:make-receiver-report
           #:encode-sender-report #:decode-sender-report
           #:encode-receiver-report #:decode-receiver-report
           #:mmp-peer #:make-mmp-peer #:mmp-receiver #:mmp-sender #:mmp-metrics
           #:mmp-send-rr #:mmp-send-sr
           #:make-mmp-receiver #:mmp-receiver-record #:mmp-receiver-due-p
           #:mmp-receiver-build-report #:mmp-receiver-reset-for-rekey
           #:make-mmp-sender #:mmp-sender-record #:mmp-sender-due-p #:mmp-sender-build-report
           #:make-mmp-metrics #:mmp-metrics-process-rr #:mmp-handle-report
           #:mmp-due-reports #:mmp-reset-for-rekey
           #:sender-report-interval-start-counter #:sender-report-interval-end-counter
           #:sender-report-interval-start-timestamp
           #:sender-report-interval-end-timestamp #:sender-report-interval-bytes-sent
           #:sender-report-cumulative-packets-sent #:sender-report-cumulative-bytes-sent
           #:receiver-report-highest-counter #:receiver-report-cumulative-packets-recv
           #:receiver-report-cumulative-bytes-recv #:receiver-report-timestamp-echo
           #:receiver-report-dwell-time #:receiver-report-max-burst-loss
           #:receiver-report-mean-burst-loss #:receiver-report-jitter
           #:receiver-report-ecn-ce-count #:receiver-report-owd-trend
           #:receiver-report-burst-loss-count #:receiver-report-cumulative-reorder-count
           #:receiver-report-interval-packets-recv #:receiver-report-interval-bytes-recv))

(defpackage #:cl-fips.test
  (:use #:common-lisp #:cl-fips #:natrium.noise #:secp256k1-fast.ecdh)
  (:export #:run-all))
