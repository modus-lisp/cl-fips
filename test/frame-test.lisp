;;;; frame-test.lisp -- FMP established frames, Lisp against upstream.
;;;;
;;;;   F1  oracle verify-frame : upstream IK initiator <-> Lisp IK responder, then
;;;;       three upstream-sealed frames opened by Lisp (out of order, plus a
;;;;       tampered header and a replay that must be refused), and Lisp-sealed
;;;;       frames opened by upstream's EncryptedHeader::parse +
;;;;       decrypt_with_replay_check_and_aad + strip_inner_header (with a
;;;;       replay, a tampered header and a tampered body that it must refuse).

(in-package #:cl-fips.test)

(defun flip (bytes index)
  (let ((v (copy-seq bytes))) (setf (aref v index) (logxor (aref v index) 1)) v))

(defun ik-session-pair ()
  "Lisp<->Lisp IK; returns (values initiator-session responder-session)."
  (let* ((rs (generate-keypair))
         (i (fips-make-ik-initiator (generate-keypair) (keypair-public-bytes rs) (random-epoch)))
         (r (fips-make-ik-responder rs (random-epoch))))
    (ik-read-message-1 r (ik-write-message-1 i))
    (ik-read-message-2 i (ik-write-message-2 r))
    (values (handshake-into-session i) (handshake-into-session r))))

(defun test-frame-local ()
  (multiple-value-bind (si sr) (ik-session-pair)
    (let* ((msg (concatenate '(vector (unsigned-byte 8)) (bytes #x10) (ascii "hi")))
           (f (fmp-seal-frame si #x01020304 77 msg :flags (logior +flag-ce+ +flag-sp+))))
      (check "frame length = 16 + 4 + |msg| + 16" (= (length f) (+ 16 4 3 16)))
      (check "frame header bytes (ver/phase 0, flags, payload_len 7, idx, counter 0)"
             (equalp (subseq f 0 16) (bytes 0 6 7 0 4 3 2 1 0 0 0 0 0 0 0 0)))
      (check "frame payload_len matches its length" (fmp-frame-payload-len-ok-p f))
      (multiple-value-bind (m ts fl idx ctr) (fmp-open-frame sr f)
        (check "frame Lisp<->Lisp round trip"
               (and (equalp m msg) (= ts 77) (= fl 6) (= idx #x01020304) (= ctr 0))))
      (check "frame replay refused" (rejects-p (lambda () (fmp-open-frame sr f))))
      (let ((g (fmp-seal-frame si 9 1 msg)))
        (check "frame with a tampered header (AAD) refused"
               (rejects-p (lambda () (fmp-open-frame sr (flip g 1)))))
        (check "frame whose header was refused still opens untampered"
               (equalp (fmp-open-frame sr g) msg)))
      (check "frame shorter than 32 bytes refused"
             (rejects-p (lambda () (fmp-open-frame sr (subseq f 0 31)))))
      (let ((h (copy-seq (fmp-seal-frame si 9 1 msg))))
        (setf (aref h 0) 1)
        (check "frame with handshake phase refused" (rejects-p (lambda () (fmp-open-frame sr h)))))
      (check "sealing with reserved flag bits set is an error"
             (handler-case (progn (fmp-seal-frame si 9 1 msg :flags 8) nil) (error () t)))
      (let ((short (fmp-seal-frame si 9 1 (bytes))))   ; inner = 4 bytes, no msg_type
        (check "frame whose plaintext lacks the inner header refused"
               (rejects-p (lambda () (fmp-open-frame sr short))))))))

;;; --- F1 ----------------------------------------------------------------------------

(defun int-field (op name) (parse-integer (field op name)))

(defun f1-open-upstream-frame (op s n lisp-idx &key (label (format nil "frame ~d" n)))
  (multiple-value-bind (m ts fl idx ctr)
      (fmp-open-frame s (field-bytes op (format nil "frame_~d" n)))
    (check (format nil "F1 Lisp opens upstream ~a" label)
           (and (equalp m (field-bytes op (format nil "frame_~d_message" n)))
                (= ts (int-field op (format nil "frame_~d_timestamp" n)))
                (= fl (int-field op (format nil "frame_~d_flags" n)))
                (= idx lisp-idx) (= ctr n)
                (fmp-frame-payload-len-ok-p (field-bytes op (format nil "frame_~d" n)))))))

(defun f1-send (op frame)
  (oracle-send op frame)
  (oracle-read-until op "frame_result")
  (equal (field op "frame_result") "ok"))

(defun f1-upstream-opened-p (op msg ts flags idx counter)
  (and (equal (field op "frame_result") "ok")
       (equalp (field-bytes op "frame_message") msg)
       (= (int-field op "frame_timestamp") ts)
       (= (int-field op "frame_flags") flags)
       (= (int-field op "frame_receiver_idx") idx)
       (= (int-field op "frame_counter") counter)
       (equal (field op "frame_payload_len_ok") "1")))

(defun f1-frames ()
  (let* ((op (oracle-start "verify-frame"))
         (static (generate-keypair))
         (hs (fips-make-ik-responder static (random-epoch))))
    (unwind-protect
         (progn
           (oracle-send op (keypair-public-bytes static))
           (oracle-read-until op "ready")
           (ik-read-message-1 hs (field-bytes op "msg1"))
           (oracle-send op (ik-write-message-2 hs))
           (oracle-read-until op "result")
           (check "F1 IK handshake accepted by upstream" (equal (field op "result") "ok"))
           (when (equal (field op "result") "ok")
             (oracle-read-until op "frames_ready")
             (let ((s (handshake-into-session hs))
                   (lisp-idx (int-field op "lisp_receiver_idx"))
                   (oracle-idx (int-field op "oracle_receiver_idx")))
               ;; upstream -> Lisp: tampered first (must not advance the window),
               ;; then out of order 2, 0, 1, then a replay.
               (check "F1 Lisp REJECTS an upstream frame with a tampered header"
                      (rejects-p (lambda () (fmp-open-frame s (flip (field-bytes op "frame_2") 1)))))
               (f1-open-upstream-frame op s 2 lisp-idx :label "frame 2 (K flag, ts 2^32-1, 601-byte message)")
               (f1-open-upstream-frame op s 0 lisp-idx :label "frame 0 after frame 2 (out of order)")
               (f1-open-upstream-frame op s 1 lisp-idx :label "frame 1 (CE|SP flags)")
               (check "F1 Lisp REJECTS a replay of upstream frame 0"
                      (rejects-p (lambda () (fmp-open-frame s (field-bytes op "frame_0")))))
               ;; Lisp -> upstream.
               (let* ((ma (concatenate '(vector (unsigned-byte 8)) (bytes #x20) (ascii "lisp zero")))
                      (mb (let ((v (make-array 1201 :element-type '(unsigned-byte 8))))
                            (dotimes (k 1201 v) (setf (aref v k) (mod (* k 13) 256)))))
                      (fa (fmp-seal-frame s oracle-idx 42 ma)))
                 (f1-send op fa)
                 (check "F1 upstream opens Lisp frame 0"
                        (f1-upstream-opened-p op ma 42 0 oracle-idx 0))
                 (f1-send op (fmp-seal-frame s oracle-idx #xffffffff mb
                                             :flags (logior +flag-ce+ +flag-sp+ +flag-key-epoch+)))
                 (check "F1 upstream opens Lisp frame 1 (all flags, ts 2^32-1, 1201 bytes)"
                        (f1-upstream-opened-p op mb #xffffffff 7 oracle-idx 1))
                 (check "F1 upstream REJECTS a replay of Lisp frame 0"
                        (not (f1-send op fa)))
                 (check "F1 upstream REJECTS a Lisp frame with a tampered header"
                        (not (f1-send op (flip (fmp-seal-frame s oracle-idx 5 ma) 1))))
                 (check "F1 upstream REJECTS a Lisp frame with a tampered body"
                        (not (f1-send op (flip (fmp-seal-frame s oracle-idx 5 ma) 20))))
                 (let ((f4 (fmp-seal-frame s oracle-idx 6 ma))
                       (f5 (fmp-seal-frame s oracle-idx 7 ma)))
                   (f1-send op f5)
                   (check "F1 upstream opens Lisp frame 5 before 4"
                          (f1-upstream-opened-p op ma 7 0 oracle-idx 5))
                   (f1-send op f4)
                   (check "F1 ...and then frame 4 (rejections did not poison the window)"
                          (f1-upstream-opened-p op ma 6 0 oracle-idx 4))))
               (write-line "end" (oproc-in op))
               (force-output (oproc-in op)))))
      (oracle-finish op))))

(defun test-frame-oracle ()
  (cond
    ((sb-ext:posix-getenv "CL_FIPS_NO_ORACLE")
     (format t "  SKIPPED: frame oracle arm (CL_FIPS_NO_ORACLE set)~%"))
    ((not (oracle-binary))
     (incf *checks*) (incf *failures*)
     (format t "  FAIL oracle binary unavailable (set CL_FIPS_NO_ORACLE=1 to skip)~%"))
    (t (dotimes (k 2) (f1-frames)))))

;;; --- node_addr / FIPS address ----------------------------------------------------

(defun test-npub ()
  ;; NIP-19's own test vectors
  (check "npub encodes NIP-19's vector"
         (string= (npub-encode (unhex "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"))
                  "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"))
  (check "nsec encodes NIP-19's vector"
         (string= (nsec-encode (unhex "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"))
                  "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"))
  (check "nsec decodes NIP-19's vector"
         (string= (hex (nsec-decode "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"))
                  "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"))
  (check "npub decodes to 0x02 || x"
         (string= (hex (npub-decode "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"))
                  "027e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"))
  (check "an upper-case npub decodes too"
         (npub-decode (string-upcase "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg")))
  (flet ((refused (s) (handler-case (progn (npub-decode s) nil) (error () t))))
    (check "a one-character change is refused (checksum)"
           (refused "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjpth"))
    (check "mixed case is refused" (refused "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjpTg"))
    (check "an nsec is not an npub"
           (refused "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"))
    (check "a valid bech32 of the wrong length is refused" (refused (bech32-encode "npub" (unhex "0102"))))))

(defun test-identity ()
  (test-npub)
  ;; 1*G: values printed by `oracle node-addr` (upstream from_pubkey/from_node_addr).
  (let* ((g (unhex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
         (na (node-addr g)))
    (check "node_addr(1*G) = upstream" (string= (hex na) "132f39a98c31baaddba6525f5d43f295"))
    (check "FIPS address(1*G) = upstream"
           (string= (hex (fips-address na)) "fd132f39a98c31baaddba6525f5d43f2"))
    (check "FIPS address text" (string= (fips-address-string (fips-address na))
                                        "fd13:2f39:a98c:31ba:addb:a652:5f5d:43f2"))
    (check "node_addr ignores parity" (equalp na (node-addr (flip g 0)))))
  (unless (sb-ext:posix-getenv "CL_FIPS_NO_ORACLE")
    (let ((op (oracle-start "node-addr")))
      (unwind-protect
           (dotimes (k 4)
             (let ((pk (keypair-public-bytes (keypair-with-prefix (if (evenp k) 2 3)))))
               (oracle-send op pk)
               (oracle-read-until op "address")
               (check "node_addr and address agree with upstream (random key)"
                      (and (equalp (node-addr pk) (field-bytes op "node_addr"))
                           (equalp (fips-address (node-addr pk)) (field-bytes op "address"))))))
        (oracle-finish op)))))
