;;;; try-read-test.lisp -- the rolling-back handshake reads (handshake.rs try_read_*).
;;;;
;;;; Upstream (jmcorgan/fips @ 57bc510, src/noise/handshake.rs:641-674, 878-909,
;;;; 1022-1054) snapshots exactly what the plain reader writes and restores it on
;;;; failure, so a forged or corrupted message cannot poison the handshake the
;;;; genuine message still has to complete.  The plain readers are NOT rolled
;;;; back: upstream's own src/noise/tests.rs
;;;; (test_a_failed_plain_xk_msg3_read_cannot_read_the_genuine_msg3) pins that a
;;;; failed plain read leaves a handshake the genuine msg3 no longer opens.
;;;;
;;;;   local   Lisp<->Lisp, every try-read: tamper, then genuine; plain-read control
;;;;   R1      oracle verify-xk-responder-retry: upstream try_read_xk_message_3 is
;;;;           fed a corrupted msg3 and then Lisp's genuine one
;;;;   R2      oracle verify-xk-responder-retry-plain: the same against upstream's
;;;;           plain read_xk_message_3 -- the genuine msg3 must now FAIL upstream,
;;;;           exactly as it fails Lisp's plain reader
;;;;   R3-R5   the upstream message is corrupted on delivery to Lisp first; Lisp's
;;;;           try-read must then complete with upstream's handshake hash and a
;;;;           working session (XK msg2, XK msg3, IK msg2)
;;;;   break   COPY-SYMMETRIC made shallow: the local check must then fail

(in-package #:cl-fips.test)

(defun quietly-count-failures (thunk)
  "Run THUNK with CHECK output suppressed; return how many checks failed."
  (let ((*failures* 0) (*checks* 0) (*standard-output* (make-broadcast-stream)))
    (handler-case (funcall thunk)
      (error () (incf *failures*)))    ; an escaping error is a failure too
    *failures*))

(defun hs-snapshot (hs)
  (list (copy-seq (handshake-hash hs)) (hs-progress hs) (hs-remote-static hs) (hs-remote-epoch hs)))

;;; --- local ---------------------------------------------------------------------

(defun ik-pair-at-msg2 ()
  "IK initiator that has sent msg1, the responder's genuine msg2, and the responder."
  (let* ((rs (generate-keypair))
         (i (fips-make-ik-initiator (generate-keypair) (keypair-public-bytes rs) (random-epoch)))
         (r (fips-make-ik-responder rs (random-epoch))))
    (ik-read-message-1 r (ik-write-message-1 i))
    (values i (ik-write-message-2 r) r)))

(defun xk-pair-at-msg2 ()
  (multiple-value-bind (i r) (xk-pair)
    (xk-read-message-1 r (xk-write-message-1 i))
    (values i (xk-write-message-2 r) r)))

(defun xk-pair-at-msg3 ()
  (multiple-value-bind (i m2 r) (xk-pair-at-msg2)
    (xk-read-message-2 i m2)
    (values r (xk-write-message-3 i) i)))

(defun try-read-local-case (label make reader try-reader tamper-indices)
  "MAKE returns (values reader-hs genuine-msg peer-hs).  Each index in
   TAMPER-INDICES is one corrupted delivery, attempted in turn on one handshake
   before the genuine message."
  (multiple-value-bind (hs msg peer) (funcall make)
    (let ((before (hs-snapshot hs)))
      (dolist (k tamper-indices)
        (check (format nil "~a: try-read REJECTS a message tampered at byte ~d" label k)
               (rejects-p (lambda () (funcall try-reader hs (flip msg k)))))
        (check (format nil "~a: ... and leaves hash, progress, remote static/epoch as they were" label)
               (equalp (hs-snapshot hs) before)))
      (check (format nil "~a: try-read REJECTS a short message without moving state" label)
             (and (rejects-p (lambda () (funcall try-reader hs (subseq msg 1))))
                  (equalp (hs-snapshot hs) before)))
      (funcall try-reader hs msg)
      (check (format nil "~a: the genuine message then reads" label)
             (not (equalp (hs-progress hs) (second before))))
      (when (eq (hs-progress hs) :message2-done) ; XK initiator: finish with msg3
        (xk-read-message-3 peer (xk-write-message-3 hs)))
      (check (format nil "~a: hashes agree with the peer after the rollback" label)
             (equalp (handshake-hash hs) (handshake-hash peer)))
      (let ((a (handshake-into-session hs)) (b (handshake-into-session peer)))
        (check (format nil "~a: sessions interoperate after the rollback" label)
               (and (equalp (session-decrypt b (session-encrypt a (ascii "p"))) (ascii "p"))
                    (equalp (session-decrypt a (session-encrypt b (ascii "q"))) (ascii "q"))))))
    ;; The plain read is the control: upstream does not roll it back.
    (multiple-value-bind (hs2 msg2) (funcall make)
      (let ((before (hs-snapshot hs2))
            (bad (flip msg2 (car (last tamper-indices)))))
        (check (format nil "~a control: plain read rejects the tampered message" label)
               (rejects-p (lambda () (funcall reader hs2 bad))))
        (check (format nil "~a control: plain read does not advance progress" label)
               (eq (hs-progress hs2) (second before)))
        (check (format nil "~a control: plain read leaves the hash poisoned (as upstream)" label)
               (not (equalp (handshake-hash hs2) (first before))))
        (check (format nil "~a control: after a failed plain read the genuine message FAILS (as upstream)" label)
               (rejects-p (lambda () (funcall reader hs2 msg2))))))))

(defun test-try-read-local ()
  ;; IK msg2 = e(33) || enc(epoch)(24): byte 5 is inside e's x (an invalid or a
  ;; different point), 40 and 56 fail the epoch AEAD after ee/se are mixed.
  ;; NOT byte 0: that is e's parity, and with an x-only ECDH and empty AAD a
  ;; parity flip is ACCEPTED (see TEST-PARITY-MALLEABILITY).
  (try-read-local-case "IK msg2" #'ik-pair-at-msg2
                       #'ik-read-message-2 #'ik-try-read-message-2 '(5 40 56))
  (try-read-local-case "XK msg2" #'xk-pair-at-msg2
                       #'xk-read-message-2 #'xk-try-read-message-2 '(5 40 56))
  ;; XK msg3 = enc(s)(49) || enc(epoch)(24): 10 fails the first AEAD after the
  ;; nonce advanced; 60 and 72 fail the epoch after s was learned and se mixed.
  (try-read-local-case "XK msg3" #'xk-pair-at-msg3
                       #'xk-read-message-3 #'xk-try-read-message-3 '(10 60 72))
  ;; upstream's own check: a failed rolling-back msg3 leaves no remote static
  (multiple-value-bind (r m3) (xk-pair-at-msg3)
    (rejects-p (lambda () (xk-try-read-message-3 r (flip m3 72))))
    (check "XK msg3: a failed try-read does not leave the static it decrypted behind"
           (null (hs-remote-static r)))))

(defun test-try-read-break ()
  "Deliberate break: a shallow COPY-SYMMETRIC (the snapshot aliases the live
   state, whose cipher nonce advances in place) must make the local check fail."
  (let ((orig (fdefinition 'natrium.noise::copy-symmetric)))
    (unwind-protect
         (progn
           (setf (fdefinition 'natrium.noise::copy-symmetric) #'identity)
           (check "break: aliasing the snapshot makes the try-read checks FAIL"
                  (plusp (quietly-count-failures #'test-try-read-local))))
      (setf (fdefinition 'natrium.noise::copy-symmetric) orig)))
  (check "break restored: the try-read checks pass again"
         (zerop (quietly-count-failures #'test-try-read-local))))

;;; An observation, not a rollback property, pinned against upstream: FIPS's
;;; ECDH hashes only the x coordinate (handshake.rs ecdh) and its handshake AEAD
;;; uses empty AAD (handshake.rs encrypt_and_hash -> mod.rs CipherState::encrypt), so
;;; flipping the parity byte of e in msg2 changes nothing the reader
;;; authenticates: upstream ACCEPTS it, the keys still agree, and only the
;;; handshake hash diverges between the two sides.
(defun test-parity-malleability ()
  (let* ((op (oracle-start "verify-ik-initiator"))
         (static (generate-keypair))
         (hs (fips-make-ik-responder static (random-epoch))))
    (unwind-protect
         (progn
           (oracle-send op (keypair-public-bytes static))
           (oracle-read-until op "ready")
           (ik-read-message-1 hs (field-bytes op "msg1"))
           (oracle-send op (flip (ik-write-message-2 hs) 0))
           (oracle-read-until op "result")
           (check "parity: upstream ACCEPTS a msg2 whose e parity byte was flipped"
                  (equal (field op "result") "ok"))
           (when (equal (field op "result") "ok")
             (oracle-read-until op "transport_ciphertext_from_initiator")
             (check "parity: ... the handshake hashes then DIFFER"
                    (not (equalp (field-bytes op "handshake_hash") (handshake-hash hs))))
             (check "parity: ... yet the session keys agree"
                    (equalp (session-decrypt (handshake-into-session hs)
                                             (field-bytes op "transport_ciphertext_from_initiator"))
                            (ascii "hello fips")))))
      (oracle-finish op))))

;;; --- R1/R2: upstream responder fed a corrupted msg3, then the genuine one ---------

(defun r-upstream-msg3-retry (mode)
  (let ((op (oracle-start mode))
        (epoch (random-epoch))
        (plain (search "plain" mode)))
    (unwind-protect
         (progn
           (oracle-read-until op "ready")
           (let* ((static (generate-keypair))
                  (hs (fips-make-xk-initiator static (field-bytes op "responder_static") epoch)))
             (oracle-send op (xk-write-message-1 hs))
             (oracle-read-until op "msg1_result")
             (xk-read-message-2 hs (field-bytes op "msg2"))
             (let ((m3 (xk-write-message-3 hs)))
               (oracle-send op (flip m3 60))
               (oracle-read-until op "attempt_result")
               (check (format nil "~a: upstream rejects the corrupted msg3" mode)
                      (equal (field op "attempt_result") "error"))
               (unless plain
                 (oracle-send op (flip m3 10))
                 (oracle-read-until op "attempt_result")
                 (check (format nil "~a: upstream rejects a second, differently corrupted msg3" mode)
                        (equal (field op "attempt_result") "error")))
               (oracle-send op m3)
               (oracle-read-until op "attempt_result")
               (cond
                 (plain
                  (check (format nil "~a: upstream's PLAIN read then rejects the genuine msg3" mode)
                         (equal (field op "attempt_result") "error")))
                 (t
                  (check (format nil "~a: upstream's try_read then accepts the genuine msg3" mode)
                         (equal (field op "attempt_result") "ok"))
                  (check (format nil "~a: handshake hash matches Lisp's" mode)
                         (equalp (field-bytes op "handshake_hash") (handshake-hash hs)))
                  (check (format nil "~a: upstream learned Lisp's static and epoch" mode)
                         (and (equalp (field-bytes op "initiator_static")
                                      (keypair-public-bytes static))
                              (equalp (field-bytes op "remote_epoch") epoch))))))
             (when plain (oracle-send-line op "end"))))
      (oracle-finish op))))

(defun oracle-send-line (op string)
  (write-line string (oproc-in op))
  (force-output (oproc-in op)))

;;; --- R3-R5: Lisp's try-read takes a corrupted upstream message first ---------------

(defun r3-xk-msg2 ()
  (let ((op (oracle-start "verify-xk-responder")) (epoch (random-epoch)))
    (unwind-protect
         (progn
           (oracle-read-until op "ready")
           (let ((hs (fips-make-xk-initiator (generate-keypair) (field-bytes op "responder_static")
                                             epoch)))
             (oracle-send op (xk-write-message-1 hs))
             (oracle-read-until op "msg1_result")
             (let ((m2 (field-bytes op "msg2")))
               (check "R3 Lisp try-read rejects upstream's msg2 corrupted on delivery"
                      (rejects-p (lambda () (xk-try-read-message-2 hs (flip m2 50)))))
               (xk-try-read-message-2 hs m2))
             (oracle-send op (xk-write-message-3 hs))
             (oracle-read-until op "result")
           (oracle-read-until op "transport_ciphertext_from_responder")
             (check "R3 upstream accepts the msg3 Lisp wrote after the rollback"
                    (equal (field op "result") "ok"))
             (check "R3 handshake hash matches upstream"
                    (equalp (handshake-hash hs) (field-bytes op "handshake_hash")))
             (let ((s (handshake-into-session hs)))
               (check "R3 session decrypts upstream's transport"
                      (equalp (session-decrypt s (field-bytes op "transport_ciphertext_from_responder"))
                              (ascii "hello fips")))
               (oracle-send op (session-encrypt s (ascii "after rollback")))
               (oracle-read-until op "initiator_plaintext" "initiator_result")
               (check "R3 upstream decrypts Lisp's transport"
                      (equalp (field-bytes op "initiator_plaintext") (ascii "after rollback"))))))
      (oracle-finish op))))

(defun r4-xk-msg3 ()
  (let* ((op (oracle-start "verify-xk-initiator"))
         (static (generate-keypair))
         (hs (fips-make-xk-responder static (random-epoch))))
    (unwind-protect
         (progn
           (oracle-send op (keypair-public-bytes static))
           (oracle-read-until op "ready")
           (xk-read-message-1 hs (field-bytes op "msg1"))
           (oracle-send op (xk-write-message-2 hs))
           (oracle-read-until op "result")
           (oracle-read-until op "transport_ciphertext_from_initiator")
           (let ((m3 (field-bytes op "msg3")))
             (check "R4 Lisp try-read rejects upstream's msg3 corrupted on delivery"
                    (rejects-p (lambda () (xk-try-read-message-3 hs (flip m3 60)))))
             (xk-try-read-message-3 hs m3))
           (check "R4 handshake hash matches upstream"
                  (equalp (handshake-hash hs) (field-bytes op "handshake_hash")))
           (check "R4 Lisp learned upstream's static key"
                  (equalp (encode-pubkey (hs-remote-static hs)) (field-bytes op "initiator_static")))
           (let ((s (handshake-into-session hs)))
             (check "R4 session decrypts upstream's transport"
                    (equalp (session-decrypt s (field-bytes op "transport_ciphertext_from_initiator"))
                            (ascii "hello fips")))))
      (oracle-finish op))))

(defun r5-ik-msg2 ()
  (let ((op (oracle-start "verify-ik-responder")))
    (unwind-protect
         (progn
           (oracle-read-until op "ready")
           (let ((hs (fips-make-ik-initiator (generate-keypair) (field-bytes op "responder_static")
                                             (random-epoch))))
             (oracle-send op (ik-write-message-1 hs))
             (oracle-read-until op "result")
           (oracle-read-until op "transport_ciphertext_from_responder")
             (let ((m2 (field-bytes op "msg2")))
               (check "R5 Lisp try-read rejects upstream's IK msg2 corrupted on delivery"
                      (rejects-p (lambda () (ik-try-read-message-2 hs (flip m2 45)))))
               (ik-try-read-message-2 hs m2))
             (check "R5 handshake hash matches upstream"
                    (equalp (handshake-hash hs) (field-bytes op "handshake_hash")))
             (let ((s (handshake-into-session hs)))
               (check "R5 session decrypts upstream's transport"
                      (equalp (session-decrypt s (field-bytes op "transport_ciphertext_from_responder"))
                              (ascii "hello fips"))))))
      (oracle-finish op))))

(defun test-try-read ()
  (test-try-read-local)
  (test-try-read-break)
  (cond
    ((sb-ext:posix-getenv "CL_FIPS_NO_ORACLE")
     (format t "  SKIPPED: try-read oracle arms (CL_FIPS_NO_ORACLE set)~%"))
    ((not (oracle-binary))
     (incf *checks*) (incf *failures*)
     (format t "  FAIL oracle binary unavailable (set CL_FIPS_NO_ORACLE=1 to skip)~%"))
    (t
     (dotimes (k 2) (r-upstream-msg3-retry "verify-xk-responder-retry"))
     (r-upstream-msg3-retry "verify-xk-responder-retry-plain")
     (dotimes (k 2) (r3-xk-msg2) (r4-xk-msg3) (r5-ik-msg2))
     (test-parity-malleability))))
