;;;; noise-test.lisp -- the Lisp Noise IK against the upstream Rust reference.
;;;;
;;;; The oracle (tools/oracle, upstream src/noise/ vendored verbatim) is driven
;;;; interactively over a pipe, so every check is "upstream accepted what Lisp
;;;; wrote, and Lisp accepted what upstream wrote":
;;;;
;;;;   M1  oracle verify-ik-initiator : upstream initiator  <->  Lisp responder
;;;;   M2  oracle verify-ik-responder : upstream responder  <->  Lisp initiator
;;;;   M3  oracle verify-xk-initiator : upstream XK initiator  <->  Lisp responder
;;;;   M4  oracle verify-xk-responder : upstream XK responder  <->  Lisp initiator
;;;;
;;;; Keys are random each run.  M1 alternates the parity of the Lisp responder's
;;;; static key, since the pre-message forces byte 0 to 0x02 on both sides.
;;;; Negative controls: a tampered msg2 must be REJECTED by upstream, and a
;;;; tampered msg1 must be rejected by Lisp; for XK, upstream must reject a
;;;; tampered msg2 (M3) and a tampered msg3 (M4), and Lisp a tampered msg2 and
;;;; msg3.  The replay window is checked against the sequences of upstream's own
;;;; src/noise/tests.rs, plus a differential against a transliteration of
;;;; replay.rs's shifting bitmap.
;;;;
;;;; Test-only: uses SB-EXT:RUN-PROGRAM.  Set CL_FIPS_NO_ORACLE=1 to skip the
;;;; oracle arms explicitly (they are reported as SKIPPED, never as passed).

(in-package #:cl-fips.test)

(defparameter *oracle-runs* 4)

(defun hex (bytes) (format nil "~(~{~2,'0x~}~)" (coerce bytes 'list)))

(defun unhex (string)
  (let ((v (make-array (floor (length string) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length v) v)
      (setf (aref v i) (parse-integer string :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun ascii (s) (map '(vector (unsigned-byte 8)) #'char-code s))

(defun oracle-dir ()
  (asdf:system-relative-pathname "cl-fips" "tools/oracle/"))

(defun oracle-binary ()
  (let ((bin (merge-pathnames "target/release/oracle" (oracle-dir))))
    (unless (probe-file bin)
      (format t "  building oracle (cargo build --release)...~%")
      (sb-ext:run-program "cargo" '("build" "--release" "--quiet")
                          :search t :directory (namestring (oracle-dir))
                          :output *standard-output* :error *standard-output*))
    (probe-file bin)))

;;; One oracle process; FIELDS accumulates its name=value lines.
(defstruct oproc process in out (fields (make-hash-table :test 'equal)))

(defun oracle-start (mode)
  (let ((p (sb-ext:run-program (namestring (oracle-binary)) (list mode)
                               :input :stream :output :stream :error nil :wait nil)))
    (make-oproc :process p :in (sb-ext:process-input p) :out (sb-ext:process-output p))))

(defun oracle-send (op bytes)
  (write-line (hex bytes) (oproc-in op))
  (force-output (oproc-in op)))

(defun oracle-read-until (op &rest stop-names)
  "Read name=value lines until one named in STOP-NAMES (or EOF)."
  (loop for l = (read-line (oproc-out op) nil)
        while l
        do (let* ((eq (position #\= l)) (name (subseq l 0 eq)))
             (setf (gethash name (oproc-fields op)) (subseq l (1+ eq)))
             (when (member name stop-names :test #'string=) (return name)))))

(defun field (op name) (gethash name (oproc-fields op)))
(defun field-bytes (op name) (let ((v (field op name))) (and v (unhex v))))

(defun oracle-finish (op)
  (ignore-errors (close (oproc-in op)))
  (sb-ext:process-wait (oproc-process op))
  (sb-ext:process-close (oproc-process op)))

(defun random-epoch () (natrium:random-bytes 8))

;;; --- M1: Lisp responder ------------------------------------------------------

(defun keypair-with-prefix (prefix)
  "A fresh keypair whose compressed encoding starts with PREFIX (2 or 3), so the
   pre-message's forced-0x02 normalization is exercised on both parities."
  (loop (let ((kp (generate-keypair)))
          (when (= (aref (keypair-public-bytes kp) 0) prefix) (return kp)))))

(defun m1-lisp-responder (&key tamper-msg2 (prefix 2))
  (let* ((op (oracle-start "verify-ik-initiator"))
         (static (keypair-with-prefix prefix))
         (epoch (random-epoch))
         (hs (fips-make-ik-responder static epoch)))
    (unwind-protect
         (progn
           (oracle-send op (keypair-public-bytes static))
           (oracle-read-until op "ready")
           (let ((msg1 (field-bytes op "msg1")))
             (check "M1 msg1 is 106 bytes" (= (length msg1) 106))
             (ik-read-message-1 hs msg1)
             (check "M1 Lisp learned the initiator's static key"
                    (equalp (encode-pubkey (hs-remote-static hs))
                            (field-bytes op "initiator_static")))
             (let ((msg2 (ik-write-message-2 hs)))
               (check "M1 Lisp msg2 is 57 bytes" (= (length msg2) 57))
               (when tamper-msg2
                 (setf (aref msg2 40) (logxor (aref msg2 40) 1)))
               (oracle-send op msg2)
               (oracle-read-until op "result")
               (cond
                 (tamper-msg2
                  (check "M1 control: upstream REJECTS a tampered msg2"
                         (equal (field op "result") "error")))
                 (t
                  (check "M1 upstream initiator accepted Lisp msg2"
                         (equal (field op "result") "ok"))
                  (oracle-read-until op "transport_ciphertext_from_initiator")
                  (check "M1 handshake hash matches upstream"
                         (equalp (handshake-hash hs) (field-bytes op "handshake_hash")))
                  (check "M1 upstream read Lisp's epoch"
                         (equalp (field-bytes op "remote_epoch") epoch))
                  (let ((s (handshake-into-session hs)))
                    (check "M1 Lisp decrypts upstream transport to \"hello fips\""
                           (equalp (session-decrypt
                                    s (field-bytes op "transport_ciphertext_from_initiator"))
                                   (ascii "hello fips")))
                    (oracle-send op (session-encrypt s (ascii "hello from lisp")))
                    (oracle-read-until op "responder_plaintext" "responder_result")
                    (check "M1 upstream decrypts Lisp's transport message"
                           (equalp (field-bytes op "responder_plaintext")
                                   (ascii "hello from lisp")))))))))
      (oracle-finish op))))

;;; --- M2: Lisp initiator ------------------------------------------------------

(defun m2-lisp-initiator ()
  (let ((op (oracle-start "verify-ik-responder"))
        (epoch (random-epoch)))
    (unwind-protect
         (progn
           (oracle-read-until op "ready")
           (let* ((static (generate-keypair))
                  (hs (fips-make-ik-initiator static (field-bytes op "responder_static") epoch))
                  (msg1 (ik-write-message-1 hs)))
             (check "M2 Lisp msg1 is 106 bytes" (= (length msg1) 106))
             (oracle-send op msg1)
             (oracle-read-until op "result")
             (check "M2 upstream responder accepted Lisp msg1"
                    (equal (field op "result") "ok"))
             (when (equal (field op "result") "ok")
               (oracle-read-until op "transport_ciphertext_from_responder")
               (check "M2 upstream learned Lisp's static key"
                      (equalp (field-bytes op "initiator_static") (keypair-public-bytes static)))
               (check "M2 upstream read Lisp's epoch"
                      (equalp (field-bytes op "remote_epoch") epoch))
               (ik-read-message-2 hs (field-bytes op "msg2"))
               (check "M2 handshake hash matches upstream"
                      (equalp (handshake-hash hs) (field-bytes op "handshake_hash")))
               (let ((s (handshake-into-session hs)))
                 (check "M2 Lisp decrypts upstream transport to \"hello fips\""
                        (equalp (session-decrypt
                                 s (field-bytes op "transport_ciphertext_from_responder"))
                                (ascii "hello fips")))
                 (oracle-send op (session-encrypt s (ascii "hello from lisp")))
                 (oracle-read-until op "initiator_plaintext" "initiator_result")
                 (check "M2 upstream decrypts Lisp's transport message"
                        (equalp (field-bytes op "initiator_plaintext")
                                (ascii "hello from lisp")))))))
      (oracle-finish op))))

;;; --- In-process checks (no oracle) -------------------------------------------

(defun test-noise-local ()
  ;; SEC1 round trip for both parities, and the generator's known encoding.
  (let ((g (keypair-from-secret (let ((v (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 0)))
                                  (setf (aref v 31) 1) v))))
    (check "1*G compressed"
           (string= (hex (keypair-public-bytes g))
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")))
  (dotimes (i 4)
    (let ((kp (generate-keypair)))
      (check "SEC1 decode(encode(P)) = P"
             (equal (decode-pubkey (keypair-public-bytes kp)) (keypair-public kp)))))
  (check "decode rejects bad prefix"
         (null (decode-pubkey (make-array 33 :element-type '(unsigned-byte 8) :initial-element 4))))
  ;; DH symmetry.
  (let ((a (generate-keypair)) (b (generate-keypair)))
    (check "noise-dh symmetric"
           (equalp (noise-dh a (keypair-public b)) (noise-dh b (keypair-public a)))))
  ;; Lisp <-> Lisp, plus the tampered-msg1 control on the Lisp responder.
  (let* ((rs (generate-keypair))
         (i (fips-make-ik-initiator (generate-keypair) (keypair-public-bytes rs) (random-epoch)))
         (r (fips-make-ik-responder rs (random-epoch)))
         (m1 (ik-write-message-1 i)))
    (let ((bad (copy-seq m1))
          (r2 (fips-make-ik-responder rs (random-epoch))))
      (setf (aref bad 50) (logxor (aref bad 50) 1))
      (check "Lisp responder REJECTS a tampered msg1"
             (handler-case (progn (ik-read-message-1 r2 bad) nil)
               (noise-error () t))))
    (ik-read-message-1 r m1)
    (ik-read-message-2 i (ik-write-message-2 r))
    (check "Lisp<->Lisp hashes agree" (equalp (handshake-hash i) (handshake-hash r)))
    (let ((si (handshake-into-session i)) (sr (handshake-into-session r)))
      (check "Lisp<->Lisp transport"
             (equalp (session-decrypt sr (session-encrypt si (ascii "x"))) (ascii "x"))))))

;;; --- M3: Lisp XK responder ----------------------------------------------------

(defun m3-lisp-xk-responder (&key tamper-msg2 (prefix 2))
  (let* ((op (oracle-start "verify-xk-initiator"))
         (static (keypair-with-prefix prefix))
         (epoch (random-epoch))
         (hs (fips-make-xk-responder static epoch)))
    (unwind-protect
         (progn
           (oracle-send op (keypair-public-bytes static))
           (oracle-read-until op "ready")
           (let ((msg1 (field-bytes op "msg1")))
             (check "M3 XK msg1 is 33 bytes" (= (length msg1) 33))
             (xk-read-message-1 hs msg1)
             (check "M3 responder does not know the initiator after msg1"
                    (null (hs-remote-static hs)))
             (let ((msg2 (xk-write-message-2 hs)))
               (check "M3 Lisp XK msg2 is 57 bytes" (= (length msg2) 57))
               (when tamper-msg2
                 (setf (aref msg2 40) (logxor (aref msg2 40) 1)))
               (oracle-send op msg2)
               (oracle-read-until op "result")
               (cond
                 (tamper-msg2
                  (check "M3 control: upstream REJECTS a tampered XK msg2"
                         (equal (field op "result") "error")))
                 (t
                  (check "M3 upstream XK initiator accepted Lisp msg2"
                         (equal (field op "result") "ok"))
                  (oracle-read-until op "transport_ciphertext_from_initiator")
                  (check "M3 upstream read Lisp's epoch"
                         (equalp (field-bytes op "remote_epoch") epoch))
                  (let ((msg3 (field-bytes op "msg3")))
                    (check "M3 XK msg3 is 73 bytes" (= (length msg3) 73))
                    (xk-read-message-3 hs msg3))
                  (check "M3 Lisp learned the initiator's static key from msg3"
                         (equalp (encode-pubkey (hs-remote-static hs))
                                 (field-bytes op "initiator_static")))
                  (check "M3 handshake hash matches upstream"
                         (equalp (handshake-hash hs) (field-bytes op "handshake_hash")))
                  (let ((s (handshake-into-session hs)))
                    (check "M3 Lisp decrypts upstream XK transport to \"hello fips\""
                           (equalp (session-decrypt
                                    s (field-bytes op "transport_ciphertext_from_initiator"))
                                   (ascii "hello fips")))
                    (oracle-send op (session-encrypt s (ascii "hello from lisp")))
                    (oracle-read-until op "responder_plaintext" "responder_result")
                    (check "M3 upstream decrypts Lisp's XK transport message"
                           (equalp (field-bytes op "responder_plaintext")
                                   (ascii "hello from lisp")))))))))
      (oracle-finish op))))

;;; --- M4: Lisp XK initiator ----------------------------------------------------

(defun m4-lisp-xk-initiator (&key tamper-msg3)
  (let ((op (oracle-start "verify-xk-responder"))
        (epoch (random-epoch)))
    (unwind-protect
         (progn
           (oracle-read-until op "ready")
           (let* ((static (generate-keypair))
                  (hs (fips-make-xk-initiator static (field-bytes op "responder_static") epoch))
                  (msg1 (xk-write-message-1 hs)))
             (check "M4 Lisp XK msg1 is 33 bytes" (= (length msg1) 33))
             (oracle-send op msg1)
             (oracle-read-until op "msg1_result")
             (check "M4 upstream XK responder accepted Lisp msg1"
                    (equal (field op "msg1_result") "ok"))
             (when (equal (field op "msg1_result") "ok")
               (xk-read-message-2 hs (field-bytes op "msg2"))
               (let ((msg3 (xk-write-message-3 hs)))
                 (check "M4 Lisp XK msg3 is 73 bytes" (= (length msg3) 73))
                 (when tamper-msg3
                   (setf (aref msg3 60) (logxor (aref msg3 60) 1)))
                 (oracle-send op msg3))
               (oracle-read-until op "result")
               (cond
                 (tamper-msg3
                  (check "M4 control: upstream REJECTS a tampered XK msg3"
                         (equal (field op "result") "error")))
                 (t
                  (check "M4 upstream XK responder accepted Lisp msg3"
                         (equal (field op "result") "ok"))
                  (oracle-read-until op "transport_ciphertext_from_responder")
                  (check "M4 upstream learned Lisp's static key from msg3"
                         (equalp (field-bytes op "initiator_static")
                                 (keypair-public-bytes static)))
                  (check "M4 upstream read Lisp's epoch"
                         (equalp (field-bytes op "remote_epoch") epoch))
                  (check "M4 handshake hash matches upstream"
                         (equalp (handshake-hash hs) (field-bytes op "handshake_hash")))
                  (let ((s (handshake-into-session hs)))
                    (check "M4 Lisp decrypts upstream XK transport to \"hello fips\""
                           (equalp (session-decrypt
                                    s (field-bytes op "transport_ciphertext_from_responder"))
                                   (ascii "hello fips")))
                    (oracle-send op (session-encrypt s (ascii "hello from lisp")))
                    (oracle-read-until op "initiator_plaintext" "initiator_result")
                    (check "M4 upstream decrypts Lisp's XK transport message"
                           (equalp (field-bytes op "initiator_plaintext")
                                   (ascii "hello from lisp")))))))))
      (oracle-finish op))))

;;; --- XK in-process ---------------------------------------------------------------

(defun rejects-p (thunk)
  (handler-case (progn (funcall thunk) nil) (noise-error () t)))

(defun xk-pair ()
  "A Lisp XK initiator and responder; returns (values i r)."
  (let ((rs (generate-keypair)))
    (values (fips-make-xk-initiator (generate-keypair) (keypair-public-bytes rs) (random-epoch))
            (fips-make-xk-responder rs (random-epoch)))))

(defun test-xk-local ()
  (multiple-value-bind (i r) (xk-pair)
    (check "XK: IK writer refuses an XK handshake"
           (rejects-p (lambda () (ik-write-message-1 i))))
    (let ((m1 (xk-write-message-1 i)))
      (xk-read-message-1 r m1)
      (check "XK: initiator cannot write msg3 before reading msg2"
             (rejects-p (lambda () (xk-write-message-3 i))))
      (let ((m2 (xk-write-message-2 r)))
        (xk-read-message-2 i m2)
        (check "XK: responder has not learned the initiator after msg2"
               (null (hs-remote-static r)))
        (let ((m3 (xk-write-message-3 i)))
          (xk-read-message-3 r m3)
          (check "XK Lisp<->Lisp hashes agree" (equalp (handshake-hash i) (handshake-hash r)))
          (check "XK both sides learned the other's epoch"
                 (and (= (length (hs-remote-epoch i)) 8) (= (length (hs-remote-epoch r)) 8)))
          (let ((si (handshake-into-session i)) (sr (handshake-into-session r)))
            (check "XK Lisp<->Lisp transport both ways"
                   (and (equalp (session-decrypt sr (session-encrypt si (ascii "a"))) (ascii "a"))
                        (equalp (session-decrypt si (session-encrypt sr (ascii "b"))) (ascii "b")))))))))
  ;; Tamper controls on the Lisp readers.
  (multiple-value-bind (i r) (xk-pair)
    (xk-read-message-1 r (xk-write-message-1 i))
    (let ((m2 (xk-write-message-2 r)))
      (setf (aref m2 45) (logxor (aref m2 45) 1))
      (check "Lisp XK initiator REJECTS a tampered msg2"
             (rejects-p (lambda () (xk-read-message-2 i m2))))))
  (multiple-value-bind (i r) (xk-pair)
    (xk-read-message-1 r (xk-write-message-1 i))
    (xk-read-message-2 i (xk-write-message-2 r))
    (let ((m3 (xk-write-message-3 i)))
      (setf (aref m3 10) (logxor (aref m3 10) 1))
      (check "Lisp XK responder REJECTS a tampered msg3"
             (rejects-p (lambda () (xk-read-message-3 r m3)))))))

;;; --- Replay window (replay.rs; sequences from src/noise/tests.rs) -----------------

(defconstant +u64-max+ (1- (expt 2 64)))

(defun test-replay-window ()
  (let ((w +replay-window-size+))
    (check "REPLAY_WINDOW_SIZE = 2048" (= w 2048))
    ;; test_replay_window_basic
    (let ((rw (make-replay-window)))
      (check "replay basic" (and (replay-check rw 0)
                                 (progn (replay-accept rw 0) (= (replay-window-highest rw) 0))
                                 (not (replay-check rw 0))
                                 (replay-check rw 1)
                                 (progn (replay-accept rw 1) (= (replay-window-highest rw) 1))
                                 (progn (replay-accept rw 10) (replay-check rw 5))
                                 (progn (replay-accept rw 5) (not (replay-check rw 5))))))
    ;; test_replay_window_large_jump
    (let ((rw (make-replay-window)))
      (replay-accept rw 0)
      (replay-accept rw (+ w 100))
      (check "replay large jump" (and (not (replay-check rw 0)) (not (replay-check rw 50))
                                      (replay-check rw (+ w 99)) (replay-check rw (+ w 50)))))
    ;; test_replay_window_boundary
    (let ((rw (make-replay-window)))
      (replay-accept rw (1- w))
      (check "replay boundary: 0 is exactly at the edge" (replay-check rw 0))
      (replay-accept rw 0)
      (replay-accept rw w)
      (check "replay boundary: 0 falls out, 1 stays"
             (and (not (replay-check rw 0)) (replay-check rw 1))))
    ;; test_replay_window_sequential
    (let ((rw (make-replay-window)) (ok t))
      (dotimes (i 1000) (unless (replay-check rw i) (setf ok nil)) (replay-accept rw i))
      (dotimes (i 1000) (when (replay-check rw i) (setf ok nil)))
      (check "replay sequential 0..999" (and ok (= (replay-window-highest rw) 999))))
    ;; test_replay_window_reset
    (let ((rw (make-replay-window)))
      (replay-accept rw 100)
      (check "replay reset" (and (= (replay-window-highest rw) 100) (not (replay-check rw 100))
                                 (progn (replay-reset rw) (= (replay-window-highest rw) 0))
                                 (replay-check rw 100))))
    ;; test_replay_window_max_counter_does_not_wedge_the_window
    (let ((rw (make-replay-window)))
      (replay-accept rw 100)
      (when (replay-check rw +u64-max+) (replay-accept rw +u64-max+))
      (check "replay: 2^64-1 does not wedge the window" (replay-check rw 101)))
    ;; test_replay_window_rejects_max_counter
    (check "replay rejects 2^64-1" (not (replay-check (make-replay-window) +u64-max+)))
    ;; test_replay_window_accepts_highest_counter_an_honest_peer_can_send
    (let ((rw (make-replay-window)))
      (check "replay accepts 2^64-2, then rejects its replay"
             (and (replay-check rw (1- +u64-max+))
                  (progn (replay-accept rw (1- +u64-max+)) (not (replay-check rw (1- +u64-max+)))))))
    (test-replay-differential)))

;;; replay.rs transliterated: HIGHEST plus a 2048-bit bitmap (bit i = counter
;;; HIGHEST - i seen), shifted on advance.  natrium keeps the same set as a ring;
;;; this drives both with the same random accept/check stream.
(defun ref-check (st c)
  (destructuring-bind (h . bm) st
    (cond ((= c +u64-max+) nil)
          ((> c h) t)
          ((>= (- h c) 2048) nil)
          (t (not (logbitp (- h c) bm))))))

(defun ref-accept (st c)
  (destructuring-bind (h . bm) st
    (if (> c h)
        (let ((shift (- c h)))
          (setf bm (if (>= shift 2048) 0 (ldb (byte 2048 0) (ash bm shift))))
          (cons c (logior bm 1)))
        (cons h (logior bm (ash 1 (- h c)))))))

(defun test-replay-differential (&optional (steps 20000))
  (let ((rw (make-replay-window)) (st (cons 0 0)) (bad 0) (rs (sb-ext:seed-random-state 1729)))
    (dotimes (k steps)
      (let* ((h (car st))
             (c (case (random 8 rs)
                  (0 (+ h 1 (random 3000 rs)))             ; jump, sometimes past the window
                  ((1 2) (+ h 1 (random 4 rs)))            ; in-order-ish
                  (3 (max 0 (- h 2040 (random 20 rs))))    ; near the trailing edge
                  (t (max 0 (- h (random 64 rs)))))))      ; recent: duplicates likely
        (unless (eq (ref-check st c) (replay-check rw c)) (incf bad))
        (when (ref-check st c)
          (setf st (ref-accept st c))
          (replay-accept rw c))
        (unless (= (car st) (replay-window-highest rw)) (incf bad))))
    (check (format nil "replay window agrees with replay.rs's bitmap over ~d steps" steps)
           (zerop bad))))

(defun test-session-replay ()
  ;; test_session_replay_protection, over an IK session.
  (let* ((rs (generate-keypair))
         (i (fips-make-ik-initiator (generate-keypair) (keypair-public-bytes rs) (random-epoch)))
         (r (fips-make-ik-responder rs (random-epoch))))
    (ik-read-message-1 r (ik-write-message-1 i))
    (ik-read-message-2 i (ik-write-message-2 r))
    (let* ((sender (handshake-into-session i))
           (receiver (handshake-into-session r))
           (counter (session-current-send-counter sender))
           (ct (session-encrypt sender (ascii "test message"))))
      (check "session replay: first decryption succeeds"
             (equalp (session-decrypt-with-replay-check receiver counter ct)
                     (ascii "test message")))
      (check "session replay: replay is rejected"
             (rejects-p (lambda () (session-decrypt-with-replay-check receiver counter ct))))
      (check "session replay: check alone detects it"
             (not (session-check-replay receiver counter)))
      ;; A forgery at a fresh counter must not advance the window.
      (let ((bad (copy-seq (session-encrypt sender (ascii "next")))))
        (setf (aref bad 0) (logxor (aref bad 0) 1))
        (check "session replay: forgery rejected, and the window is not advanced"
               (and (rejects-p (lambda () (session-decrypt-with-replay-check receiver 1 bad)))
                    (session-check-replay receiver 1)))))))

(defun test-noise-oracle ()
  (cond
    ((sb-ext:posix-getenv "CL_FIPS_NO_ORACLE")
     (format t "  SKIPPED: oracle arms (CL_FIPS_NO_ORACLE set)~%"))
    ((not (oracle-binary))
     (incf *checks*) (incf *failures*)
     (format t "  FAIL oracle binary unavailable (set CL_FIPS_NO_ORACLE=1 to skip)~%"))
    (t
     (dotimes (k *oracle-runs*) (m1-lisp-responder :prefix (if (evenp k) 2 3)))
     (m1-lisp-responder :tamper-msg2 t)
     (dotimes (k *oracle-runs*) (m2-lisp-initiator))
     (dotimes (k *oracle-runs*) (m3-lisp-xk-responder :prefix (if (evenp k) 2 3)))
     (m3-lisp-xk-responder :tamper-msg2 t)
     (dotimes (k *oracle-runs*) (m4-lisp-xk-initiator))
     (m4-lisp-xk-initiator :tamper-msg3 t))))
