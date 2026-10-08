;;;; noise-test.lisp -- the Lisp Noise IK against the upstream Rust reference.
;;;;
;;;; The oracle (tools/oracle, upstream src/noise/ vendored verbatim) is driven
;;;; interactively over a pipe, so every check is "upstream accepted what Lisp
;;;; wrote, and Lisp accepted what upstream wrote":
;;;;
;;;;   M1  oracle verify-ik-initiator : upstream initiator  <->  Lisp responder
;;;;   M2  oracle verify-ik-responder : upstream responder  <->  Lisp initiator
;;;;
;;;; Keys are random each run.  M1 alternates the parity of the Lisp responder's
;;;; static key, since the pre-message forces byte 0 to 0x02 on both sides.
;;;; Negative controls: a tampered msg2 must be REJECTED by upstream, and a
;;;; tampered msg1 must be rejected by Lisp.
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
     (dotimes (k *oracle-runs*) (m2-lisp-initiator)))))
