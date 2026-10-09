;;;; test.lisp -- byte-layout and round-trip checks for the FIPS wire codecs.
;;;; Expected values are written out from the spec tables, not computed by the
;;;; code under test.

(in-package #:cl-fips.test)

(defvar *failures* 0)
(defvar *checks* 0)

(defmacro check (name form)
  `(progn (incf *checks*)
          (unless ,form
            (incf *failures*)
            (format t "  FAIL ~a~%" ,name))))

(defun bytes (&rest xs) (coerce xs '(vector (unsigned-byte 8))))

(defun test-little-endian ()
  (check "u16 LE" (equalp (encode-u16le #x1234) (bytes #x34 #x12)))
  (check "u32 LE" (equalp (encode-u32le #xdeadbeef) (bytes #xef #xbe #xad #xde)))
  (check "u64 LE" (equalp (encode-u64le #x0102030405060708)
                          (bytes 8 7 6 5 4 3 2 1)))
  (check "u64 round trip max" (= (decode-u64le (encode-u64le (1- (expt 2 64))))
                                 (1- (expt 2 64)))))

(defun test-prefix ()
  ;; version 0, phase 1 (msg1), flags 0, payload 110
  (let ((p (encode-prefix 0 +phase-msg1+ 0 110)))
    (check "prefix msg1 bytes" (equalp p (bytes #x01 #x00 110 0)))
    (multiple-value-bind (v ph fl len) (decode-prefix p)
      (check "prefix decode" (and (= v 0) (= ph 1) (= fl 0) (= len 110)))))
  ;; the phase nibble is the LOW nibble; version is the high nibble
  (let ((p (bytes #x20 #x05 0 0)))
    (check "version is high nibble" (= (prefix-version p) 2))
    (check "phase is low nibble" (= (prefix-phase p) 0))))

(defun test-stream-framing ()
  ;; msg1 is 114 bytes total: 4-byte prefix + 110 remaining
  (check "msg1 remaining 110"
         (= (stream-frame-length (encode-prefix 0 +phase-msg1+ 0 110)) 110))
  ;; msg2 is 69 bytes total: 4-byte prefix + 65 remaining
  (check "msg2 remaining 65"
         (= (stream-frame-length (encode-prefix 0 +phase-msg2+ 0 65)) 65))
  ;; established: remaining = 12 + payload + 16
  (check "established remaining = 12 + payload + 16"
         (= (stream-frame-length (encode-prefix 0 +phase-established+ 0 100))
            (+ 12 100 16)))
  ;; unknown phase: spec says close the connection
  (check "unknown phase rejected"
         (null (stream-frame-length (encode-prefix 0 5 0 10)))))

(defun test-fmp-established ()
  (let* ((h (encode-fmp-established-header #b00000011 300 #xa1b2c3d4 #x0102))
         (expected (bytes #x00 #x03 #x2c #x01   ; prefix: ver/phase, flags, len 300 LE
                          #xd4 #xc3 #xb2 #xa1   ; receiver_idx LE
                          #x02 #x01 0 0 0 0 0 0))) ; counter LE
    (check "fmp header length 16" (= (length h) 16))
    (check "fmp header bytes" (equalp h expected))
    (multiple-value-bind (fl len idx ctr) (decode-fmp-established-header h)
      (check "fmp round trip"
             (and (= fl 3) (= len 300) (= idx #xa1b2c3d4) (= ctr #x0102))))))

(defun test-fsp ()
  (let* ((h (encode-fsp-header #b00000001 40 7))
         (expected (bytes 0 1 40 0 7 0 0 0 0 0 0 0)))
    (check "fsp header length 12" (= (length h) 12))
    (check "fsp header bytes" (equalp h expected))
    (multiple-value-bind (fl len ctr) (decode-fsp-header h)
      (check "fsp round trip" (and (= fl 1) (= len 40) (= ctr 7))))))

(defvar *tcp-suite* nil
  "Set by tcp-test.lisp when cl-fips/transport-test is loaded (it needs usocket).")

(defun run-all ()
  (setf *failures* 0 *checks* 0)
  (test-little-endian)
  (test-prefix)
  (test-stream-framing)
  (test-fmp-established)
  (test-fsp)
  (test-noise-local)                    ; noise-test.lisp
  (test-xk-local)
  (test-replay-window)
  (test-session-replay)
  (test-noise-oracle)
  (test-frame-local)                    ; frame-test.lisp
  (test-frame-oracle)
  (test-identity)                       ; frame-test.lisp
  (test-try-read)                       ; try-read-test.lisp
  (test-rekey)                          ; rekey-test.lisp
  (test-mmp)                            ; mmp-test.lisp
  (test-routing)                        ; routing-test.lisp
  (test-fsp-session)                    ; fsp-test.lisp
  (test-transit)                        ; transit-test.lisp
  (test-link-local)                     ; link-test.lisp
  (if *tcp-suite*
      (funcall *tcp-suite*)             ; tcp-test.lisp
      (format t "  SKIPPED: TCP arms (cl-fips/transport-test not loaded; it needs usocket)~%"))
  (format t "~&~d checks, ~d failures~%" *checks* *failures*)
  (zerop *failures*))
