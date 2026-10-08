;;;; link-test.lisp -- FMP stream framing and the stream link, in memory.
;;;;
;;;; No sockets: the far side of every BYTE-PORT here is a Lisp closure, so this
;;;; file runs with CL_FIPS_NO_ORACLE=1 and without usocket.  Expected sizes are
;;;; upstream's (transport/framing.rs read_fmp_packet and its unit tests), written
;;;; out rather than recomputed from the code under test.  Each rejection has a
;;;; control that differs from it in the one property being checked.

(in-package #:cl-fips.test)

(defun octets (&rest parts)
  "Concatenate byte sequences and integers (single bytes) into one vector."
  (let ((out '()))
    (dolist (p parts) (if (integerp p) (push p out) (map nil (lambda (b) (push b out)) p)))
    (coerce (nreverse out) '(vector (unsigned-byte 8)))))

(defun filler (n &optional (byte #xaa)) (make-array n :element-type '(unsigned-byte 8)
                                                      :initial-element byte))

(defun link-error-of (thunk)
  "The LINK-ERROR THUNK signals, or NIL."
  (handler-case (progn (funcall thunk) nil) (link-error (e) e)))

(defun reason-of (thunk) (let ((e (link-error-of thunk))) (and e (link-error-reason e))))

(defun remaining-reason (prefix &optional (mtu 1400))
  (nth-value 1 (fmp-packet-remaining prefix mtu)))

(defun make-peer-port (peer)
  "A port whose far side is PEER: called with each packet the link writes, it
   returns the bytes to deliver back.  Reading past what was delivered is :eof.
   Second value: a function that appends bytes to the inbox directly."
  (let ((inbox (make-array 0 :element-type '(unsigned-byte 8))))
    (flet ((deliver (bytes) (setf inbox (octets inbox bytes))))
      (values
       (make-byte-port
        (lambda (n deadline)
          (declare (ignore deadline))
          (let* ((k (min n (length inbox))) (got (subseq inbox 0 k)))
            (setf inbox (subseq inbox k))
            (values got (if (= k n) :ok :eof))))
        (lambda (packet) (deliver (or (funcall peer packet) #())) :ok)
        (lambda () nil))
       #'deliver))))

;;; --- framing -----------------------------------------------------------------------

(defun test-stream-remaining ()
  (check "stream: msg1 payload_len 110 -> 110 more (114 total)"
         (eql (fmp-packet-remaining (bytes 1 0 110 0)) 110))
  (check "stream: msg2 payload_len 65 -> 65 more (69 total)"
         (eql (fmp-packet-remaining (bytes 2 0 65 0)) 65))
  (check "stream: established payload_len 100 -> 12 + 100 + 16 more"
         (eql (fmp-packet-remaining (bytes 0 0 100 0)) 128))
  (check "stream: established payload_len 0 -> 28 more (32 total)"
         (eql (fmp-packet-remaining (bytes 0 0 0 0)) 28))
  (check "stream: msg1 with payload_len 50 is a size mismatch"
         (eq (remaining-reason (bytes 1 0 50 0)) :handshake-size-mismatch))
  (check "stream: msg1 with payload_len 111 is a size mismatch"
         (eq (remaining-reason (bytes 1 0 111 0)) :handshake-size-mismatch))
  (check "stream: msg2 with payload_len 64 is a size mismatch"
         (eq (remaining-reason (bytes 2 0 64 0)) :handshake-size-mismatch))
  ;; framing.rs test_max_payload_at_mtu_boundary / test_payload_one_over_mtu
  (check "stream: established 1368 at MTU 1400 is accepted (control)"
         (eql (fmp-packet-remaining (octets 0 0 (encode-u16le 1368)) 1400) (+ 12 1368 16)))
  (check "stream: established 1369 at MTU 1400 is too large"
         (eq (remaining-reason (octets 0 0 (encode-u16le 1369)) 1400) :payload-too-large))
  (check "stream: MTU 100 caps payload at 68 (framing.rs test_payload_too_large)"
         (and (eql (fmp-packet-remaining (bytes 0 0 68 0) 100) (+ 12 68 16))
              (eq (remaining-reason (bytes 0 0 69 0) 100) :payload-too-large)))
  (check "stream: every phase 3..15 is unknown"
         (loop for ph from 3 to 15 always (eq (remaining-reason (bytes ph 0 10 0)) :unknown-phase)))
  ;; framing.rs test_unknown_version_error: a TLS ClientHello starts 0x16
  (check "stream: 0x16 (TLS ClientHello) is an unknown version, not a phase"
         (eq (remaining-reason (bytes #x16 3 1 0)) :unknown-version))
  (check "stream: version 1 with a valid phase is still refused"
         (eq (remaining-reason (bytes #x11 0 110 0)) :unknown-version)))

(defun test-read-fmp-packet ()
  (let* ((m1 (octets 1 0 110 0 (filler 110)))
         (m2 (octets 2 0 65 0 (filler 65 #xbb)))
         (est (octets 0 0 3 0 (filler 31 #xcc))))
    (let ((port (make-octet-source-port (octets m1 est m2))))
      (check "stream: three packets back to back come out whole and in order"
             (and (equalp (read-fmp-packet port) m1)
                  (equalp (read-fmp-packet port) est)
                  (equalp (read-fmp-packet port) m2)))
      (check "stream: EOF exactly between packets is :peer-closed"
             (eq (reason-of (lambda () (read-fmp-packet port))) :peer-closed))
      (check "stream: ... and the port is closed" (byte-port-closed port))))
  (let ((port (make-octet-source-port (octets 1 0 110 0 (filler 40)))))
    (check "stream: EOF inside a msg1 is :truncated"
           (eq (reason-of (lambda () (read-fmp-packet port))) :truncated))
    (check "stream: a truncated packet closes the port" (byte-port-closed port)))
  (let ((port (make-octet-source-port (octets 1 0))))
    (check "stream: EOF inside the prefix is :truncated, not :peer-closed"
           (eq (reason-of (lambda () (read-fmp-packet port))) :truncated)))
  (let ((port (make-octet-source-port (octets 1 0 110 0 (filler 40)) :on-exhaustion :timeout)))
    (check "stream: a stalled packet is :timeout"
           (eq (reason-of (lambda () (read-fmp-packet port :timeout-ms 10))) :timeout))
    (check "stream: a timeout closes the port" (byte-port-closed port)))
  (let ((port (make-octet-source-port (octets 5 0 10 0 (filler 10)))))
    (check "stream: unknown phase 5 is refused" (eq (reason-of (lambda () (read-fmp-packet port)))
                                                     :unknown-phase))
    (check "stream: an unknown phase closes the port" (byte-port-closed port)))
  (let ((port (make-octet-source-port (octets 1 0 110 0 (filler 110)))))
    (read-fmp-packet port)
    (check "stream: control -- a good packet leaves the port open"
           (not (byte-port-closed port)))))

;;; --- the link state machine --------------------------------------------------------

(defun scripted-responder (rs epoch r-idx)
  "A far side that answers msg1 with a genuine msg2 from a Lisp responder and
   records established frames.  Returns (values peer-fn session-getter frames-getter)."
  (let ((r (fips-make-ik-responder rs epoch)) (session nil) (frames '()))
    (values (lambda (pkt)
              (case (prefix-phase pkt)
                (1 (multiple-value-bind (sidx m1) (parse-msg1 pkt)
                     (ik-read-message-1 r m1)
                     (prog1 (build-msg2 r-idx sidx (ik-write-message-2 r))
                       (setf session (handshake-into-session r)))))
                (t (push pkt frames) nil)))
            (lambda () session)
            (lambda () (reverse frames))
            r)))

(defun test-link-initiator-local ()
  (let* ((rs (generate-keypair)) (epoch-r (random-epoch)) (epoch-i (random-epoch)))
    (multiple-value-bind (peer get-session get-frames r) (scripted-responder rs epoch-r 4242)
      (multiple-value-bind (port deliver) (make-peer-port peer)
        (let ((link (stream-link-initiate port (generate-keypair) (keypair-public-bytes rs)
                                          epoch-i :our-index 77)))
          (check "link: initiator hash equals the responder's"
                 (equalp (stream-link-handshake-hash link) (handshake-hash r)))
          (check "link: initiator learned the responder's index and epoch"
                 (and (= (stream-link-their-index link) 4242)
                      (equalp (stream-link-remote-epoch link) epoch-r)))
          (let ((msg (octets #x10 (ascii "over the stream"))))
            (stream-link-send link msg :timestamp-ms 5)
            (let ((wire (first (funcall get-frames))))
              (check "link: frame is addressed to the responder's index"
                     (= (decode-u32le wire 4) 4242))
              (check "link: the responder opens the initiator's frame"
                     (equalp (fmp-open-frame (funcall get-session) wire) msg))))
          (let* ((s (funcall get-session))
                 (good (fmp-seal-frame s 77 9 (octets #x11 (ascii "back")))))
            ;; non-fatal drops first: tampered, wrong index, a handshake packet
            (funcall deliver (flip good 20))
            (let ((e (link-error-of (lambda () (stream-link-receive link)))))
              (check "link: a tampered frame is :frame-rejected"
                     (and e (eq (link-error-reason e) :frame-rejected)))
              (check "link: ... and it is NOT fatal" (and e (not (link-error-fatal-p e)))))
            (funcall deliver (fmp-seal-frame s 78 9 (octets #x11)))
            (check "link: a frame for another index is dropped"
                   (eq (reason-of (lambda () (stream-link-receive link))) :wrong-receiver-index))
            (funcall deliver (octets 1 0 110 0 (filler 110)))
            (check "link: a msg1 on an established link is :unexpected-phase"
                   (eq (reason-of (lambda () (stream-link-receive link))) :unexpected-phase))
            (check "link: the drops left the port open" (not (byte-port-closed port)))
            (funcall deliver good)
            (multiple-value-bind (m ts flags) (stream-link-receive link)
              (check "link: control -- the untampered frame still opens"
                     (and (equalp m (octets #x11 (ascii "back"))) (= ts 9) (= flags 0))))
            (funcall deliver (octets 7 0 0 0))
            (check "link: an unknown phase after the handshake is fatal"
                   (let ((e (link-error-of (lambda () (stream-link-receive link)))))
                     (and e (eq (link-error-reason e) :unknown-phase) (link-error-fatal-p e))))
            (check "link: ... and closed the port" (byte-port-closed port))))))))

(defun genuine-msg1 (rs &key (idx 31))
  "A real msg1 packet to RS's static key, and the initiator state that wrote it."
  (let ((i (fips-make-ik-initiator (generate-keypair) (keypair-public-bytes rs) (random-epoch))))
    (values (build-msg1 idx (ik-write-message-1 i)) i)))

(defun test-link-responder-local ()
  (let ((rs (generate-keypair)))
    (multiple-value-bind (m1 i) (genuine-msg1 rs :idx 31)
      (multiple-value-bind (port written) (make-octet-source-port m1)
        (let ((link (stream-link-accept port rs (random-epoch) :our-index 900)))
          (multiple-value-bind (sidx ridx m2) (parse-msg2 (funcall written))
            (check "link: responder wrote a 69-byte msg2 to the initiator's index"
                   (and (= (length (funcall written)) 69) (= sidx 900) (= ridx 31)))
            (ik-read-message-2 i m2)
            (check "link: responder hash equals the initiator's"
                   (equalp (stream-link-handshake-hash link) (handshake-hash i)))))))
    ;; handshake failures, each against its control
    (check "link: an established frame before the handshake is :unexpected-phase"
           (eq (reason-of (lambda () (stream-link-accept
                                      (make-octet-source-port (octets 0 0 10 0 (filler 38)))
                                      rs (random-epoch))))
               :unexpected-phase))
    (check "link: a msg1 of the right length but garbage noise is :handshake-failed"
           (eq (reason-of (lambda () (stream-link-accept
                                      (make-octet-source-port (octets 1 0 110 0 (filler 110)))
                                      rs (random-epoch))))
               :handshake-failed))
    (check "link: a msg1 with nonzero flags is :handshake-failed (Msg1Header::parse)"
           (let ((m1 (copy-seq (genuine-msg1 rs))))
             (setf (aref m1 1) 1)
             (eq (reason-of (lambda () (stream-link-accept (make-octet-source-port m1)
                                                           rs (random-epoch))))
                 :handshake-failed)))
    (check "link: a msg1 for another responder key is :handshake-failed"
           (eq (reason-of (lambda () (stream-link-accept
                                      (make-octet-source-port (genuine-msg1 (generate-keypair)))
                                      rs (random-epoch))))
               :handshake-failed))
    (check "link: a wrong-length msg1 is :handshake-size-mismatch"
           (eq (reason-of (lambda () (stream-link-accept
                                      (make-octet-source-port (octets 1 0 50 0 (filler 50)))
                                      rs (random-epoch))))
               :handshake-size-mismatch))
    ;; the initiator refuses a msg2 that names another index
    (multiple-value-bind (peer) (scripted-responder rs (random-epoch) 5)
      (let ((port (make-peer-port (lambda (pkt)
                                    (let ((m2 (copy-seq (funcall peer pkt))))
                                      (setf (aref m2 8) (logxor (aref m2 8) 1)) m2)))))
        (check "link: a msg2 for another receiver index is refused"
               (eq (reason-of (lambda () (stream-link-initiate port (generate-keypair)
                                                               (keypair-public-bytes rs)
                                                               (random-epoch) :our-index 64)))
                   :wrong-receiver-index))))))

(defun test-link-local ()
  (test-stream-remaining)
  (test-read-fmp-packet)
  (test-link-initiator-local)
  (test-link-responder-local))
