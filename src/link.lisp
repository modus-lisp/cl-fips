;;;; link.lisp -- FMP over a byte stream: packet framing and the link state machine.
;;;;
;;;; Pure: no socket calls, no FFI, no implementation packages.  Bytes move
;;;; through a BYTE-PORT, two closures supplied by whoever owns the stream (the
;;;; SBCL/usocket adapter in transport/, an in-memory pipe in the tests, and
;;;; eventually a modus socket):
;;;;
;;;;   (read-exactly N DEADLINE) -> (values OCTETS STATUS)
;;;;       STATUS :ok      OCTETS is exactly N bytes
;;;;              :eof     the peer closed; OCTETS holds what arrived first
;;;;              :timeout DEADLINE (an absolute GET-INTERNAL-REAL-TIME value,
;;;;                       or NIL for none) passed first
;;;;   (write-all OCTETS) -> :ok | :closed
;;;;   (close)            -> anything; must be idempotent
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510.
;;;;   src/transport/framing.rs  read_fmp_packet (lines 112-185): prefix, version
;;;;       check, per-phase remaining length, MTU bound on established frames,
;;;;       exact payload_len for msg1 (110) and msg2 (65), close on an unknown
;;;;       phase.  The deadline is per COMPLETE packet, not per byte, as in
;;;;       src/transport/tcp/mod.rs tcp_receive_loop / InboundDeadline (a peer
;;;;       that drips a packet slower than the deadline is dropped).
;;;;   src/transport/tcp/mod.rs  default MTU 1400 (docs: "Default MTU | 1400").
;;;;   src/proto/fmp/wire.rs     msg1/msg2 packets (rekey.lisp BUILD-/PARSE-MSG*).
;;;;
;;;; Policy: every FATAL link error closes the port before it is signalled, so
;;;; "reject by closing" is decided here and not left to the adapter.  An
;;;; established frame that fails to open is NOT fatal: upstream's dataplane
;;;; drops such a frame and keeps the connection (encrypted.rs).

(in-package #:cl-fips)

(defconstant +stream-prefix-size+ 4)
(defconstant +default-stream-mtu+ 1400 "transport/tcp: default TCP MTU.")
(defconstant +msg1-payload-len+ (- +msg1-wire-size+ +stream-prefix-size+))   ; 110
(defconstant +msg2-payload-len+ (- +msg2-wire-size+ +stream-prefix-size+))   ; 65

(define-condition link-error (error)
  ((reason :initarg :reason :reader link-error-reason)
   (detail :initarg :detail :initform nil :reader link-error-detail)
   (fatal :initarg :fatal :initform t :reader link-error-fatal-p))
  (:report (lambda (c s)
             (format s "FMP link error ~s~@[: ~a~]~:[ (frame dropped, link kept)~;~]"
                     (link-error-reason c) (link-error-detail c) (link-error-fatal-p c)))))

(defstruct (byte-port (:constructor make-byte-port (read-exactly write-all &optional close-fn)))
  read-exactly write-all close-fn (closed nil))

(defun byte-port-close (port)
  (unless (byte-port-closed port)
    (setf (byte-port-closed port) t)
    (when (byte-port-close-fn port) (funcall (byte-port-close-fn port)))))

(defun link-fail (port reason &optional detail (fatal t))
  "Signal a LINK-ERROR; a fatal one closes PORT first."
  (when (and fatal port) (byte-port-close port))
  (error 'link-error :reason reason :detail detail :fatal fatal))

;;; --- Framing ---------------------------------------------------------------------

(defun fmp-packet-remaining (prefix &optional (mtu +default-stream-mtu+))
  "framing.rs read_fmp_packet, the decision half.  From the 4-byte PREFIX return
   (values REMAINING NIL NIL), the byte count that follows it, or
   (values NIL REASON DETAIL) for a packet the stream must be closed on."
  (multiple-value-bind (version phase flags payload-len) (decode-prefix prefix)
    (declare (ignore flags))
    (cond
      ((/= version +fmp-version+)
       (values nil :unknown-version (format nil "unknown FMP version: ~d" version)))
      ((= phase +phase-established+)
       (let ((max (max 0 (- mtu +fmp-established-header-size+ +aead-tag-size+))))
         (if (> payload-len max)
             (values nil :payload-too-large
                     (format nil "payload_len ~d exceeds max ~d" payload-len max))
             (values (+ (- +fmp-established-header-size+ +stream-prefix-size+)
                        payload-len +aead-tag-size+)
                     nil nil))))
      ((= phase +phase-msg1+)
       (if (/= payload-len +msg1-payload-len+)
           (values nil :handshake-size-mismatch
                   (format nil "handshake phase 0x1: expected payload_len ~d, got ~d"
                           +msg1-payload-len+ payload-len))
           (values payload-len nil nil)))
      ((= phase +phase-msg2+)
       (if (/= payload-len +msg2-payload-len+)
           (values nil :handshake-size-mismatch
                   (format nil "handshake phase 0x2: expected payload_len ~d, got ~d"
                           +msg2-payload-len+ payload-len))
           (values payload-len nil nil)))
      (t (values nil :unknown-phase (format nil "unknown FMP phase: 0x~2,'0x" phase))))))

(defun deadline-after-ms (timeout-ms)
  (and timeout-ms
       (+ (get-internal-real-time)
          (ceiling (* timeout-ms internal-time-units-per-second) 1000))))

(defun %port-read (port n deadline at-boundary)
  (multiple-value-bind (octets status) (funcall (byte-port-read-exactly port) n deadline)
    (ecase status
      (:ok octets)
      (:timeout (link-fail port :timeout "no complete packet within the read deadline"))
      (:eof (if (and at-boundary (zerop (length octets)))
                (link-fail port :peer-closed "peer closed the stream")
                (link-fail port :truncated
                           (format nil "stream ended inside a packet (~d of ~d bytes)"
                                   (length octets) n)))))))

(defun read-fmp-packet (port &key (mtu +default-stream-mtu+) timeout-ms)
  "Read one whole FMP packet (prefix included) from PORT.  TIMEOUT-MS bounds the
   complete packet.  Every failure is a fatal LINK-ERROR and closes PORT:
   :peer-closed (EOF between packets), :truncated (EOF inside one), :timeout,
   :unknown-version, :unknown-phase, :handshake-size-mismatch, :payload-too-large."
  (let* ((deadline (deadline-after-ms timeout-ms))
         (prefix (%port-read port +stream-prefix-size+ deadline t)))
    (multiple-value-bind (remaining reason detail) (fmp-packet-remaining prefix mtu)
      (unless remaining (link-fail port reason detail))
      (u8-append prefix (%port-read port remaining deadline nil)))))

(defun write-fmp-packet (port packet)
  (unless (eq (funcall (byte-port-write-all port) packet) :ok)
    (link-fail port :write-failed "peer stopped accepting bytes")))

;;; --- The link state machine -------------------------------------------------------

(defstruct (stream-link (:constructor %make-stream-link))
  port role session our-index their-index handshake-hash
  remote-static remote-epoch (mtu +default-stream-mtu+) timeout-ms (started 0)
  (state :established))

(defun random-session-index ()
  (decode-u32le (natrium:random-bytes 4)))

(defun %handshake-packet (port expected-phase mtu timeout-ms)
  (let ((packet (read-fmp-packet port :mtu mtu :timeout-ms timeout-ms)))
    (unless (= (prefix-phase packet) expected-phase)
      (link-fail port :unexpected-phase
                 (format nil "expected phase 0x~x during the handshake, got 0x~x"
                         expected-phase (prefix-phase packet))))
    packet))

(defmacro %noise-or-fail ((port reason &optional (fatal t)) &body body)
  `(handler-case (progn ,@body)
     (natrium.noise:noise-error (e)
       (link-fail ,port ,reason (natrium.noise:noise-error-reason e) ,fatal))))

(defun %finish-link (port role hs our their mtu timeout-ms)
  (%make-stream-link
   :port port :role role :our-index our :their-index their
   :handshake-hash (natrium.noise:handshake-hash hs)
   :remote-static (secp256k1-fast.ecdh:encode-pubkey (natrium.noise:hs-remote-static hs))
   :remote-epoch (natrium.noise:hs-remote-epoch hs)
   :session (natrium.noise:handshake-into-session hs)
   :mtu mtu :timeout-ms timeout-ms :started (get-internal-real-time)))

(defun stream-link-initiate (port static remote-static-bytes local-epoch
                             &key (our-index (random-session-index))
                               (mtu +default-stream-mtu+) timeout-ms)
  "IK initiator on PORT: write msg1, read msg2.  Returns an established STREAM-LINK."
  (let* ((hs (fips-make-ik-initiator static remote-static-bytes local-epoch)))
    (write-fmp-packet port (build-msg1 our-index (natrium.noise:ik-write-message-1 hs)))
    (let ((packet (%handshake-packet port +phase-msg2+ mtu timeout-ms)))
      (multiple-value-bind (their-index receiver-index noise-msg2) (parse-msg2 packet)
        (unless their-index (link-fail port :handshake-failed "malformed msg2"))
        (unless (= receiver-index our-index)
          (link-fail port :wrong-receiver-index
                     (format nil "msg2 names index ~d, ours is ~d" receiver-index our-index)))
        (%noise-or-fail (port :handshake-failed)
          (natrium.noise:ik-read-message-2 hs noise-msg2))
        (%finish-link port :initiator hs our-index their-index mtu timeout-ms)))))

(defun stream-link-accept (port static local-epoch
                           &key (our-index (random-session-index))
                             (mtu +default-stream-mtu+) timeout-ms)
  "IK responder on PORT: read msg1, write msg2.  Returns an established STREAM-LINK."
  (let* ((hs (fips-make-ik-responder static local-epoch))
         (packet (%handshake-packet port +phase-msg1+ mtu timeout-ms)))
    (multiple-value-bind (their-index noise-msg1) (parse-msg1 packet)
      (unless their-index (link-fail port :handshake-failed "malformed msg1"))
      (%noise-or-fail (port :handshake-failed)
        (natrium.noise:ik-read-message-1 hs noise-msg1))
      (let ((noise-msg2 (natrium.noise:ik-write-message-2 hs)))
        (write-fmp-packet port (build-msg2 our-index their-index noise-msg2))
        (%finish-link port :responder hs our-index their-index mtu timeout-ms)))))

(defun stream-link-elapsed-ms (link)
  (floor (* 1000 (- (get-internal-real-time) (stream-link-started link)))
         internal-time-units-per-second))

(defun stream-link-send (link link-message &key (flags 0) timestamp-ms)
  "Seal LINK-MESSAGE ([msg_type][body]) to the peer's index and write it."
  (let ((wire (fmp-seal-frame (stream-link-session link) (stream-link-their-index link)
                              (ldb (byte 32 0) (or timestamp-ms (stream-link-elapsed-ms link)))
                              link-message :flags flags)))
    (when (> (length wire) (stream-link-mtu link))
      (error 'link-error :reason :mtu-exceeded :fatal nil
                         :detail (format nil "~d-byte packet over MTU ~d"
                                         (length wire) (stream-link-mtu link))))
    (write-fmp-packet (stream-link-port link) wire)
    wire))

(defun stream-link-receive (link &key (timeout-ms (stream-link-timeout-ms link)))
  "Read the next packet.  An established frame for our index that opens returns
   (values link-message timestamp-ms flags counter).  Framing failures are fatal
   and close the port; a frame that does not open, names another index, or a
   handshake packet on an established link (rekey is not wired to the stream
   yet) is a NON-fatal LINK-ERROR: the frame is dropped and the link stays up."
  (let* ((port (stream-link-port link))
         (wire (read-fmp-packet port :mtu (stream-link-mtu link) :timeout-ms timeout-ms)))
    (unless (= (prefix-phase wire) +phase-established+)
      (link-fail port :unexpected-phase
                 (format nil "phase 0x~x on an established link" (prefix-phase wire)) nil))
    (let ((idx (decode-u32le wire 4)))
      (unless (= idx (stream-link-our-index link))
        (link-fail port :wrong-receiver-index
                   (format nil "frame for index ~d, ours is ~d" idx (stream-link-our-index link))
                   nil)))
    (multiple-value-bind (msg ts flags idx counter)
        (%noise-or-fail (port :frame-rejected nil)
          (fmp-open-frame (stream-link-session link) wire))
      (declare (ignore idx))
      (values msg ts flags counter))))

(defun stream-link-close (link)
  (byte-port-close (stream-link-port link)))

;;; --- An in-memory port (tests; also a template for a new adapter) ----------------

(defun make-octet-source-port (octets &key (on-exhaustion :eof))
  "A read-only port over OCTETS.  When they run out, a read returns ON-EXHAUSTION
   (:eof or :timeout) with the bytes it got.  Writes are collected; the second
   value is a function returning everything written so far."
  (let ((pos 0) (written (u8-vector 0)))
    (values
     (make-byte-port
      (lambda (n deadline)
        (declare (ignore deadline))
        (let* ((end (min (length octets) (+ pos n)))
               (got (subseq octets pos end)))
          (setf pos end)
          (values (coerce got '(vector (unsigned-byte 8)))
                  (if (= (length got) n) :ok on-exhaustion))))
      (lambda (bytes) (setf written (u8-append written bytes)) :ok)
      (lambda () nil))
     (lambda () written))))
