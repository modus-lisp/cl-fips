;;;; link.lisp -- FMP over a byte stream: packet framing and the link state machine.
;;;;
;;;; Pure: no socket calls, no FFI, no implementation packages.  Bytes move
;;;; through a BYTE-PORT, two closures supplied by whoever owns the stream (the
;;;; sb-bsd-sockets adapter in transport/ (SBCL and hosted modus), an in-memory pipe in the tests, and
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
  read-exactly write-all close-fn (closed nil)
  ;; a DATAGRAM port (UDP) delivers whole packets instead of a byte stream:
  ;;   (read-packet DEADLINE) -> (values OCTETS STATUS), STATUS :ok | :timeout | :eof
  ;; One datagram is one FMP packet, with no stream framing around it.
  (read-packet nil))

(defun make-datagram-port (read-packet write-all &optional close-fn)
  "A port over a datagram transport.  READ-PACKET returns one whole datagram; WRITE-ALL
   sends OCTETS as one datagram.  On such a port a malformed packet or a read timeout
   drops nothing but that packet: there is no stream to lose sync with."
  (let ((p (make-byte-port nil write-all close-fn)))
    (setf (byte-port-read-packet p) read-packet)
    p))

(defun datagram-port-p (port) (and (byte-port-read-packet port) t))

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

(defun %read-datagram-packet (port mtu deadline)
  "One datagram, checked as the stream rule would check it: the prefix's length must
   account for exactly the bytes that arrived.  Failures are NON-fatal (the datagram
   is dropped), except :peer-closed, which means the port itself was closed."
  (multiple-value-bind (octets status) (funcall (byte-port-read-packet port) deadline)
    (ecase status
      (:ok
       (when (< (length octets) +stream-prefix-size+)
         (link-fail port :truncated (format nil "~d-byte datagram" (length octets)) nil))
       (multiple-value-bind (remaining reason detail) (fmp-packet-remaining octets mtu)
         (cond ((null remaining) (link-fail port reason detail nil))
               ((/= (length octets) (+ +stream-prefix-size+ remaining))
                (link-fail port :length-mismatch
                           (format nil "~d-byte datagram, its prefix says ~d"
                                   (length octets) (+ +stream-prefix-size+ remaining))
                           nil))
               (t octets))))
      (:timeout (link-fail port :timeout "no datagram within the read deadline" nil))
      (:eof (link-fail port :peer-closed "the datagram port was closed")))))

(defun read-fmp-packet (port &key (mtu +default-stream-mtu+) timeout-ms)
  "Read one whole FMP packet (prefix included) from PORT.  TIMEOUT-MS bounds the
   complete packet.  On a stream port every failure is a fatal LINK-ERROR and closes
   PORT: :peer-closed (EOF between packets), :truncated (EOF inside one), :timeout,
   :unknown-version, :unknown-phase, :handshake-size-mismatch, :payload-too-large.
   On a datagram port they are non-fatal and drop the one datagram."
  (when (datagram-port-p port)
    (return-from read-fmp-packet
      (%read-datagram-packet port mtu (deadline-after-ms timeout-ms))))
  (let* ((deadline (deadline-after-ms timeout-ms))
         (prefix (%port-read port +stream-prefix-size+ deadline t)))
    (multiple-value-bind (remaining reason detail) (fmp-packet-remaining prefix mtu)
      (unless remaining (link-fail port reason detail))
      (u8-append prefix (%port-read port remaining deadline nil)))))

(defun write-fmp-packet (port packet)
  (unless (eq (funcall (byte-port-write-all port) packet) :ok)
    (link-fail port :write-failed "peer stopped accepting bytes")))

;;; --- The link state machine -------------------------------------------------------
;;;
;;; After the handshake a STREAM-LINK is a shell around two pure machines: an
;;; FMP-LINK (rekey.lisp: current / previous / pending sessions, the K bit, the
;;; rekey decision and its msg1/msg2 packets) and an MMP-PEER (mmp.lisp: the
;;; receiver and sender report state).  The shell owns the port and the clock;
;;; every entry point takes an optional NOW-MS (milliseconds since the link was
;;; established) so tests can drive time, and reads the clock when it is absent.
;;;
;;; Rekey packets on the established stream (upstream src/transport/framing.rs
;;; read_fmp_packet accepts phases 0x1 and 0x2 on any connection; node/handlers/
;;; handshake.rs routes a msg1 from an established peer to the rekey responder
;;; and a msg2 naming our in-flight rekey index to complete_rekey_msg2):
;;;   msg1 from the peer -> LINK-RECEIVE answers it; the msg2 is written here.
;;;   msg2 for our rekey -> held pending; the next STREAM-LINK-POLL cuts over.
;;;   a frame that authenticates on the pending session (K flipped) -> adopted.
;;; Both promotions reset the MMP receiver, as peer/active.rs (1401, 1447) does.

(defstruct (stream-link (:constructor %make-stream-link))
  port role fmp mmp handshake-hash remote-static remote-epoch
  (mtu +default-stream-mtu+) timeout-ms (started 0) (state :established)
  ;; routing (optional): our spanning-tree declaration and our reachability filter
  tree                          ; a TREE-STATE, or NIL when routing is off
  (tree-dirty nil)              ; a peer announce arrived: recompute before sending
  (announce-due-ms nil)         ; when the next TreeAnnounce + FilterAnnounce is due
  (filter-seq 0)
  (peer-filter nil)             ; the last FilterAnnounce the peer sent us, as a bloom
  (filter-source nil))          ; NIL: send our own address only; else (link) -> bloom

(defun stream-link-session (link) (link-session (stream-link-fmp link)))
(defun stream-link-our-index (link) (link-our-index (stream-link-fmp link)))
(defun stream-link-their-index (link) (link-their-index (stream-link-fmp link)))
(defun stream-link-k-bit (link) (link-k-bit (stream-link-fmp link)))

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

(defun %make-mmp (reports)
  "REPORTS: T (SenderReport and ReceiverReport), :NO-RR (SenderReport only),
   :RR-ONLY, or NIL (no reports)."
  (make-mmp-peer :send-rr (and (member reports '(t :rr-only)) t)
                 :send-sr (and (member reports '(t :no-rr)) t)))

(defun %finish-link (port role hs our their mtu timeout-ms static local-epoch
                     rekey-config jitter-fn reports routing)
  (let* ((hash (natrium.noise:handshake-hash hs))
         (remote (secp256k1-fast.ecdh:encode-pubkey (natrium.noise:hs-remote-static hs)))
         (epoch (natrium.noise:hs-remote-epoch hs))
         (session (natrium.noise:handshake-into-session hs))
         ;; ROUTING is T (a tree of this link's own), or a TREE-STATE shared by every
         ;; link of a node that has more than one peer.  A node presents one tree.
         (tree (when routing
                 (let ((st (if (tree-state-p routing)
                               routing
                               (make-tree-state (secp256k1-fast.ecdh:keypair-secret static)))))
                   ;; the peer's key came from the handshake, so its node_addr is known
                   (tree-register-peer-key st (node-addr remote) (subseq remote 1))
                   st))))
    (%make-stream-link
     :tree tree
     :port port :role role :handshake-hash hash :remote-static remote :remote-epoch epoch
     :fmp (make-link session our their :static static :peer-static-bytes remote
                                       :local-epoch local-epoch :remote-epoch epoch :now-ms 0
                                       :allocate-index #'random-session-index
                                       :config (or rekey-config (make-rekey-config))
                                       :jitter-fn (or jitter-fn (constantly 0)))
     :mmp (%make-mmp reports)
     :mtu mtu :timeout-ms timeout-ms :started (get-internal-real-time))))

(defconstant +msg1-first-resend-ms+ 1000
  "handshake_resend_interval_ms; the interval doubles, so resends go at about
   t+1, t+3, t+7, t+15 s (handshake.rs).")
(defconstant +handshake-timeout-ms+ 30000 "handshake_timeout_secs.")

(defstruct (link-dial (:constructor %make-link-dial))
  "An IK initiation in progress: msg1 is out, msg2 not yet in."
  port static remote local-epoch our-index hs msg1 mtu
  timeout-ms                    ; the link's read timeout, as the caller gave it
  give-up-ms                    ; how long the dial waits for msg2
  rekey-config jitter-fn reports routing
  started next-resend (resend-in +msg1-first-resend-ms+))

(defun stream-link-dial (port static remote-static-bytes local-epoch
                         &key (our-index (random-session-index)) (mtu +default-stream-mtu+)
                           timeout-ms rekey-config jitter-fn (reports t) routing (now-ms 0))
  "Start an IK initiation on PORT: build and write msg1.  Returns a LINK-DIAL, which
   LINK-DIAL-RECEIVE completes when msg2 arrives and LINK-DIAL-TICK resends (on a
   datagram port) or abandons.  Nothing here waits."
  (let* ((hs (fips-make-ik-initiator static remote-static-bytes local-epoch))
         (msg1 (build-msg1 our-index (natrium.noise:ik-write-message-1 hs))))
    (write-fmp-packet port msg1)
    (%make-link-dial :port port :static static :remote remote-static-bytes
                     :local-epoch local-epoch :our-index our-index :hs hs :msg1 msg1
                     :mtu mtu :timeout-ms timeout-ms
                     :give-up-ms (or timeout-ms +handshake-timeout-ms+)
                     :rekey-config rekey-config :jitter-fn jitter-fn :reports reports
                     :routing routing :started now-ms
                     :next-resend (+ now-ms +msg1-first-resend-ms+))))

(defun %dial-finish (dial their-index)
  (%finish-link (link-dial-port dial) :initiator (link-dial-hs dial) (link-dial-our-index dial)
                their-index (link-dial-mtu dial) (link-dial-timeout-ms dial) (link-dial-static dial)
                (link-dial-local-epoch dial) (link-dial-rekey-config dial) (link-dial-jitter-fn dial)
                (link-dial-reports dial) (link-dial-routing dial)))

(defun link-dial-receive (dial &key (timeout-ms 0))
  "Read one packet for DIAL.  Returns the established STREAM-LINK when it is the msg2
   that answers our msg1, else NIL.  On a stream port the packet must be that msg2:
   anything else is a fatal LINK-ERROR, as before.  On a datagram port anything else
   is dropped (a non-fatal LINK-ERROR for a malformed datagram, NIL otherwise),
   except a msg1: the peer is dialling us at the same time, and that returns
   (values NIL :PEER-MSG1 packet) so the caller can resolve the crossing."
  (let* ((port (link-dial-port dial))
         (mtu (link-dial-mtu dial))
         (hs (link-dial-hs dial))
         (our-index (link-dial-our-index dial)))
    (if (datagram-port-p port)
        (let ((packet (read-fmp-packet port :mtu mtu :timeout-ms timeout-ms)))
          (if (= (prefix-phase packet) +phase-msg1+)
              ;; the peer is dialling us too: the caller decides who yields
              (values nil :peer-msg1 packet)
              (multiple-value-bind (their-index receiver-index noise-msg2) (parse-msg2 packet)
                (when (and their-index (= receiver-index our-index)
                           (ignore-errors (natrium.noise:ik-try-read-message-2 hs noise-msg2) t))
                  (%dial-finish dial their-index)))))
        (let ((packet (%handshake-packet port +phase-msg2+ mtu timeout-ms)))
          (multiple-value-bind (their-index receiver-index noise-msg2) (parse-msg2 packet)
            (unless their-index (link-fail port :handshake-failed "malformed msg2"))
            (unless (= receiver-index our-index)
              (link-fail port :wrong-receiver-index
                         (format nil "msg2 names index ~d, ours is ~d" receiver-index our-index)))
            (%noise-or-fail (port :handshake-failed)
              (natrium.noise:ik-read-message-2 hs noise-msg2))
            (%dial-finish dial their-index))))))

(defun link-dial-tick (dial now-ms)
  "Abandon DIAL (a fatal LINK-ERROR :timeout, closing its port) once its timeout has
   passed; on a datagram port, resend msg1 when it is due (1 s, doubling).  Returns
   T if msg1 was resent."
  (let ((port (link-dial-port dial)))
    (when (>= (- now-ms (link-dial-started dial)) (link-dial-give-up-ms dial))
      (link-fail port :timeout "no msg2 answered our msg1"))
    (when (and (datagram-port-p port) (>= now-ms (link-dial-next-resend dial)))
      (write-fmp-packet port (link-dial-msg1 dial))
      (setf (link-dial-resend-in dial) (* 2 (link-dial-resend-in dial))
            (link-dial-next-resend dial) (+ now-ms (link-dial-resend-in dial)))
      t)))

(defun link-dial-next-due-ms (dial)
  "The time LINK-DIAL-TICK next has something to do."
  (min (+ (link-dial-started dial) (link-dial-give-up-ms dial))
       (if (datagram-port-p (link-dial-port dial)) (link-dial-next-resend dial) most-positive-fixnum)))

(defun %clock-ms ()
  (floor (* 1000 (get-internal-real-time)) internal-time-units-per-second))

(defun stream-link-initiate (port static remote-static-bytes local-epoch
                             &key (our-index (random-session-index))
                               (mtu +default-stream-mtu+) timeout-ms
                               rekey-config jitter-fn (reports t) routing)
  "IK initiator on PORT: write msg1, read msg2.  Returns an established STREAM-LINK.
   REKEY-CONFIG / JITTER-FN configure the rekey machine (stock: 120 s, no
   jitter); REPORTS selects the MMP reports STREAM-LINK-POLL emits.  On a datagram
   port msg1 is resent until it is answered or TIMEOUT-MS (default 30 s) passes.
   This is STREAM-LINK-DIAL driven to completion, waiting on the port."
  (let ((dial (stream-link-dial port static remote-static-bytes local-epoch
                                :our-index our-index :mtu mtu :timeout-ms timeout-ms
                                :rekey-config rekey-config :jitter-fn jitter-fn
                                :reports reports :routing routing :now-ms (%clock-ms))))
    (if (datagram-port-p port)
        (loop
          (let ((wait (max 0 (- (link-dial-next-due-ms dial) (%clock-ms)))))
            (let ((link (handler-case (link-dial-receive dial :timeout-ms wait)
                          (link-error (e) (when (link-error-fatal-p e) (error e)) nil))))
              (when link (return link))
              (link-dial-tick dial (%clock-ms)))))
        (link-dial-receive dial :timeout-ms timeout-ms))))

(defun stream-link-accept (port static local-epoch
                           &key (our-index (random-session-index))
                             (mtu +default-stream-mtu+) timeout-ms
                             rekey-config jitter-fn (reports t) routing)
  "IK responder on PORT: read msg1, write msg2.  Returns an established STREAM-LINK."
  (let* ((hs (fips-make-ik-responder static local-epoch))
         (packet (%handshake-packet port +phase-msg1+ mtu timeout-ms)))
    (multiple-value-bind (their-index noise-msg1) (parse-msg1 packet)
      (unless their-index (link-fail port :handshake-failed "malformed msg1"))
      (%noise-or-fail (port :handshake-failed)
        (natrium.noise:ik-read-message-1 hs noise-msg1))
      (let* ((noise-msg2 (natrium.noise:ik-write-message-2 hs))
             (msg2 (build-msg2 our-index their-index noise-msg2)))
        (write-fmp-packet port msg2)
        (let ((link (%finish-link port :responder hs our-index their-index mtu timeout-ms
                                  static local-epoch rekey-config jitter-fn reports routing)))
          ;; kept so a resent msg1 (our msg2 lost on a datagram transport) is answered
          (setf (link-setup-answer (stream-link-fmp link)) (cons (%msg1-digest packet) msg2))
          link)))))

(defun stream-link-elapsed-ms (link)
  (floor (* 1000 (- (get-internal-real-time) (stream-link-started link)))
         internal-time-units-per-second))

(defun %session-ms (link now)
  "Session-relative ms on the CURRENT session (node/mod.rs: the frame timestamp,
   and peer.session_elapsed_ms() that a timestamp echo is measured against)."
  (ldb (byte 32 0) (- now (link-session-start (stream-link-fmp link)))))

(defun stream-link-send (link link-message &key (flags 0) timestamp-ms now-ms)
  "Seal LINK-MESSAGE ([msg_type][body]) on the current session, to the peer's
   current index, with our K bit, and write it.  Counts it for SenderReports."
  (let* ((now (or now-ms (stream-link-elapsed-ms link)))
         (fmp (stream-link-fmp link))
         (session (link-session fmp))
         (counter (natrium.noise:session-current-send-counter session))
         (ts (ldb (byte 32 0) (or timestamp-ms (%session-ms link now))))
         (wire (fmp-seal-frame session (link-their-index fmp) ts link-message
                               :flags (if (link-k-bit fmp) (logior flags +flag-key-epoch+) flags))))
    (when (> (length wire) (stream-link-mtu link))
      (error 'link-error :reason :mtu-exceeded :fatal nil
                         :detail (format nil "~d-byte packet over MTU ~d"
                                         (length wire) (stream-link-mtu link))))
    (write-fmp-packet (stream-link-port link) wire)
    (mmp-sender-record (mmp-sender (stream-link-mmp link)) counter ts (length wire))
    wire))

(defun %drop-reason (reason)
  "rekey.lisp's drop reasons, in this file's historic vocabulary where one exists."
  (case reason
    ((:decrypt-failed :inner-header-too-short :malformed) :frame-rejected)
    (:unknown-index :wrong-receiver-index)
    (t reason)))

(defun stream-link-receive (link &key (timeout-ms (stream-link-timeout-ms link)) now-ms)
  "Read and handle the next packet.
   An established frame that authenticates returns
     (values link-message timestamp-ms flags counter slot)
   with SLOT :current, :previous (the drain) or :adopted (the peer's first frame
   on a rekeyed session; the keys rotated here).  Frames on the current session
   feed the MMP receiver; incoming SenderReports / ReceiverReports are decoded
   into the MMP state (and still returned).
   A rekey packet returns (values NIL EVENT): :rekey-answered (a msg1 from the
   peer was answered with a msg2, written here) or :rekey-complete (the msg2 for
   our rekey; the next STREAM-LINK-POLL cuts over).
   Framing failures are fatal and close the port.  Everything upstream drops --
   a frame that does not open (:frame-rejected), names an index we do not hold
   (:wrong-receiver-index), a msg1 that is not a rekey -- is a NON-fatal
   LINK-ERROR whose reason is the drop reason; the link stays up."
  (let* ((port (stream-link-port link))
         (wire (read-fmp-packet port :mtu (stream-link-mtu link) :timeout-ms timeout-ms))
         (now (or now-ms (stream-link-elapsed-ms link)))
         (mmp (stream-link-mmp link)))
    (multiple-value-bind (kind a b c d e) (link-receive (stream-link-fmp link) wire now)
      (ecase kind
        (:frame
         (let ((msg a) (slot b) (flags c) (ts d) (counter e))
           (when (eq slot :adopted) (mmp-reset-for-rekey mmp now))
           (unless (eq slot :previous)
             (mmp-receiver-record (mmp-receiver mmp) counter ts (length wire)
                                  (logtest flags +flag-ce+) now))
           (mmp-handle-report mmp msg (%session-ms link now))
           (%handle-routing link msg)
           (values msg ts flags counter slot)))
        (:msg2 (write-fmp-packet port a) (values nil :rekey-answered))
        (:rekey-complete (values nil :rekey-complete))
        (:drop (link-fail port (%drop-reason a)
                          (format nil "phase 0x~x packet dropped: ~(~a~)" (prefix-phase wire) a)
                          nil))))))

(defconstant +routing-interval-ms+ 10000)

(defun %handle-routing (link msg)
  "A peer's TreeAnnounce updates our tree state, and our announce is recomputed
   on the next poll.  A FilterAnnounce replaces the peer's reachability filter.
   Malformed or unverified announces are ignored, as upstream drops them; they do
   not close the link."
  (let ((tree (stream-link-tree link)))
    (when (and tree (plusp (length msg)) (= (aref msg 0) +tree-announce-msg-type+))
      (handler-case
          (multiple-value-bind (decl entries) (decode-tree-announce (subseq msg 1))
            (when (tree-observe-announce tree decl entries)
              (setf (stream-link-tree-dirty link) t)))
        (error () nil)))
    (when (and (plusp (length msg)) (= (aref msg 0) +filter-announce-msg-type+))
      (handler-case
          (setf (stream-link-peer-filter link) (nth-value 1 (decode-filter-announce (subseq msg 1))))
        (error () nil)))))

(defun %unix-seconds ()
  (- (get-universal-time) 2208988800))

(defun %send-routing (link now-ms unix-seconds)
  "Recompute our declaration, then send our TreeAnnounce and FilterAnnounce.  Our
   reachability filter holds our own node_addr only: a leaf with one peer has
   nothing else behind it."
  (let ((tree (stream-link-tree link)))
    (tree-recompute tree unix-seconds)
    (stream-link-send link (tree-current-announce tree) :now-ms now-ms)
    (let ((filter (if (stream-link-filter-source link)
                      (funcall (stream-link-filter-source link) link)
                      (let ((own (make-bloom)))
                        (bloom-insert own (tree-state-node tree))
                        own))))
      (incf (stream-link-filter-seq link))
      (stream-link-send link (encode-filter-announce (stream-link-filter-seq link) filter)
                        :now-ms now-ms))
    (setf (stream-link-tree-dirty link) nil
          (stream-link-announce-due-ms link) (+ now-ms +routing-interval-ms+))))

(defun stream-link-poll (link &key now-ms unix-seconds)
  "The periodic tick: the rekey decision (cutover, drain, retire, initiate --
   a msg1 is written here), then any MMP report that is due.  Returns
   (values rekey-actions report-msg-types)."
  (let* ((now (or now-ms (stream-link-elapsed-ms link)))
         (mmp (stream-link-mmp link))
         (sent '()))
    (multiple-value-bind (packets actions) (link-tick (stream-link-fmp link) now)
      (when (member :cutover actions) (mmp-reset-for-rekey mmp now))
      (dolist (p packets) (write-fmp-packet (stream-link-port link) p))
      (dolist (m (mmp-due-reports mmp now))
        (stream-link-send link m :now-ms now)
        (push (aref m 0) sent))
      (when (and (stream-link-tree link)
                 (or (null (stream-link-announce-due-ms link))
                     (>= now (stream-link-announce-due-ms link))
                     (stream-link-tree-dirty link)))
        (%send-routing link now (or unix-seconds (%unix-seconds)))
        (push +tree-announce-msg-type+ sent)
        (push +filter-announce-msg-type+ sent))
      (values actions (nreverse sent)))))

(defun stream-link-close (link)
  "Close the link.  With routing, the peer leaves our tree: a shared tree must not
   keep a dead link's peer as a parent candidate."
  (let ((tree (stream-link-tree link)))
    (when tree
      (tree-forget-peer tree (node-addr (stream-link-remote-static link)))))
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
