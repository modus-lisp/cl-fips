;;;; fsp.lisp -- the end-to-end data plane: SessionDatagram (link msg 0x00) and the
;;;; FSP session (Noise XK over SessionDatagrams, then established frames).
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510.
;;;;   src/proto/link.rs          SessionDatagram: [0x00][ttl u8][path_mtu u16 LE]
;;;;                              [src 16][dest 16][payload], header 36 bytes
;;;;   src/proto/fsp/wire.rs      FSP common prefix; SessionSetup / SessionAck /
;;;;                              SessionMsg3 bodies; the established 12-byte header;
;;;;                              DataPacket port header [src_port][dst_port] (LE)
;;;;   src/proto/coord.rs         coordinates: [count u16 LE][count x 16-byte addrs]
;;;;   src/node/session/mod.rs    seal: header = build_fsp_header(counter, flags,
;;;;                              plaintext.len()); AEAD with AAD = header
;;;;   src/node/handlers/session.rs  dst_port 256 = IPv6 shim; other ports go to the
;;;;                              native datagram API
;;;;
;;;; Handshake, phases in the FSP common prefix (version 0, flags 0):
;;;;   1 SessionSetup  [flags u8][src coords][dest coords][hs_len u16][XK msg1 33]
;;;;   2 SessionAck    [flags u8][src coords][dest coords][hs_len u16][XK msg2 57]
;;;;   3 SessionMsg3   [flags u8][hs_len u16][XK msg3 73]
;;;; Established frame: [header 12][AEAD(inner 6 + body)]; the inner header is
;;;; [timestamp u32 LE][msg_type u8][inner_flags u8]; a DataPacket body is
;;;; [src_port u16 LE][dst_port u16 LE][data].

(in-package #:cl-fips)

(defconstant +session-datagram-msg-type+ #x00)
(defconstant +session-datagram-header-size+ 36)
(defconstant +fsp-data-packet-msg-type+ #x10)
(defconstant +fsp-port-ipv6-shim+ 256)
(defconstant +fsp-inner-header-size+ 6)
(defconstant +fsp-port-header-size+ 4)

;;; --- SessionDatagram (link layer) ------------------------------------------

(defun encode-session-datagram (src dest payload &key (ttl 64) (path-mtu #xffff))
  "The full link plaintext, msg_type first."
  (bytes-cat (bytes-of +session-datagram-msg-type+ ttl)
             (encode-u16le path-mtu)
             src dest payload))

(defun decode-session-datagram (body)
  "Parse the body after msg_type.  Returns (values src dest ttl path-mtu payload)."
  (when (< (length body) 35)
    (error "SessionDatagram too short: ~d bytes" (length body)))
  (values (bytes-slice body 3 19)
          (bytes-slice body 19 35)
          (aref body 0)
          (decode-u16le body 1)
          (bytes-slice body 35)))

;;; --- FSP handshake bodies ----------------------------------------------------

(defun encode-coords (addrs)
  "A coordinate on the wire: a count, then the node addresses root-last."
  (when (null addrs) (error "a coordinate needs at least one entry"))
  (apply #'bytes-cat (encode-u16le (length addrs)) addrs))

(defun decode-coords (body offset)
  "Returns (values addresses next-offset).  A zero count is malformed."
  (let ((count (decode-u16le body offset)))
    (when (zerop count) (error "coordinate with zero entries"))
    (values (loop for i from 0 below count
                  collect (bytes-slice body (+ offset 2 (* 16 i)) (+ offset 18 (* 16 i))))
            (+ offset 2 (* 16 count)))))

(defun encode-fsp-setup-or-ack (phase flags src-coords dest-coords hs)
  "SessionSetup (PHASE 1) and SessionAck (PHASE 2) share one body layout."
  (let ((body (bytes-cat (bytes-of flags)
                         (encode-coords src-coords)
                         (encode-coords dest-coords)
                         (encode-u16le (length hs))
                         hs)))
    (bytes-cat (encode-prefix 0 phase 0 (length body)) body)))

(defun decode-fsp-setup-or-ack (wire)
  "Returns (values phase flags src-coords dest-coords hs) for a phase 1 or 2 FSP
   handshake packet."
  (let ((phase (prefix-phase wire)))
    (unless (member phase '(1 2)) (error "not a SessionSetup or SessionAck"))
    (let ((body (bytes-slice wire 4)))
      (multiple-value-bind (src off) (decode-coords body 1)
        (multiple-value-bind (dest off2) (decode-coords body off)
          (let* ((hs-len (decode-u16le body off2))
                 (hs (bytes-slice body (+ off2 2) (+ off2 2 hs-len))))
            (unless (= (length hs) hs-len) (error "FSP handshake payload truncated"))
            (unless (= (+ off2 2 hs-len) (length body))
              (error "FSP handshake packet has trailing bytes"))
            (values phase (aref body 0) src dest hs)))))))

(defun encode-fsp-msg3 (hs)
  (let ((body (bytes-cat (bytes-of 0) (encode-u16le (length hs)) hs)))
    (bytes-cat (encode-prefix 0 3 0 (length body)) body)))

(defun decode-fsp-msg3 (wire)
  (unless (= (prefix-phase wire) 3) (error "not a SessionMsg3"))
  (let* ((body (bytes-slice wire 4))
         (hs-len (decode-u16le body 1))
         (hs (bytes-slice body 3 (+ 3 hs-len))))
    (unless (and (= (length hs) hs-len) (= (+ 3 hs-len) (length body)))
      (error "SessionMsg3 length mismatch"))
    hs))

;;; --- Established frames -------------------------------------------------------

(defconstant +fsp-flag-cp+ #x01 "Coords Present: cleartext coordinates follow the header.")
(defconstant +fsp-flag-k+ #x02 "Key epoch: the frame is sealed under the rekeyed session.")

(defun fsp-seal-data (session src-port dst-port data timestamp-ms &key coords k)
  "An established FSP frame carrying a DataPacket.  COORDS, when given, is
   (src-addrs dest-addrs) and sets CP: the two cleartext coordinates sit between
   the header and the ciphertext, and are not part of the AAD.  Returns the wire
   bytes."
  (let* ((inner (bytes-cat (encode-u32le timestamp-ms)
                           (bytes-of +fsp-data-packet-msg-type+ 0)
                           (encode-u16le src-port) (encode-u16le dst-port)
                           data))
         (counter (natrium.noise:session-current-send-counter session))
         (flags (logior (if coords +fsp-flag-cp+ 0) (if k +fsp-flag-k+ 0)))
         (header (encode-fsp-header flags (length inner) counter))
         (ct (natrium.noise:session-encrypt-with-aad session inner header))
         (cleartext (if coords
                        (bytes-cat (encode-coords (first coords))
                                   (encode-coords (second coords)))
                        (bytes-of))))
    (bytes-cat header cleartext ct)))

(defun fsp-skip-coords (wire offset)
  "The offset just past two cleartext coordinates starting at OFFSET.  A zero
   count is an absent coordinate, as upstream's decode_optional_coords reads it."
  (dotimes (i 2 offset)
    (when (> (+ offset 2) (length wire))
      (error 'natrium.noise:noise-error :reason "CP coordinates truncated"))
    (let ((count (decode-u16le wire offset)))
      (incf offset (+ 2 (* 16 count)))
      (when (> offset (length wire))
        (error 'natrium.noise:noise-error :reason "CP coordinates truncated")))))

(defun fsp-open-data (session wire)
  "Open an established FSP frame.  Returns (values msg-type src-port dst-port data
   timestamp-ms) for a DataPacket.  Signals NOISE-ERROR for anything upstream
   drops: a short frame, a bad tag, a replay."
  (when (< (length wire) (+ +fsp-header-size+ +aead-tag-size+))
    (error 'natrium.noise:noise-error :reason "FSP frame shorter than header + tag"))
  (unless (= (prefix-phase wire) 0) (error "not an established FSP frame"))
  (multiple-value-bind (flags payload-len counter) (decode-fsp-header wire)
    (declare (ignore flags))
    (let* ((header (bytes-slice wire 0 +fsp-header-size+))
           (ct-start (if (logtest (aref wire 1) +fsp-flag-cp+)
                         (fsp-skip-coords wire +fsp-header-size+)
                         +fsp-header-size+))
           (ct (bytes-slice wire ct-start))
           (inner (natrium.noise:session-decrypt-with-replay-check session counter ct header)))
      (unless (= (length inner) payload-len)
        (error 'natrium.noise:noise-error :reason "FSP payload length does not match"))
      (when (< (length inner) +fsp-inner-header-size+)
        (error 'natrium.noise:noise-error :reason "FSP inner header too short"))
      (let ((msg-type (aref inner 4)))
        (unless (= msg-type +fsp-data-packet-msg-type+)
          (return-from fsp-open-data (values msg-type nil nil inner (decode-u32le inner 0))))
        (when (< (length inner) (+ +fsp-inner-header-size+ +fsp-port-header-size+))
          (error 'natrium.noise:noise-error :reason "DataPacket too short for port header"))
        (values msg-type
                (decode-u16le inner 6)
                (decode-u16le inner 8)
                (bytes-slice inner 10)
                (decode-u32le inner 0))))))

;;; --- The initiator's side of the session ------------------------------------

(defstruct (fsp-initiator (:constructor %make-fsp-initiator))
  hs              ; natrium.noise XK handshake state (our initial handshake)
  session         ; the established NOISE-SESSION, or NIL until msg3 is sent
  our-addr peer-addr our-coords peer-coords
  (phase :idle)   ; :idle :setup-sent :established
  static local-epoch peer-static   ; for rekeys
  pending-hs      ; a rekey the peer started: XK responder, after msg2 is sent
  pending-session ; the rekeyed session, waiting for its first frame to take over
  previous-session ; the session we replaced, kept for late frames
  (k nil)         ; the K bit we set on frames sent under the current session
  rekey-hs        ; a rekey we started: XK initiator, until its msg2 arrives
  rekey-initiator-p ; we started the rekey in flight: cutover is ours, on our next send
  last-msg3       ; the msg3 we last took, so a resend of it is not an error
  setup-datagram  ; our SessionSetup, kept so an unanswered one can be resent
  (setup-sent-at 0) (setup-tries 0))  ; when it was last sent, and how often

(defun make-fsp-initiator (static peer-static-bytes local-epoch our-addr peer-addr
                           our-coords peer-coords)
  (%make-fsp-initiator :hs (fips-make-xk-initiator static peer-static-bytes local-epoch)
                       :our-addr our-addr :peer-addr peer-addr
                       :our-coords our-coords :peer-coords peer-coords
                       :static static :local-epoch local-epoch
                       :peer-static peer-static-bytes))

(defun fsp-setup-datagram (fi &optional (now 0))
  "Start the handshake: the SessionDatagram that carries SessionSetup (XK msg1).
   The datagram is kept, so FSP-RESEND-SETUP can send the same msg1 again."
  (let* ((msg1 (natrium.noise:xk-write-message-1 (fsp-initiator-hs fi)))
         (setup (encode-fsp-setup-or-ack 1 0 (fsp-initiator-our-coords fi)
                                         (fsp-initiator-peer-coords fi) msg1))
         (datagram (encode-session-datagram (fsp-initiator-our-addr fi) (fsp-initiator-peer-addr fi)
                                            setup)))
    (setf (fsp-initiator-phase fi) :setup-sent
          (fsp-initiator-setup-datagram fi) datagram
          (fsp-initiator-setup-sent-at fi) now
          (fsp-initiator-setup-tries fi) 1)
    datagram))

(defun fsp-resend-setup (fi now &key (interval-ms 4000) (max-tries 10))
  "The SessionSetup again, if the handshake is still unanswered and the interval
   has passed.  Returns the link message to send, or NIL.  The same msg1 goes out:
   a SessionAck lost on the way is answered the same way."
  (when (and (eq (fsp-initiator-phase fi) :setup-sent)
             (fsp-initiator-setup-datagram fi)
             (< (fsp-initiator-setup-tries fi) max-tries)
             (>= (- now (fsp-initiator-setup-sent-at fi)) interval-ms))
    (setf (fsp-initiator-setup-sent-at fi) now)
    (incf (fsp-initiator-setup-tries fi))
    (fsp-initiator-setup-datagram fi)))

(defun fsp-handle-ack (fi datagram-body)
  "Consume the SessionAck (XK msg2) carried in a SessionDatagram body.  Returns the
   SessionDatagram body that carries SessionMsg3 (XK msg3); the session is
   established from that point."
  (unless (eq (fsp-initiator-phase fi) :setup-sent)
    (error "no SessionSetup is outstanding"))
  (multiple-value-bind (src dest ttl mtu payload) (decode-session-datagram datagram-body)
    (declare (ignore ttl mtu))
    (unless (and (equalp src (fsp-initiator-peer-addr fi))
                 (equalp dest (fsp-initiator-our-addr fi)))
      (error "SessionAck is not from our peer"))
    (multiple-value-bind (phase flags src-coords dest-coords hs) (decode-fsp-setup-or-ack payload)
      (declare (ignore flags src-coords dest-coords))
      (unless (= phase 2) (error "expected SessionAck, got phase ~d" phase))
      (natrium.noise:xk-read-message-2 (fsp-initiator-hs fi) hs)
      (let* ((msg3 (natrium.noise:xk-write-message-3 (fsp-initiator-hs fi)))
             (ok (encode-fsp-msg3 msg3)))
        (setf (fsp-initiator-session fi)
              (natrium.noise:handshake-into-session (fsp-initiator-hs fi))
              (fsp-initiator-phase fi) :established)
        (encode-session-datagram (fsp-initiator-our-addr fi) (fsp-initiator-peer-addr fi) ok)))))

(defun fsp-data-datagram (fi data &key (src-port 0) (dst-port +fsp-port-ipv6-shim+)
                                    (timestamp-ms 0))
  "A SessionDatagram carrying one DataPacket on the established session."
  (unless (eq (fsp-initiator-phase fi) :established) (error "session is not established"))
  (fsp-cut-over-if-ours fi)
  (encode-session-datagram (fsp-initiator-our-addr fi) (fsp-initiator-peer-addr fi)
                           (fsp-seal-data (fsp-initiator-session fi) src-port dst-port
                                          data timestamp-ms :k (fsp-initiator-k fi))))

;;; --- Session rekey, answered as responder -----------------------------------
;;; The node starts an FSP rekey on the established session: SessionSetup (XK
;;; msg1), we answer SessionAck (msg2), it sends SessionMsg3 (msg3).  The rekeyed
;;; session is adopted when a frame first opens under it; the one it replaces is
;;; kept as the previous session for late frames.

(defun fsp-handle-rekey-setup (fi datagram-body)
  "Answer a SessionSetup that rekeys the established session.  Returns the
   SessionDatagram body that carries SessionAck (XK msg2)."
  (unless (eq (fsp-initiator-phase fi) :established)
    (error "a rekey needs an established session"))
  (multiple-value-bind (src dest ttl mtu payload) (decode-session-datagram datagram-body)
    (declare (ignore ttl mtu))
    (unless (and (equalp src (fsp-initiator-peer-addr fi))
                 (equalp dest (fsp-initiator-our-addr fi)))
      (error "rekey SessionSetup is not from our peer"))
    (multiple-value-bind (phase flags src-c dest-c msg1) (decode-fsp-setup-or-ack payload)
      (declare (ignore flags src-c dest-c))
      (unless (= phase 1) (error "expected SessionSetup, got phase ~d" phase))
      (let ((hs (fips-make-xk-responder (fsp-initiator-static fi) (fsp-initiator-local-epoch fi))))
        (natrium.noise:xk-read-message-1 hs msg1)
        (let* ((msg2 (natrium.noise:xk-write-message-2 hs))
               (ack (encode-fsp-setup-or-ack 2 0 (fsp-initiator-our-coords fi)
                                             (fsp-initiator-peer-coords fi) msg2)))
          (setf (fsp-initiator-pending-hs fi) hs)
          (encode-session-datagram (fsp-initiator-our-addr fi) (fsp-initiator-peer-addr fi) ack))))))

(defun fsp-handle-rekey-msg3 (fi datagram-body)
  "Consume SessionMsg3 (XK msg3) of a rekey we answered.  The rekeyed session waits
   for its first authenticated frame before it takes over."
  (multiple-value-bind (src dest ttl mtu payload) (decode-session-datagram datagram-body)
    (declare (ignore ttl mtu))
    (unless (and (equalp src (fsp-initiator-peer-addr fi))
                 (equalp dest (fsp-initiator-our-addr fi)))
      (error "rekey SessionMsg3 is not from our peer"))
    (let ((msg3 (decode-fsp-msg3 payload)))
      (cond
        ((and (fsp-initiator-last-msg3 fi) (equalp msg3 (fsp-initiator-last-msg3 fi)))
         ;; the peer resends msg3 until a frame under the new session reaches it
         :duplicate)
        ((null (fsp-initiator-pending-hs fi)) (error "no rekey is outstanding"))
        (t
         (let ((hs (fsp-initiator-pending-hs fi)))
           (natrium.noise:xk-read-message-3 hs msg3)
           (setf (fsp-initiator-pending-session fi) (natrium.noise:handshake-into-session hs)
                 (fsp-initiator-pending-hs fi) nil
                 (fsp-initiator-last-msg3 fi) msg3)
           t))))))

;;; --- A rekey we start ---------------------------------------------------------
;;; SessionSetup (XK msg1) on the established session, the peer's SessionAck
;;; (msg2), our SessionMsg3 (msg3).  The new session takes over on our first frame
;;; under it, which carries the K bit; the peer switches when it sees that frame.

(defun fsp-start-rekey (fi)
  "Begin a rekey of the established session.  Returns the SessionDatagram link
   message that carries SessionSetup (XK msg1)."
  (unless (eq (fsp-initiator-phase fi) :established) (error "a rekey needs an established session"))
  (when (fsp-initiator-rekey-hs fi) (error "a rekey is already in flight"))
  (let* ((hs (fips-make-xk-initiator (fsp-initiator-static fi) (fsp-initiator-peer-static fi)
                                     (fsp-initiator-local-epoch fi)))
         (msg1 (natrium.noise:xk-write-message-1 hs))
         (setup (encode-fsp-setup-or-ack 1 0 (fsp-initiator-our-coords fi)
                                         (fsp-initiator-peer-coords fi) msg1)))
    (setf (fsp-initiator-rekey-hs fi) hs)
    (encode-session-datagram (fsp-initiator-our-addr fi) (fsp-initiator-peer-addr fi) setup)))

(defun fsp-handle-rekey-ack (fi datagram-body)
  "Consume the peer's SessionAck (XK msg2) for a rekey we started.  Returns the
   SessionDatagram link message that carries SessionMsg3 (XK msg3)."
  (unless (fsp-initiator-rekey-hs fi) (error "no rekey is outstanding"))
  (multiple-value-bind (src dest ttl mtu payload) (decode-session-datagram datagram-body)
    (declare (ignore ttl mtu))
    (unless (and (equalp src (fsp-initiator-peer-addr fi))
                 (equalp dest (fsp-initiator-our-addr fi)))
      (error "rekey SessionAck is not from our peer"))
    (multiple-value-bind (phase flags src-c dest-c msg2) (decode-fsp-setup-or-ack payload)
      (declare (ignore flags src-c dest-c))
      (unless (= phase 2) (error "expected SessionAck, got phase ~d" phase))
      (let ((hs (fsp-initiator-rekey-hs fi)))
        (natrium.noise:xk-read-message-2 hs msg2)
        (let ((msg3 (natrium.noise:xk-write-message-3 hs)))
          (setf (fsp-initiator-pending-session fi) (natrium.noise:handshake-into-session hs)
                (fsp-initiator-rekey-hs fi) nil
                (fsp-initiator-rekey-initiator-p fi) t)
          (encode-session-datagram (fsp-initiator-our-addr fi) (fsp-initiator-peer-addr fi)
                                   (encode-fsp-msg3 msg3)))))))

(defun fsp-cut-over-if-ours (fi)
  "On our first frame under a rekey we started, the new session becomes current
   and the K bit goes on."
  (when (and (fsp-initiator-rekey-initiator-p fi) (fsp-initiator-pending-session fi))
    (setf (fsp-initiator-previous-session fi) (fsp-initiator-session fi)
          (fsp-initiator-session fi) (fsp-initiator-pending-session fi)
          (fsp-initiator-pending-session fi) nil
          (fsp-initiator-rekey-initiator-p fi) nil
          (fsp-initiator-k fi) t)))

(defun fsp-open-any (fi wire)
  "Open an established frame.  It is tried under the current session, then under
   the rekeyed session (which completes the cutover: it becomes current and the
   one it replaces becomes the previous session), then under the previous session
   (late frames sent before the cutover).  Returns the values FSP-OPEN-DATA
   returns; a frame that opens under none of them is refused."
  (let ((cur (fsp-initiator-session fi))
        (pend (fsp-initiator-pending-session fi))
        (prev (fsp-initiator-previous-session fi)))
    (flet ((try (session)
             (and session
                  (handler-case (multiple-value-list (fsp-open-data session wire))
                    (natrium.noise:noise-error () nil)))))
      (let ((opened (try cur)))
        (when opened (return-from fsp-open-any (values-list opened))))
      (let ((opened (try pend)))
        (when opened
          (setf (fsp-initiator-previous-session fi) cur
                (fsp-initiator-session fi) pend
                (fsp-initiator-pending-session fi) nil
                (fsp-initiator-k fi) t)
          (return-from fsp-open-any (values-list opened))))
      (let ((opened (try prev)))
        (when opened (return-from fsp-open-any (values-list opened))))
      ;; nothing opened: report the failure the way FSP-OPEN-DATA does
      (fsp-open-data cur wire))))
