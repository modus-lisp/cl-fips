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

(defun fsp-seal-data (session src-port dst-port data timestamp-ms)
  "An established FSP frame carrying a DataPacket.  Returns the wire bytes."
  (let* ((inner (bytes-cat (encode-u32le timestamp-ms)
                           (bytes-of +fsp-data-packet-msg-type+ 0)
                           (encode-u16le src-port) (encode-u16le dst-port)
                           data))
         (counter (natrium.noise:session-current-send-counter session))
         (header (encode-fsp-header 0 (length inner) counter))
         (ct (natrium.noise:session-encrypt-with-aad session inner header)))
    (bytes-cat header ct)))

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
           (ct (bytes-slice wire +fsp-header-size+))
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
  hs              ; natrium.noise XK handshake state
  session         ; established NOISE-SESSION, or NIL until msg3 is sent
  our-addr peer-addr our-coords peer-coords
  (phase :idle))  ; :idle :setup-sent :established

(defun make-fsp-initiator (static peer-static-bytes local-epoch our-addr peer-addr
                           our-coords peer-coords)
  (%make-fsp-initiator :hs (fips-make-xk-initiator static peer-static-bytes local-epoch)
                       :our-addr our-addr :peer-addr peer-addr
                       :our-coords our-coords :peer-coords peer-coords))

(defun fsp-setup-datagram (fi)
  "Start the handshake: the SessionDatagram that carries SessionSetup (XK msg1)."
  (let* ((msg1 (natrium.noise:xk-write-message-1 (fsp-initiator-hs fi)))
         (setup (encode-fsp-setup-or-ack 1 0 (fsp-initiator-our-coords fi)
                                         (fsp-initiator-peer-coords fi) msg1)))
    (setf (fsp-initiator-phase fi) :setup-sent)
    (encode-session-datagram (fsp-initiator-our-addr fi) (fsp-initiator-peer-addr fi) setup)))

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
  (encode-session-datagram (fsp-initiator-our-addr fi) (fsp-initiator-peer-addr fi)
                           (fsp-seal-data (fsp-initiator-session fi) src-port dst-port
                                          data timestamp-ms)))
