;;;; fsp-test.lisp -- the SessionDatagram and FSP codecs (src/fsp.lisp), and a
;;;; complete XK handshake and data exchange between two in-memory endpoints.
;;;;
;;;;   F1  SessionDatagram: byte layout offset by offset; round trip; short rejected
;;;;   F2  coordinates: count and addresses, root last; zero count rejected
;;;;   F3  SessionSetup / SessionAck / SessionMsg3 bodies: round trip; wrong phase,
;;;;       truncated and trailing bytes rejected
;;;;   F4  the full XK handshake (initiator and responder in memory), then DataPacket
;;;;       in both directions, with the port header and inner header checked
;;;;   F5  negative controls: a tampered frame, a replayed frame, a SessionAck from
;;;;       the wrong peer

(in-package #:cl-fips.test)

(defun fsp-addr (n) (make-array 16 :element-type '(unsigned-byte 8) :initial-element n))

(defun test-session-datagram ()
  (let* ((src (fsp-addr 1)) (dest (fsp-addr 2))
         (msg (encode-session-datagram src dest (octets 9 8 7) :ttl 64 :path-mtu #x1234)))
    (check "SessionDatagram header is 36 bytes with the payload after it"
           (= (length msg) (+ 36 3)))
    (check "SessionDatagram msg_type 0x00 at offset 0" (= (aref msg 0) 0))
    (check "SessionDatagram ttl at offset 1" (= (aref msg 1) 64))
    (check "SessionDatagram path_mtu LE at offsets 2-3"
           (and (= (aref msg 2) #x34) (= (aref msg 3) #x12)))
    (check "SessionDatagram src at offsets 4-19" (equalp (subseq msg 4 20) src))
    (check "SessionDatagram dest at offsets 20-35" (equalp (subseq msg 20 36) dest))
    (multiple-value-bind (s d ttl mtu payload) (decode-session-datagram (subseq msg 1))
      (check "SessionDatagram round trip"
             (and (equalp s src) (equalp d dest) (= ttl 64) (= mtu #x1234)
                  (equalp payload (octets 9 8 7)))))
    (check "a SessionDatagram body shorter than the header is rejected"
           (handler-case (progn (decode-session-datagram (subseq msg 1 30)) nil)
             (error () t)))))

(defun test-coords ()
  (let ((c (encode-coords (list (fsp-addr 5) (fsp-addr 9)))))
    (check "coordinate: count LE then 16-byte addresses in order"
           (and (= (length c) 34) (= (aref c 0) 2) (= (aref c 1) 0)
                (= (aref c 2) 5) (= (aref c 18) 9)))
    (multiple-value-bind (addrs next) (decode-coords c 0)
      (check "coordinate round trip" (and (= (length addrs) 2) (= next 34)
                                          (equalp (second addrs) (fsp-addr 9)))))
    (check "a zero-entry coordinate is rejected"
           (handler-case (progn (decode-coords (octets 0 0) 0) nil) (error () t)))))

(defun test-fsp-bodies ()
  (let* ((hs (octets 1 2 3 4 5)) (c (list (fsp-addr 1)))
         (setup (encode-fsp-setup-or-ack 1 0 c c hs)))
    (check "SessionSetup prefix is version 0, phase 1, flags 0"
           (and (= (aref setup 0) #x01) (= (aref setup 1) 0)))
    (multiple-value-bind (phase flags src dest got) (decode-fsp-setup-or-ack setup)
      (check "SessionSetup round trip"
             (and (= phase 1) (= flags 0) (equalp got hs)
                  (equalp (first src) (fsp-addr 1)) (equalp (first dest) (fsp-addr 1)))))
    (check "a SessionAck phase byte is 0x02"
           (= (aref (encode-fsp-setup-or-ack 2 0 c c hs) 0) #x02))
    (check "SessionSetup with a trailing byte is rejected"
           (handler-case (progn (decode-fsp-setup-or-ack (u8-cat setup (octets 0))) nil)
             (error () t)))
    (check "SessionSetup truncated is rejected"
           (handler-case (progn (decode-fsp-setup-or-ack (subseq setup 0 (- (length setup) 1))) nil)
             (error () t)))
    (let ((m3 (encode-fsp-msg3 hs)))
      (check "SessionMsg3 prefix is phase 3" (= (aref m3 0) #x03))
      (check "SessionMsg3 round trip" (equalp (decode-fsp-msg3 m3) hs)))
    (check "a SessionMsg3 with a bad length is rejected"
           (handler-case (progn (decode-fsp-msg3 (subseq (encode-fsp-msg3 hs) 0 7)) nil)
             (error () t)))))

(defun fsp-handshake-pair ()
  "Returns (values initiator responder-hs-after-msg3 initiator-session responder-session)
   after a complete XK handshake carried in SessionDatagrams."
  (let* ((ka (generate-keypair)) (kb (generate-keypair))
         (a (fsp-addr 10)) (b (fsp-addr 20))
         (fi (make-fsp-initiator ka (keypair-public-bytes kb) (octets 1 1 1 1 1 1 1 1)
                                 a b (list a) (list b)))
         (rh (fips-make-xk-responder kb (octets 2 2 2 2 2 2 2 2))))
    ;; msg1: initiator -> responder
    (let ((d1 (fsp-setup-datagram fi)))
      (multiple-value-bind (src dest ttl mtu payload) (decode-session-datagram (subseq d1 1))
        (declare (ignore ttl mtu src dest))
        (multiple-value-bind (phase flags src-c dest-c hs) (decode-fsp-setup-or-ack payload)
          (declare (ignore flags src-c dest-c))
          (assert (= phase 1))
          (natrium.noise:xk-read-message-1 rh hs))))
    ;; msg2: responder -> initiator
    (let* ((m2 (natrium.noise:xk-write-message-2 rh))
           (ack (encode-fsp-setup-or-ack 2 0 (list b) (list a) m2))
           (d2 (encode-session-datagram b a ack)))
      ;; msg3: initiator consumes msg2 and produces msg3
      (let ((d3 (fsp-handle-ack fi (subseq d2 1))))
        (multiple-value-bind (src dest ttl mtu payload) (decode-session-datagram (subseq d3 1))
          (declare (ignore ttl mtu src dest))
          (natrium.noise:xk-read-message-3 rh (decode-fsp-msg3 payload)))))
    (values fi rh (fsp-initiator-session fi)
            (natrium.noise:handshake-into-session rh))))

(defun test-fsp-handshake-and-data ()
  (multiple-value-bind (fi rh init-session resp-session) (fsp-handshake-pair)
    (declare (ignore rh))
    (check "the initiator reaches the established phase"
           (eq (fsp-initiator-phase fi) :established))
    ;; initiator -> responder
    (let* ((d (fsp-data-datagram fi (ascii-octets "hello from lisp") :src-port 7 :dst-port 256
                                    :timestamp-ms 1234))
           (wire (subseq d 36)))
      (multiple-value-bind (msg-type sp dp data ts) (fsp-open-data resp-session wire)
        (check "DataPacket open: msg_type 0x10, ports and timestamp"
               (and (= msg-type #x10) (= sp 7) (= dp 256) (= ts 1234)))
        (check "DataPacket open: payload intact"
               (equalp data (ascii-octets "hello from lisp")))
        ;; the frame's layout: a 12-byte header, then the AEAD of inner + port + body
        (check "frame header is 12 bytes and carries the body length"
               (= (decode-u16le wire 2) (+ 6 4 (length (ascii-octets "hello from lisp")))))
        ;; N2: a replay is refused
        (check "a replayed frame is refused"
               (handler-case (progn (fsp-open-data resp-session wire) nil)
                 (natrium.noise:noise-error () t)))
        ;; N1: a tampered frame is refused
        (let ((bad (copy-seq wire)))
          (setf (aref bad (- (length bad) 1)) (logxor 1 (aref bad (- (length bad) 1))))
          (check "a tampered frame is refused"
                 (handler-case (progn (fsp-open-data resp-session bad) nil)
                   (natrium.noise:noise-error () t))))))
    ;; responder -> initiator
    (let* ((payload (ascii-octets "hello back"))
           (inner-seal (fsp-seal-data resp-session 0 3 payload 99)))
      (multiple-value-bind (msg-type sp dp data ts) (fsp-open-data init-session inner-seal)
        (check "responder -> initiator DataPacket opens"
               (and (= msg-type #x10) (= sp 0) (= dp 3) (= ts 99)
                    (equalp data payload)))))))

(defun test-fsp-wrong-peer ()
  (let* ((ka (generate-keypair)) (kb (generate-keypair))
         (a (fsp-addr 10)) (b (fsp-addr 20))
         (fi (make-fsp-initiator ka (keypair-public-bytes kb) (octets 1 1 1 1 1 1 1 1)
                                 a b (list a) (list b))))
    (fsp-setup-datagram fi)
    (let* ((ack (encode-fsp-setup-or-ack 2 0 (list b) (list a) (octets 0)))
           (from-stranger (encode-session-datagram (fsp-addr 99) a ack)))
      (check "a SessionAck from a stranger is refused"
             (handler-case (progn (fsp-handle-ack fi (subseq from-stranger 1)) nil)
               (error () t))))))

(defun test-fsp-cp-frames ()
  "A CP-flagged frame: coordinates sit between the header and the ciphertext."
  (multiple-value-bind (fi rh init-session resp-session) (fsp-handshake-pair)
    (declare (ignore fi rh))
    (let* ((src (list (fsp-addr 10) (fsp-addr 20)))
           (dst (list (fsp-addr 30)))
           (wire (fsp-seal-data resp-session 0 3 (ascii-octets "with coords") 7
                                :coords (list src dst))))
      (check "a CP frame sets bit 0 of the flags byte" (logtest (aref wire 1) 1))
      (check "a CP frame carries both coordinates before the ciphertext"
             (= (decode-u16le wire 12) 2))
      (multiple-value-bind (mt sp dp data ts) (fsp-open-data init-session wire)
        (check "a CP DataPacket opens with its coordinates skipped"
               (and (= mt #x10) (= sp 0) (= dp 3) (= ts 7)
                    (equalp data (ascii-octets "with coords")))))
      ;; N: the CP bit set on a frame with no coordinates must not open
      (let ((bad (copy-seq wire)))
        (setf (aref bad 12) 9 (aref bad 13) 0)
        (check "a CP frame with a corrupt coordinate count is refused"
               (handler-case (progn (fsp-open-data init-session bad) nil)
                 (error () t)))))))

(defun fsp-rekey-setup-body (fi nh b a)
  "The node's rekey msg1 as a SessionDatagram body, answered by FI.  Returns the
   SessionAck body (XK msg2) that FI produces."
  (let ((m1 (natrium.noise:xk-write-message-1 nh)))
    (fsp-handle-rekey-setup
     fi (subseq (encode-session-datagram b a (encode-fsp-setup-or-ack 1 0 (list b) (list a) m1)) 1))))

(defun fsp-rekey-ack-payload (ack-link-message)
  "The SessionAck payload inside a SessionDatagram link message (msg_type first)."
  (nth-value 4 (decode-session-datagram (subseq ack-link-message 1))))

(defun test-fsp-rekey ()
  "The node rekeys the established session; we answer as responder, adopt the new
   session on its first authenticated frame, and keep the old one for late frames."
  (let* ((ka (generate-keypair)) (kb (generate-keypair))   ; ours, the node's
         (a (fsp-addr 10)) (b (fsp-addr 20))
         (fi (make-fsp-initiator ka (keypair-public-bytes kb) (octets 1 1 1 1 1 1 1 1)
                                 a b (list a) (list b)))
         (rh (fips-make-xk-responder kb (octets 2 2 2 2 2 2 2 2))))
    ;; the initial session, as in FSP-HANDSHAKE-PAIR
    (let* ((d1 (fsp-setup-datagram fi))
           (setup-payload (nth-value 4 (decode-session-datagram (subseq d1 1)))))
      (natrium.noise:xk-read-message-1 rh (nth-value 4 (decode-fsp-setup-or-ack setup-payload))))
    (let* ((m2 (natrium.noise:xk-write-message-2 rh))
           (d3 (fsp-handle-ack fi (subseq (encode-session-datagram b a (encode-fsp-setup-or-ack 2 0 (list b) (list a) m2)) 1))))
      (natrium.noise:xk-read-message-3 rh (decode-fsp-msg3 (nth-value 4 (decode-session-datagram (subseq d3 1))))))
    (let* ((rs-old (natrium.noise:handshake-into-session rh))
           (rs-old-i (fsp-initiator-session fi))
           (old-frame (fsp-seal-data rs-old 0 3 (ascii-octets "old") 1)))
      (check "before the rekey, the initial session opens"
             (equalp (nth-value 3 (fsp-open-any fi old-frame)) (ascii-octets "old")))
      ;; the node starts a rekey: SessionSetup (XK msg1); we answer SessionAck (msg2)
      (let* ((nh (fips-make-xk-initiator kb (keypair-public-bytes ka) (octets 3 3 3 3 3 3 3 3)))
             (ack (fsp-rekey-setup-body fi nh b a))
             (ack-payload (fsp-rekey-ack-payload ack)))
        (check "the rekey SessionSetup is answered with a SessionAck (phase 2)"
               (= (prefix-phase ack-payload) 2))
        (natrium.noise:xk-read-message-2 nh (nth-value 4 (decode-fsp-setup-or-ack ack-payload)))
        ;; the node's SessionMsg3 completes the rekey on our side
        (let* ((m3 (natrium.noise:xk-write-message-3 nh))
               (msg3 (encode-session-datagram b a (encode-fsp-msg3 m3))))
          (check "the rekey SessionMsg3 is taken"
                 (fsp-handle-rekey-msg3 fi (subseq msg3 1)))
          (let* ((ns (natrium.noise:handshake-into-session nh))
                 (new-frame (fsp-seal-data ns 0 3 (ascii-octets "new epoch") 2 :k t)))
            (check "a frame under the rekeyed session does not open under the old one"
                   (handler-case (progn (fsp-open-data rs-old new-frame) nil)
                     (natrium.noise:noise-error () t)))
            (check "a frame under the rekeyed session opens and completes the cutover"
                   (equalp (nth-value 3 (fsp-open-any fi new-frame)) (ascii-octets "new epoch")))
            (check "after the cutover the new session is current, the old one kept"
                   (and (not (eq (fsp-initiator-session fi) rs-old-i))
                        (eq (fsp-initiator-previous-session fi) rs-old-i)
                        (null (fsp-initiator-pending-session fi))))
            (check "after the cutover our frames carry the K bit"
                   (fsp-initiator-k fi))
            (let ((late (fsp-seal-data rs-old 0 3 (ascii-octets "late") 3)))
              (check "a late frame under the replaced session still opens"
                     (equalp (nth-value 3 (fsp-open-any fi late)) (ascii-octets "late"))))
            (let ((wire (subseq (fsp-data-datagram fi (ascii-octets "from lisp") :dst-port 3) 36)))
              (check "our post-rekey frame opens under the node's new session"
                     (equalp (nth-value 3 (fsp-open-data ns wire)) (ascii-octets "from lisp"))))
            (let ((stranger (fsp-seal-data (nth-value 3 (fsp-handshake-pair)) 0 3
                                           (ascii-octets "x") 4)))
              (check "a frame under no session of ours is refused"
                     (handler-case (progn (fsp-open-any fi stranger) nil)
                       (natrium.noise:noise-error () t))))))))))

(defun test-fsp ()
  (test-session-datagram)
  (test-coords)
  (test-fsp-bodies)
  (test-fsp-handshake-and-data)
  (test-fsp-cp-frames)
  (test-fsp-rekey)
  (test-fsp-wrong-peer))
