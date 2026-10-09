;;;; real-node-test.lisp -- cl-fips against a REAL upstream `fips` node over TCP.
;;;;
;;;; Not part of run-tests.sh: it needs the upstream daemon (jmcorgan/fips @
;;;; 57bc510, built with cargo).  Driven by scripts/run-real-node.sh, which
;;;; writes the node's YAML, starts and stops the node, and greps its log.  This
;;;; file is the Lisp half, run as `sbcl --script test/real-node-test.lisp MODE DIR ...`:
;;;;
;;;;   keygen DIR            write DIR/node.key and DIR/lisp.key (secret hex, then
;;;;                         compressed public hex) and DIR/lisp.npub, DIR/node.addr
;;;;   dial DIR PORT SECS    Lisp IK initiator dials the node on 127.0.0.1:PORT
;;;;   accept DIR PORT SECS  Lisp IK responder listens on 127.0.0.1:PORT; the node
;;;;                         dials it as a configured static peer
;;;;
;;;; dial/accept: complete the handshake, send a Heartbeat (msg_type 0x51, no
;;;; body) every 5 s, poll the link every ~200 ms (rekey decisions; MMP
;;;; SenderReports and ReceiverReports when due), and log every established
;;;; frame the node sends by its inner msg_type until SECS pass.  The node's
;;;; rekey msg1 is answered on the stream and its new-epoch frames adopted; our
;;;; own rekey (120 s) is initiated by the poll.  CL_FIPS_REPORTS=no-rr turns the
;;;; ReceiverReports off (the negative control in run-real-node.sh).
;;;; Exit 0 when the handshake completed, the remote static key is the node's,
;;;; and at least one TreeAnnounce (0x10) and one Heartbeat (0x51) arrived.

(require :asdf)
(let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
  (push (merge-pathnames "../" here) asdf:*central-registry*))
(push (pathname (format nil "~a/" (or (sb-ext:posix-getenv "NATRIUM_DIR")
                                      (namestring (merge-pathnames "natrium" (user-homedir-pathname))))))
      asdf:*central-registry*)
(push (pathname (format nil "~a/" (or (sb-ext:posix-getenv "SECP256K1_DIR")
                                      (namestring (merge-pathnames "secp256k1-fast" (user-homedir-pathname))))))
      asdf:*central-registry*)
(let ((ql (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (when (probe-file ql) (load ql)))
(if (find-package "QL")
    (funcall (find-symbol "QUICKLOAD" "QL") "usocket" :silent t)
    (asdf:load-system "usocket"))
(asdf:load-system "cl-fips/transport")

(defpackage #:cl-fips.real-node (:use #:common-lisp))
(in-package #:cl-fips.real-node)

(defun hex (v) (format nil "~(~{~2,'0x~}~)" (coerce v 'list)))
(defun unhex (s)
  (let ((v (make-array (floor (length s) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length v) v)
      (setf (aref v i) (parse-integer s :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))
(defun ms () (floor (* 1000 (get-internal-real-time)) internal-time-units-per-second))
(defun out (fmt &rest args) (apply #'format t fmt args) (terpri) (finish-output))

;;; NIP-19 npub: bech32 (BIP-173 checksum constant 1) of the 32-byte x-only key.
(defun bech32-polymod (values)
  (let ((gen #(#x3b6a57b2 #x26508e6d #x1ea119fa #x3d4233dd #x2a1462b3)) (chk 1))
    (dolist (v values chk)
      (let ((b (ash chk -25)))
        (setf chk (logxor (ash (logand chk #x1ffffff) 5) v))
        (dotimes (i 5) (when (logbitp i b) (setf chk (logxor chk (aref gen i)))))))))

(defun npub (pubkey)
  (let* ((x (if (= (length pubkey) 33) (subseq pubkey 1) pubkey))
         (alphabet "qpzry9x8gf2tvdw0s3jn54khce6mua7l") (hrp "npub")
         (data (let ((acc 0) (bits 0) (r '()))
                 (loop for b across x
                       do (setf acc (logior (ash acc 8) b)) (incf bits 8)
                          (loop while (>= bits 5)
                                do (decf bits 5) (push (ldb (byte 5 bits) acc) r)))
                 (when (plusp bits) (push (ldb (byte 5 0) (ash acc (- 5 bits))) r))
                 (nreverse r)))
         (hv (append (map 'list (lambda (c) (ash (char-code c) -5)) hrp) '(0)
                     (map 'list (lambda (c) (logand (char-code c) 31)) hrp)))
         (pm (logxor 1 (bech32-polymod (append hv data '(0 0 0 0 0 0)))))
         (chk (loop for i below 6 collect (ldb (byte 5 (* 5 (- 5 i))) pm))))
    (format nil "~a1~{~c~}" hrp (mapcar (lambda (d) (char alphabet d)) (append data chk)))))

(defun write-key (path kp)
  (with-open-file (o path :direction :output :if-exists :supersede)
    (format o "~a~%~a~%"
            (hex (secp256k1-fast:int-to-bytes32 (secp256k1-fast.ecdh::keypair-secret kp)))
            (hex (secp256k1-fast.ecdh:keypair-public-bytes kp)))))

(defun read-key (path)
  (with-open-file (i path) (list (unhex (read-line i)) (unhex (read-line i)))))

(defun keygen (dir)
  (let ((node (cl-fips:generate-keypair)) (lisp (cl-fips:generate-keypair)))
    (write-key (format nil "~a/node.key" dir) node)
    (write-key (format nil "~a/lisp.key" dir) lisp)
    (with-open-file (o (format nil "~a/lisp.npub" dir) :direction :output :if-exists :supersede)
      (write-line (npub (secp256k1-fast.ecdh:keypair-public-bytes lisp)) o))
    (with-open-file (o (format nil "~a/node.npub" dir) :direction :output :if-exists :supersede)
      (write-line (npub (secp256k1-fast.ecdh:keypair-public-bytes node)) o))
    (with-open-file (o (format nil "~a/node.addr" dir) :direction :output :if-exists :supersede)
      (write-line (hex (cl-fips:node-addr (secp256k1-fast.ecdh:keypair-public-bytes node))) o))))

(defun routing-mode ()
  "CL_FIPS_ROUTING: unset or \"on\" = send our TreeAnnounce and FilterAnnounce
   (the default); \"off\" = none (the negative control)."
  (let ((v (sb-ext:posix-getenv "CL_FIPS_ROUTING")))
    (not (equal v "off"))))

(defun reports-mode ()
  "CL_FIPS_REPORTS: unset or \"all\" = SenderReport + ReceiverReport (default),
   \"no-rr\" = SenderReport only (the negative control), \"off\" = none."
  (let ((v (sb-ext:posix-getenv "CL_FIPS_REPORTS")))
    (cond ((or (null v) (string= v "") (string= v "all")) t)
          ((string= v "no-rr") :no-rr)
          ((string= v "off") nil)
          (t (error "CL_FIPS_REPORTS must be all, no-rr or off, not ~s" v)))))

(defvar *stats* nil)
(defun bump (key) (incf (getf *stats* key 0)))

(defun probe-payload (n)
  "CL_FIPS_PROBE_BYTES: the probe's size (default 15, the text alone).  Larger
   probes are padded with a repeating pattern, so an echo that truncates or
   mangles the body shows up as a mismatch."
  (let* ((text (natrium:ascii->bytes (format nil "cl-fips probe ~d" n)))
         (want (let ((v (sb-ext:posix-getenv "CL_FIPS_PROBE_BYTES")))
                 (if (and v (plusp (length v))) (parse-integer v) (length text))))
         (out (make-array (max want (length text)) :element-type '(unsigned-byte 8))))
    (replace out text)
    (loop for i from (length text) below (length out)
          do (setf (aref out i) (+ 97 (mod (+ i n) 26))))
    out))

(defun fsp-target-pub ()
  "CL_FIPS_FSP_PEER_DIR: a directory whose node.key names a node behind our link.
   The FSP session is then with that node, reached through the linked node (the
   multi-hop run).  Unset = the linked node itself."
  (let ((dir (sb-ext:posix-getenv "CL_FIPS_FSP_PEER_DIR")))
    (and dir (plusp (length dir))
         (second (read-key (format nil "~a/node.key" dir))))))

(defun rekey-at-seconds ()
  "CL_FIPS_FSP_REKEY_AT: seconds into the exchange at which we start an FSP
   rekey (default 60; \"off\" = never)."
  (let ((v (sb-ext:posix-getenv "CL_FIPS_FSP_REKEY_AT")))
    (cond ((equal v "off") nil)
          ((and v (plusp (length v))) (parse-integer v))
          (t 60))))

(defun echo-enabled-p ()
  "CL_FIPS_ECHO: unset or \"on\" = probe the node's native-echo on port 4600
   (the default); \"off\" = probe the IPv6 shim on port 256."
  (not (equal (sb-ext:posix-getenv "CL_FIPS_ECHO") "off")))

(defun fsp-enabled-p ()
  "CL_FIPS_FSP: unset or \"on\" = run an end-to-end FSP session through the node
   (the default); \"off\" = none."
  (not (equal (sb-ext:posix-getenv "CL_FIPS_FSP") "off")))

(defun fsp-peer-coords (link node-addr)
  "The node's ancestry from its verified TreeAnnounce, or NIL before one arrives."
  (let* ((tree (cl-fips:stream-link-tree link))
         (held (and tree (gethash node-addr (cl-fips::tree-state-peers tree)))))
    (and held (mapcar #'cl-fips:coord-entry-node (cdr held)))))

(defun exchange (link sock secs static node-pub)
  "Heartbeat every 5 s; poll the link (rekey decisions, MMP reports) every
   200 ms; log each frame by msg_type and each rekey event.  Returns the
   msg_types seen."
  (let* ((t0 (ms)) (deadline (+ t0 (* 1000 secs))) (next-hb 0) (seen '())
         (last-frame-log 0)
         (fsp nil) (next-data 0) (data-count 0) (last-probe nil)
         (rekey-at (rekey-at-seconds)) (rekey-started nil)
         ;; the FSP peer: the node we are linked to, or -- with CL_FIPS_FSP_PEER_DIR
         ;; set -- a node behind it that the session reaches through that link
         (fsp-pub (or (fsp-target-pub) node-pub))
         (fsp-addr (cl-fips:node-addr fsp-pub))
         (multihop (and (fsp-target-pub) t))
         (our-addr (cl-fips:node-addr (secp256k1-fast.ecdh:keypair-public-bytes static))))
    (loop while (< (ms) deadline) do
      (when (>= (ms) next-hb)
        (cl-fips:stream-link-send link (coerce #(#x51) '(vector (unsigned-byte 8))))
        (out "~6d SENT msg_type=0x51 (Heartbeat) k=~:[0~;1~]"
             (- (ms) t0) (cl-fips:stream-link-k-bit link))
        (setf next-hb (+ (ms) 5000)))
      ;; the end-to-end session: start once the node's ancestry is known
      (when (and (fsp-enabled-p) (null fsp))
        (let ((peer-coords (or (fsp-peer-coords link fsp-addr)
                               (and multihop (list fsp-addr))))
              (tree (cl-fips:stream-link-tree link)))
          (when (and peer-coords tree (cl-fips:tree-state-entries tree))
            (setf fsp (cl-fips:make-fsp-initiator
                       static fsp-pub (natrium:random-bytes 8) our-addr fsp-addr
                       (mapcar #'cl-fips:coord-entry-node (cl-fips:tree-state-entries tree))
                       peer-coords))
            (let ((d (cl-fips:fsp-setup-datagram fsp (ms))))
              (cl-fips:stream-link-send link d)
              (out "~6d FSP SessionSetup sent to the node (XK msg1)" (- (ms) t0))))))
      ;; an unanswered SessionSetup is sent again (the relay may not know the way yet)
      (when fsp
        (let ((again (cl-fips:fsp-resend-setup fsp (ms))))
          (when again
            (cl-fips:stream-link-send link again)
            (out "~6d FSP SessionSetup resent (no SessionAck yet)" (- (ms) t0)))))
      ;; we start the FSP rekey once, after REKEY-AT seconds
      (when (and fsp rekey-at (not rekey-started)
                 (eq (cl-fips:fsp-initiator-phase fsp) :established)
                 (>= (- (ms) t0) (* 1000 rekey-at)))
        (setf rekey-started t)
        (cl-fips:stream-link-send link (cl-fips:fsp-start-rekey fsp :now (ms)))
        (out "~6d FSP rekey: SessionSetup sent (ours)" (- (ms) t0)))
      (when (and fsp (eq (cl-fips:fsp-initiator-phase fsp) :established) (>= (ms) next-data))
        (incf data-count)
        ;; CL_FIPS_ECHO=on (default): the probe goes to port 4600, which the node's
        ;; native-echo holds, so the node sends the bytes back; otherwise the IPv6
        ;; shim (256) decrypts and rejects them.
        (let* ((payload (probe-payload data-count))
               (port (if (echo-enabled-p) 4600 256))
               ;; building the datagram is what cuts over a rekey we started
               (cutting (cl-fips::fsp-initiator-rekey-initiator-p fsp))
               (d (cl-fips:fsp-data-datagram fsp payload :dst-port port
                                                         :timestamp-ms (ldb (byte 32 0) (- (ms) t0))
                                                         :now (ms))))
          ;; a DataPacket is 110 bytes of framing around its data on the link (FMP
          ;; header and tag, the SessionDatagram header, the FSP header and tag, the
          ;; inner and port headers); anything above that does not fit the link MTU
          (let ((limit (- (cl-fips::stream-link-mtu link) 110)))
            (cond
              ((> (length payload) limit)
               (out "~6d FSP probe ~d NOT SENT: ~d bytes exceeds the ~d-byte limit (link MTU ~d less 110)"
                    (- (ms) t0) data-count (length payload) limit (cl-fips::stream-link-mtu link)))
              (t
               (setf last-probe payload)
               (cl-fips:stream-link-send link d)
               (when (and cutting (not (cl-fips::fsp-initiator-rekey-initiator-p fsp)))
                 (out "~6d FSP rekey cutover (ours): the new session is current, K set" (- (ms) t0)))
               (out "~6d FSP DataPacket ~d sent (dst_port ~d)" (- (ms) t0) data-count port)))))
        (setf next-data (+ (ms) 5000)))
      (multiple-value-bind (actions reports) (cl-fips:stream-link-poll link)
        (dolist (a actions)
          (bump a)
          (when (eq a :cutover) (setf (getf *stats* :frames-since-rotate) 0))
          (out "~6d REKEY ~(~a~) our_index=~8,'0x their_index=~8,'0x k=~:[0~;1~]"
               (- (ms) t0) a (cl-fips:stream-link-our-index link)
               (cl-fips:stream-link-their-index link) (cl-fips:stream-link-k-bit link)))
        (dolist (r reports)
          (bump (if (= r 2) :rr-sent :sr-sent))))
      (when (or (listen (usocket:socket-stream sock))
                (usocket:wait-for-input sock :timeout 0.2 :ready-only t))
        (handler-case
            (multiple-value-bind (m ts flags counter slot)
                (cl-fips:stream-link-receive link :timeout-ms 10000)
              (cond
                ((null m)
                 (bump ts)                 ; the event keyword
                 (out "~6d REKEY ~(~a~) (rekey packet from the node) our_index=~8,'0x"
                      (- (ms) t0) ts (cl-fips:stream-link-our-index link)))
                ((and (= (aref m 0) 0) fsp)
                 ;; a SessionDatagram: the SessionAck during setup, then established
                 ;; FSP frames from the node (its session reports, and any data)
                 (pushnew (aref m 0) seen)
                 (handler-case
                     (let ((payload (nth-value 4 (cl-fips:decode-session-datagram (subseq m 1)))))
                       (cond
                         ((and (= (cl-fips:prefix-phase payload) 2) (cl-fips::fsp-initiator-rekey-hs fsp))
                          (let ((reply (cl-fips:fsp-handle-rekey-ack fsp (subseq m 1))))
                            (cl-fips:stream-link-send link reply)
                            (out "~6d FSP rekey: SessionAck handled; SessionMsg3 sent" (- (ms) t0))))
                         ((eq (cl-fips:fsp-initiator-phase fsp) :setup-sent)
                          (let ((reply (cl-fips:fsp-handle-ack fsp (subseq m 1))))
                            (cl-fips:stream-link-send link reply)
                            (out "~6d FSP SessionAck received; SessionMsg3 sent; session established"
                                 (- (ms) t0))))
                         ((= (cl-fips:prefix-phase payload) 1)
                          ;; the node rekeys the FSP session: answer its msg1 with SessionAck
                          (let ((reply (cl-fips:fsp-handle-rekey-setup fsp (subseq m 1) :now (ms))))
                            (cl-fips:stream-link-send link reply)
                            (out "~6d FSP rekey: SessionSetup answered with SessionAck" (- (ms) t0))))
                         ((= (cl-fips:prefix-phase payload) 3)
                          (cl-fips:fsp-handle-rekey-msg3 fsp (subseq m 1) :now (ms))
                          (out "~6d FSP rekey: SessionMsg3 taken; the new session waits for its first frame"
                               (- (ms) t0)))
                         ((zerop (cl-fips:prefix-phase payload))
                          (multiple-value-bind (mt sp dp data)
                              (handler-case
                                  (let ((had-pending (cl-fips::fsp-initiator-pending-session fsp)))
                                    (multiple-value-prog1 (cl-fips:fsp-open-any fsp payload :now (ms))
                                      (when (and had-pending (null (cl-fips::fsp-initiator-pending-session fsp)))
                                        (out "~6d FSP rekey cutover: the node's new session is current"
                                             (- (ms) t0)))))
                                (error (e)
                                  (multiple-value-bind (fl plen ctr) (cl-fips:decode-fsp-header payload)
                                    (out "~6d FSP frame did not open: flags=~d payload_len=~d counter=~d (~a)"
                                         (- (ms) t0) fl plen ctr e))
                                  (values nil nil nil nil)))
                            (declare (ignore dp))
                            (cond
                              ((null mt) nil)           ; logged above: the frame did not open
                              ((and (= mt #x10) (/= sp 4600))
                               ;; a DataPacket the node initiated (its native flow to us)
                               (out "~6d FSP DataPacket from the node src_port=~d dst_port=~d data=~s"
                                    (- (ms) t0) sp dp (map 'string #'code-char data)))
                              ((and (= mt #x10) (= sp 4600))
                               (if (and last-probe (equalp data last-probe))
                                   (out "~6d FSP echo OK: the node returned our ~d bytes from port 4600"
                                        (- (ms) t0) (length data))
                                   (out "~6d FSP echo MISMATCH from port 4600 (~d bytes)"
                                        (- (ms) t0) (length data))))
                              (t
                               (out "~6d FSP inbound established frame msg_type=0x~2,'0x len=~d"
                                    (- (ms) t0) mt (length payload))))))
                         (t (out "~6d FSP phase ~d ignored" (- (ms) t0)
                                 (cl-fips:prefix-phase payload)))))
                   (error (e) (out "~6d FSP: ~a" (- (ms) t0) e))))
                (t
                 (pushnew (aref m 0) seen)
                 (bump :frames)
                 (when (eq slot :adopted)
                   (bump :adopted)
                   (setf (getf *stats* :frames-since-rotate) 0)
                   (out "~6d REKEY adopted: keys rotated our_index=~8,'0x their_index=~8,'0x k=~:[0~;1~]"
                        (- (ms) t0) (cl-fips:stream-link-our-index link)
                        (cl-fips:stream-link-their-index link) (cl-fips:stream-link-k-bit link)))
                 (when (getf *stats* :frames-since-rotate) (bump :frames-since-rotate))
                 ;; reports arrive every second: log one line per 10 s of them
                 (when (or (not (member (aref m 0) '(1 2)))
                           (>= (- (ms) last-frame-log) 10000))
                   (when (member (aref m 0) '(1 2)) (setf last-frame-log (ms)))
                   (out "~6d RECV msg_type=0x~2,'0x len=~d ts=~d flags=~d counter=~d slot=~(~a~)"
                        (- (ms) t0) (aref m 0) (length m) ts flags counter slot)))))
          (cl-fips:link-error (e)
            (out "~6d LINK-ERROR ~a" (- (ms) t0) e)
            (when (cl-fips:link-error-fatal-p e) (return))))))
    (let ((m (cl-fips::mmp-metrics (cl-fips:stream-link-mmp link))))
      (out "MMP: sent ~d ReceiverReports, ~d SenderReports; node's RRs accepted ~d of ~d, RTT samples ~d, srtt ~,1f ms"
           (getf *stats* :rr-sent 0) (getf *stats* :sr-sent 0)
           (cl-fips::mm-reports-accepted m) (cl-fips::mm-reports-seen m)
           (cl-fips::mm-rtt-samples m) (/ (cl-fips::mm-srtt-us m) 1000.0)))
    (out "REKEY-SUMMARY answered=~d complete=~d cutover=~d adopted=~d frames-after-last-rotation=~a"
         (getf *stats* :rekey-answered 0) (getf *stats* :rekey-complete 0)
         (getf *stats* :cutover 0) (getf *stats* :adopted 0)
         (getf *stats* :frames-since-rotate "n/a"))
    seen))

(defun run-link (dir role port secs)
  (let* ((lisp (read-key (format nil "~a/lisp.key" dir)))
         (node (read-key (format nil "~a/node.key" dir)))
         (static (secp256k1-fast.ecdh:keypair-from-secret (first lisp)))
         (epoch (natrium:random-bytes 8))
         (listener (and (eq role :accept)
                        (usocket:socket-listen "127.0.0.1" port :reuse-address t
                                                                :element-type '(unsigned-byte 8))))
         (sock (if listener
                   (progn (out "LISTENING 127.0.0.1:~d" port)
                          (and (usocket:wait-for-input listener :timeout 60 :ready-only t)
                               (usocket:socket-accept listener :element-type '(unsigned-byte 8))))
                   (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8)
                                                            :nodelay t :timeout 10)))
         (link nil))
    (when listener (usocket:socket-close listener))
    (unless sock (out "FAIL: the node never connected") (sb-ext:exit :code 1))
    (let ((port (cl-fips.transport:socket-byte-port sock)))
      (handler-case
          (setf link (if (eq role :accept)
                         (cl-fips:stream-link-accept port static epoch :timeout-ms 10000
                                                     :reports (reports-mode) :routing (routing-mode))
                         (cl-fips:stream-link-initiate port static (second node) epoch
                                                       :timeout-ms 10000 :reports (reports-mode) :routing (routing-mode))))
        (error (e) (out "FAIL: handshake: ~a" e) (sb-ext:exit :code 1))))
    (out "REPORTS mode=~(~a~)" (reports-mode))
    (out "HANDSHAKE OK role=~(~a~) our_index=~8,'0x their_index=~8,'0x remote_epoch=~a"
         role (cl-fips:stream-link-our-index link) (cl-fips:stream-link-their-index link)
         (hex (cl-fips:stream-link-remote-epoch link)))
    (let* ((static-ok (equalp (cl-fips:stream-link-remote-static link) (second node)))
           (seen (exchange link sock secs static (second node)))
           (ok (and static-ok (member #x10 seen) (member #x51 seen))))
      (cl-fips:stream-link-close link)
      (out "remote static is the node's key: ~:[NO~;yes~]" static-ok)
      (out "msg_types received: ~{0x~2,'0x~^ ~}" (sort seen #'<))
      (out "~:[FAIL~;PASS~] ~(~a~)" ok role)
      (sb-ext:exit :code (if ok 0 1)))))

(defun keygen-root (dir)
  "keygen, then a node B (DIR/b/node.key) whose node_addr is the smallest of the
   three, so B is the root of the tree and every node can route to it."
  (keygen dir)
  (ensure-directories-exist (format nil "~a/b/" dir))
  (keygen (format nil "~a/b" dir))
  (let* ((a (cl-fips:node-addr (second (read-key (format nil "~a/node.key" dir)))))
         (l (cl-fips:node-addr (second (read-key (format nil "~a/lisp.key" dir)))))
         (least (if (bytes< a l) a l)))
    (loop
      (let* ((kp (cl-fips:generate-keypair))
             (addr (cl-fips:node-addr (secp256k1-fast.ecdh:keypair-public-bytes kp))))
        (when (bytes< addr least)
          (write-key (format nil "~a/b/node.key" dir) kp)
          (with-open-file (o (format nil "~a/b/node.npub" dir) :direction :output :if-exists :supersede)
            (write-line (npub (secp256k1-fast.ecdh:keypair-public-bytes kp)) o))
          (return))))))

(defun bytes< (a b)
  (loop for x across a for y across b
        do (cond ((< x y) (return t)) ((> x y) (return nil)))
        finally (return nil)))

(defstruct transit-state
  l1 l2 own b-addr static node-b fi (primed nil) (fwd 0) (no-route 0) (ttl 0) (local 0) (t0 0))

(defun transit-filters (ts)
  (list (cons (transit-state-l1 ts) (cl-fips:stream-link-peer-filter (transit-state-l1 ts)))
        (cons (transit-state-l2 ts) (cl-fips:stream-link-peer-filter (transit-state-l2 ts)))))

(defun transit-forward (ts link body)
  "A SessionDatagram that is not for us: next hop from the peers' filters, TTL down
   by one, path_mtu capped at the outgoing MTU."
  (let* ((dest (cl-fips:sd-dest body))
         (target (cl-fips:route-next-hop (transit-filters ts) link dest)))
    (if (null target)
        (incf (transit-state-no-route ts))
        (let ((out-body (cl-fips:sd-forward-header body 1400)))
          (cond
            ((null out-body) (incf (transit-state-ttl ts)))
            (t
             (cl-fips:stream-link-send target
                                       (concatenate '(vector (unsigned-byte 8))
                                                    (vector #x00) out-body))
             (incf (transit-state-fwd ts))
             (when (<= (transit-state-fwd ts) 6)
               (out "~6d FORWARD datagram ttl=~d (to ~:[B~;A~])"
                    (- (ms) (transit-state-t0 ts)) (cl-fips:sd-ttl out-body)
                    (eq target (transit-state-l1 ts))))))))))

(defun transit-local (ts link body)
  "A SessionDatagram for us.  Our SessionAck (from B) completes the session we
   primed.  Anything else addressed to us -- an error signal a transit node sends
   back to a source it could not route for, such as A -- is logged and ignored."
  (incf (transit-state-local ts))
  (let ((fi (transit-state-fi ts)))
    (cond
      ((and fi (eq (cl-fips:fsp-initiator-phase fi) :setup-sent)
            (equalp (cl-fips:sd-src body) (transit-state-b-addr ts)))
       (cl-fips:stream-link-send link (cl-fips:fsp-handle-ack fi body))
       (out "~6d FSP session with B established through the middle"
            (- (ms) (transit-state-t0 ts))))
      (t
       (out "~6d local SessionDatagram from ~a ignored (not our peer's SessionAck)"
            (- (ms) (transit-state-t0 ts))
            (hex (cl-fips:sd-src body)))))))

(defun transit-receive (ts link)
  (handler-case
      (let ((m (cl-fips:stream-link-receive link :timeout-ms 2000)))
        ;; the tree is shared: a change learned on one link changes both announces
        (setf (cl-fips:stream-link-tree-dirty (transit-state-l1 ts)) t
              (cl-fips:stream-link-tree-dirty (transit-state-l2 ts)) t)
        (when (and m (= (aref m 0) #x00))
          (let ((body (subseq m 1)))
            (if (equalp (cl-fips:sd-dest body) (transit-state-own ts))
                (transit-local ts link body)
                (transit-forward ts link body)))))
    (cl-fips:link-error (e) (out "~6d link error: ~a" (- (ms) (transit-state-t0 ts)) e))
    (error (e) (out "~6d FAIL: ~a" (- (ms) (transit-state-t0 ts)) e))))

(defun transit-prime (ts)
  "Once our coordinates exist, one SessionSetup toward B goes out through A."
  (let* ((l1 (transit-state-l1 ts))
         (tree (cl-fips:stream-link-tree l1)))
    (when (and (not (transit-state-primed ts)) tree (cl-fips:tree-state-entries tree))
      (let ((fi (cl-fips:make-fsp-initiator
                 (transit-state-static ts) (second (transit-state-node-b ts))
                 (natrium:random-bytes 8) (transit-state-own ts) (transit-state-b-addr ts)
                 (mapcar #'cl-fips:coord-entry-node (cl-fips:tree-state-entries tree))
                 (list (transit-state-b-addr ts)))))
        (setf (transit-state-fi ts) fi
              (transit-state-primed ts) t)
        (cl-fips:stream-link-send l1 (cl-fips:fsp-setup-datagram fi (ms)))
        (out "~6d SessionSetup toward B sent through A" (- (ms) (transit-state-t0 ts)))))))

(defun run-transit (dir port-a port-l secs)
  "Lisp as the MIDDLE node: a link to relay A (dialled), and a link B dials into
   (accepted).  Frames are forwarded between the two.  Once, a SessionSetup toward
   B goes out through A, so A learns B's coordinates from it and can route to B."
  (let* ((lisp (read-key (format nil "~a/lisp.key" dir)))
         (static (secp256k1-fast.ecdh:keypair-from-secret (first lisp)))
         (node-a (read-key (format nil "~a/node.key" dir)))
         (node-b (read-key (format nil "~a/b/node.key" dir)))
         (own (cl-fips:node-addr (secp256k1-fast.ecdh:keypair-public-bytes static)))
         (epoch (natrium:random-bytes 8))
         (s1 (usocket:socket-connect "127.0.0.1" port-a :element-type '(unsigned-byte 8)
                                                        :nodelay t :timeout 10))
         ;; one tree for the node, shared by both links: it sees both peers' announces
         (tree (cl-fips:make-tree-state (secp256k1-fast.ecdh:keypair-secret static)))
         (l1 (cl-fips:stream-link-initiate (cl-fips.transport:socket-byte-port s1) static
                                           (second node-a) epoch :timeout-ms 10000 :routing tree))
         (listener (usocket:socket-listen "127.0.0.1" port-l :reuse-address t
                                                             :element-type '(unsigned-byte 8))))
    (out "HANDSHAKE OK role=dial (to A)")
    (out "LISTENING 127.0.0.1:~d" port-l)
    (unless (usocket:wait-for-input listener :timeout 120 :ready-only t)
      (out "FAIL: B never dialled in") (sb-ext:exit :code 1))
    (let* ((s2 (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
           (l2 (cl-fips:stream-link-accept (cl-fips.transport:socket-byte-port s2) static epoch
                                           :timeout-ms 10000 :routing tree))
           (ts (make-transit-state :l1 l1 :l2 l2 :own own :static static :node-b node-b
                                   :b-addr (cl-fips:node-addr (second node-b)) :t0 (ms))))
      (usocket:socket-close listener)
      (out "HANDSHAKE OK role=accept (from B)")
      (setf (cl-fips:stream-link-filter-source l1) (lambda (l) (cl-fips:route-filter-for own (transit-filters ts) l))
            (cl-fips:stream-link-filter-source l2) (lambda (l) (cl-fips:route-filter-for own (transit-filters ts) l)))
      (let ((next-hb 0) (deadline (+ (ms) (* 1000 secs))))
        (loop while (< (ms) deadline) do
          (when (>= (ms) next-hb)
            (cl-fips:stream-link-send l1 (coerce #(#x51) '(vector (unsigned-byte 8))))
            (cl-fips:stream-link-send l2 (coerce #(#x51) '(vector (unsigned-byte 8))))
            (setf next-hb (+ (ms) 5000)))
          (cl-fips:stream-link-poll l1)
          (cl-fips:stream-link-poll l2)
          (transit-prime ts)
          (let ((fi (transit-state-fi ts)))
            (when fi
              (let ((again (cl-fips:fsp-resend-setup fi (ms))))
                (when again (cl-fips:stream-link-send l1 again)))))
          (dolist (sock (usocket:wait-for-input (list s1 s2) :timeout 0.1 :ready-only t))
            (transit-receive ts (if (eq sock s1) l1 l2))))
        (out "TRANSIT forwarded=~d dropped-no-route=~d dropped-ttl=~d local=~d primed=~:[no~;yes~]"
             (transit-state-fwd ts) (transit-state-no-route ts) (transit-state-ttl ts)
             (transit-state-local ts) (transit-state-primed ts))
        (cl-fips:stream-link-close l1)
        (cl-fips:stream-link-close l2)
        (sb-ext:exit :code 0)))))

(let* ((args (rest sb-ext:*posix-argv*)) (mode (first args)))
  (cond ((string= mode "keygen") (keygen (second args)))
        ((string= mode "keygen-root") (keygen-root (second args)))
        ((string= mode "transit")
         (run-transit (second args) (parse-integer (third args))
                      (parse-integer (fourth args)) (parse-integer (or (fifth args) "60"))))
        (t (destructuring-bind (mode dir &optional port secs) args
             (run-link dir (if (string= mode "accept") :accept :dial)
                       (parse-integer port) (parse-integer (or secs "20")))))))
