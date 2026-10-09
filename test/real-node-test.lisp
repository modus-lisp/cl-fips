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

(defun log-event (ev t0 state)
  "Log one node event in the lines the runner scripts read.  STATE is a plist
   cell (:last-probe ...)."
  (let ((at (- (ms) t0)))
    (case (first ev)
      (:frame
       (destructuring-bind (type link slot) (rest ev)
         (declare (ignore link))
         (bump :frames)
         (when (eq slot :adopted)
           (bump :adopted)
           (setf (getf *stats* :frames-since-rotate) 0)
           (out "~6d REKEY adopted: keys rotated" at))
         (when (getf *stats* :frames-since-rotate) (bump :frames-since-rotate))
         (unless (member type '(1 2 0))
           (out "~6d RECV msg_type=0x~2,'0x slot=~(~a~)" at type slot))))
      (:link-event (bump (second ev)) (out "~6d REKEY ~(~a~) (rekey packet from the node)" at (second ev)))
      (:link-action
       (bump (second ev))
       (when (eq (second ev) :cutover) (setf (getf *stats* :frames-since-rotate) 0))
       (out "~6d REKEY ~(~a~)" at (second ev)))
      (:link-drop (out "~6d LINK-ERROR ~(~a~) (frame dropped, link kept)" at (second ev)))
      (:link-closed (out "~6d LINK-ERROR ~(~a~) (link closed)" at (second ev)))
      (:established (out "~6d FSP SessionAck received; SessionMsg3 sent; session established" at))
      (:accepted (out "~6d FSP session opened by ~a accepted" at (hex (second ev))))
      (:accept-answered (out "~6d FSP SessionSetup from ~a answered" at (hex (second ev))))
      (:setup-resent (out "~6d FSP SessionSetup resent (no SessionAck yet)" at))
      (:rekey-answered (out "~6d FSP rekey: SessionSetup answered with SessionAck" at))
      (:rekey-msg3 (out "~6d FSP rekey: SessionMsg3 taken; the new session waits for its first frame" at))
      (:rekey-ack (out "~6d FSP rekey: SessionAck handled; SessionMsg3 sent" at))
      (:cutover (out "~6d FSP rekey cutover: the node's new session is current" at))
      (:data
       (destructuring-bind (peer sp dp data ts) (rest ev)
         (declare (ignore peer ts))
         (cond
           ((/= sp 4600)
            (out "~6d FSP DataPacket from the node src_port=~d dst_port=~d data=~s"
                 at sp dp (map 'string #'code-char data)))
           ((and (getf (car state) :last-probe) (equalp data (getf (car state) :last-probe)))
            (out "~6d FSP echo OK: the node returned our ~d bytes from port 4600" at (length data)))
           (t (out "~6d FSP echo MISMATCH from port 4600 (~d bytes)" at (length data))))))
      (:session-frame nil)
      (:session-error (out "~6d FSP: ~a" at (third ev)))
      (:unsolicited (out "~6d FSP: datagram from ~a with no session (phase ~a)" at (hex (second ev)) (third ev)))
      (:forwarded nil)
      (:dropped (out "~6d dropped ~(~a~)" at (second ev)))
      (t (out "~6d ~s" at ev)))))

(defun exchange (node link sock secs node-pub)
  "Run NODE on LINK for SECS: the node's tick (heartbeats, link rekey, MMP,
   announces), its session with the FSP peer (open, probe every 5 s, our rekey at
   CL_FIPS_FSP_REKEY_AT), and everything it receives.  Returns the msg_types seen."
  (let* ((t0 (ms)) (deadline (+ t0 (* 1000 secs))) (seen '())
         (state (list (list :last-probe nil)))
         (next-data 0) (data-count 0)
         (rekey-at (rekey-at-seconds)) (rekey-started nil) (opened nil)
         ;; the FSP peer: the node we are linked to, or -- with CL_FIPS_FSP_PEER_DIR
         ;; set -- a node behind it that the session reaches through that link
         (fsp-pub (or (fsp-target-pub) node-pub))
         (fsp-addr (cl-fips:node-addr fsp-pub))
         (multihop (and (fsp-target-pub) t)))
    (flet ((session () (cl-fips:node-session node fsp-addr))
           (established-p (fi) (and fi (eq (cl-fips:fsp-initiator-phase fi) :established))))
      (loop while (< (ms) deadline) do
        (let ((now (ms)))
          (dolist (ev (cl-fips:node-tick node now)) (log-event ev t0 state))
          ;; the session: open once our and the peer's coordinates are known
          (when (and (fsp-enabled-p) (not opened)
                     (cl-fips:tree-state-entries (cl-fips:fips-node-tree node))
                     (if multihop
                         (cl-fips:node-route node fsp-addr)   ; the relay's filter reaches B
                         (cl-fips:node-peer-coords node fsp-addr)))
            (setf opened t)
            (cl-fips:node-open-session node fsp-pub :now now
                                                    :peer-coords (and multihop (list fsp-addr)))
            (out "~6d FSP SessionSetup sent to the node (XK msg1)" (- now t0)))
          ;; our FSP rekey, once, after REKEY-AT seconds
          (when (and rekey-at (not rekey-started) (established-p (session))
                     (>= (- now t0) (* 1000 rekey-at)))
            (setf rekey-started t)
            (cl-fips:node-start-rekey node fsp-addr :now now)
            (out "~6d FSP rekey: SessionSetup sent (ours)" (- now t0)))
          ;; a probe every 5 s: to the node's native-echo (4600) or the IPv6 shim (256)
          (when (and (established-p (session)) (>= now next-data))
            (incf data-count)
            (setf next-data (+ now 5000))
            (let ((payload (probe-payload data-count))
                  (port (if (echo-enabled-p) 4600 256)))
              (handler-case
                  (progn
                    (setf (getf (car state) :last-probe) payload)
                    (when (cl-fips:node-send-data node fsp-addr payload :dst-port port :now now)
                      (out "~6d FSP rekey cutover (ours): the new session is current, K set" (- now t0)))
                    (out "~6d FSP DataPacket ~d sent (dst_port ~d)" (- now t0) data-count port))
                (cl-fips:node-error (e)
                  (out "~6d FSP probe ~d NOT SENT: ~a" (- now t0) data-count e)))))
          ;; input
          (when (or (listen (usocket:socket-stream sock))
                    (usocket:wait-for-input sock :timeout 0.2 :ready-only t))
            (dolist (ev (cl-fips:node-receive node link :timeout-ms 10000 :now (ms)))
              (when (eq (first ev) :frame) (pushnew (second ev) seen))
              (log-event ev t0 state)
              (when (eq (first ev) :link-closed) (setf deadline 0)))))))
    (let ((m (cl-fips::mmp-metrics (cl-fips:stream-link-mmp link))))
      (out "MMP: node's RRs accepted ~d of ~d, RTT samples ~d, srtt ~,1f ms"
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
         (lnode (cl-fips:make-fips-node static))
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
                                                     :reports (reports-mode)
                                                     :routing (and (routing-mode) (cl-fips:fips-node-tree lnode)))
                         (cl-fips:stream-link-initiate port static (second node) epoch
                                                       :timeout-ms 10000 :reports (reports-mode)
                                                       :routing (and (routing-mode) (cl-fips:fips-node-tree lnode)))))
        (error (e) (out "FAIL: handshake: ~a" e) (sb-ext:exit :code 1))))
    (out "REPORTS mode=~(~a~)" (reports-mode))
    (out "HANDSHAKE OK role=~(~a~) our_index=~8,'0x their_index=~8,'0x remote_epoch=~a"
         role (cl-fips:stream-link-our-index link) (cl-fips:stream-link-their-index link)
         (hex (cl-fips:stream-link-remote-epoch link)))
    (cl-fips:node-add-link lnode link)
    (let* ((static-ok (equalp (cl-fips:stream-link-remote-static link) (second node)))
           (seen (exchange lnode link sock secs (second node)))
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

(defun run-transit (dir port-a port-l secs)
  "Lisp as the MIDDLE node: one node with two links, one to relay A (dialled) and
   one B dials into (accepted).  The node forwards SessionDatagrams between them.
   Once, a session toward B is opened through A, so A learns B's coordinates from
   its SessionSetup and can route to B itself."
  (let* ((lisp (read-key (format nil "~a/lisp.key" dir)))
         (static (secp256k1-fast.ecdh:keypair-from-secret (first lisp)))
         (node-a (read-key (format nil "~a/node.key" dir)))
         (node-b (read-key (format nil "~a/b/node.key" dir)))
         (b-addr (cl-fips:node-addr (second node-b)))
         (lnode (cl-fips:make-fips-node static))
         (tree (cl-fips:fips-node-tree lnode))
         (s1 (usocket:socket-connect "127.0.0.1" port-a :element-type '(unsigned-byte 8)
                                                        :nodelay t :timeout 10))
         (l1 (cl-fips:stream-link-initiate (cl-fips.transport:socket-byte-port s1) static
                                           (second node-a) (natrium:random-bytes 8)
                                           :timeout-ms 10000 :routing tree))
         (listener (usocket:socket-listen "127.0.0.1" port-l :reuse-address t
                                                             :element-type '(unsigned-byte 8)))
         (t0 (ms)) (primed nil) (local 0))
    (cl-fips:node-add-link lnode l1)
    (out "HANDSHAKE OK role=dial (to A)")
    (out "LISTENING 127.0.0.1:~d" port-l)
    (unless (usocket:wait-for-input listener :timeout 120 :ready-only t)
      (out "FAIL: B never dialled in") (sb-ext:exit :code 1))
    (let* ((s2 (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
           (l2 (cl-fips:stream-link-accept (cl-fips.transport:socket-byte-port s2) static
                                           (natrium:random-bytes 8) :timeout-ms 10000 :routing tree))
           (deadline (+ (ms) (* 1000 secs))))
      (usocket:socket-close listener)
      (cl-fips:node-add-link lnode l2)
      (out "HANDSHAKE OK role=accept (from B)")
      (loop while (< (ms) deadline) do
        (let ((now (ms)))
          (dolist (ev (cl-fips:node-tick lnode now))
            (when (eq (first ev) :setup-resent) nil))
          ;; one session toward B, through A, once our coordinates exist
          (when (and (not primed) (>= (- now t0) 6000)
                     (cl-fips:tree-state-entries tree))
            (setf primed t)
            (cl-fips:node-open-session lnode (second node-b) :via l1 :now now
                                                             :peer-coords (list b-addr))
            (out "~6d SessionSetup toward B sent through A" (- now t0)))
          (dolist (sock (usocket:wait-for-input (list s1 s2) :timeout 0.1 :ready-only t))
            (dolist (ev (cl-fips:node-receive lnode (if (eq sock s1) l1 l2) :timeout-ms 2000 :now (ms)))
              (case (first ev)
                (:forwarded
                 (when (<= (cl-fips:fips-node-forwarded lnode) 6)
                   (out "~6d FORWARD datagram ttl=~d (to ~:[B~;A~])"
                        (- (ms) t0) (third ev) (eq (fourth ev) l1))))
                (:established
                 (incf local)
                 (out "~6d FSP session with B established through the middle" (- (ms) t0)))
                (:unsolicited
                 (incf local)
                 (out "~6d local SessionDatagram from ~a ignored (no session with it)"
                      (- (ms) t0) (hex (second ev))))
                (:link-closed (out "~6d link closed: ~(~a~)" (- (ms) t0) (second ev)))
                (:session-error (out "~6d FSP: ~a" (- (ms) t0) (third ev)))))))))
    (out "TRANSIT forwarded=~d dropped-no-route=~d dropped-ttl=~d too-big=~d malformed=~d local=~d primed=~:[no~;yes~]"
         (cl-fips:fips-node-forwarded lnode) (cl-fips:fips-node-no-route lnode)
         (cl-fips:fips-node-ttl-expired lnode) (cl-fips:fips-node-too-big lnode)
         (cl-fips:fips-node-malformed lnode) local primed)
    (dolist (l (cl-fips:fips-node-links lnode)) (cl-fips:node-remove-link lnode l))
    (sb-ext:exit :code 0)))

(let* ((args (rest sb-ext:*posix-argv*)) (mode (first args)))
  (cond ((string= mode "keygen") (keygen (second args)))
        ((string= mode "keygen-root") (keygen-root (second args)))
        ((string= mode "transit")
         (run-transit (second args) (parse-integer (third args))
                      (parse-integer (fourth args)) (parse-integer (or (fifth args) "60"))))
        (t (destructuring-bind (mode dir &optional port secs) args
             (run-link dir (if (string= mode "accept") :accept :dial)
                       (parse-integer port) (parse-integer (or secs "20")))))))
