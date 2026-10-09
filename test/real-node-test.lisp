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
;;;; body) every 5 s, and log every established frame the node sends by its
;;;; inner msg_type until SECS pass.  Handshake packets arriving on the
;;;; established link (the node's periodic rekey msg1) are logged and dropped.
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

(defun exchange (link sock secs)
  "Heartbeat every 5 s; log each frame by msg_type.  Returns the msg_types seen."
  (let* ((t0 (ms)) (deadline (+ t0 (* 1000 secs))) (next-hb 0) (seen '()))
    (loop while (< (ms) deadline) do
      (when (>= (ms) next-hb)
        (cl-fips:stream-link-send link (coerce #(#x51) '(vector (unsigned-byte 8))))
        (out "~6d SENT msg_type=0x51 (Heartbeat)" (- (ms) t0))
        (setf next-hb (+ (ms) 5000)))
      (when (or (listen (usocket:socket-stream sock))
                (usocket:wait-for-input sock :timeout 1 :ready-only t))
        (handler-case
            (multiple-value-bind (m ts flags counter) (cl-fips:stream-link-receive link :timeout-ms 10000)
              (pushnew (aref m 0) seen)
              (out "~6d RECV msg_type=0x~2,'0x len=~d ts=~d flags=~d counter=~d"
                   (- (ms) t0) (aref m 0) (length m) ts flags counter))
          (cl-fips:link-error (e)
            (out "~6d LINK-ERROR ~a" (- (ms) t0) e)
            (when (cl-fips:link-error-fatal-p e) (return))))))
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
                         (cl-fips:stream-link-accept port static epoch :timeout-ms 10000)
                         (cl-fips:stream-link-initiate port static (second node) epoch
                                                       :timeout-ms 10000)))
        (error (e) (out "FAIL: handshake: ~a" e) (sb-ext:exit :code 1))))
    (out "HANDSHAKE OK role=~(~a~) our_index=~8,'0x their_index=~8,'0x remote_epoch=~a"
         role (cl-fips:stream-link-our-index link) (cl-fips:stream-link-their-index link)
         (hex (cl-fips:stream-link-remote-epoch link)))
    (let* ((static-ok (equalp (cl-fips:stream-link-remote-static link) (second node)))
           (seen (exchange link sock secs))
           (ok (and static-ok (member #x10 seen) (member #x51 seen))))
      (cl-fips:stream-link-close link)
      (out "remote static is the node's key: ~:[NO~;yes~]" static-ok)
      (out "msg_types received: ~{0x~2,'0x~^ ~}" (sort seen #'<))
      (out "~:[FAIL~;PASS~] ~(~a~)" ok role)
      (sb-ext:exit :code (if ok 0 1)))))

(let ((args (rest sb-ext:*posix-argv*)))
  (destructuring-bind (mode dir &optional port secs) args
    (cond ((string= mode "keygen") (keygen dir))
          (t (run-link dir (if (string= mode "accept") :accept :dial)
                       (parse-integer port) (parse-integer (or secs "20")))))))
