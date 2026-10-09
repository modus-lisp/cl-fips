;;;; fips-stream.lisp -- byte streams over FIPS, a TCP gateway, and cl-transport's :fips.
;;;;
;;;; SBCL ADAPTER (threads, sockets, gray streams), like the rest of transport/.
;;;;
;;;; FIPS carries DATAGRAMS between nodes (DataPackets on ports).  Upstream's way to
;;;; carry TCP is its IPv6 TUN, which needs root and a TUN device; its native API is
;;;; datagrams only.  So a byte stream between two cl-fips nodes is this file's own
;;;; small protocol on one service port -- NOT upstream interop; both ends must be
;;;; cl-fips:
;;;;
;;;;   [type u8][stream-id u32][seq u32][ack u32][payload]        (all LE)
;;;;   SYN     payload "host:port" -- open a stream to that TCP endpoint (gateway)
;;;;   SYN-OK  the gateway connected            SYN-FAIL  it did not (payload: why)
;;;;   DATA    one segment, numbered by seq     FIN       end of stream (takes a seq)
;;;;   ACK     ack = the next seq expected      RST       abort
;;;;
;;;; Segments are at most +SEGMENT+ bytes, so one DataPacket fits a UDP link (1280 -
;;;; 110 bytes of FIPS framing).  At most +WINDOW+ unacknowledged segments; each is
;;;; resent after 1 s, doubling, and the stream fails after +MAX-TRIES+ sends.  Acks
;;;; are cumulative; out-of-order segments wait for the gap.
;;;;
;;;; Threads: one thread runs the daemon and every protocol timer, and is the only
;;;; one that touches the daemon.  A caller's thread only queues bytes and waits on a
;;;; condition variable, under the endpoint's one lock.
;;;;
;;;;   (start-fips-client config :gateway "npub1...")  ; registers :FIPS with cl-transport
;;;;   (cl-transport:dial "example.com" 443 :transport :fips)
;;;;   (start-fips-gateway config :allow '("npub1..."))  ; the far end, in its own process

(defpackage #:cl-fips.stream
  (:use #:common-lisp)
  (:local-nicknames (#:bt #:bordeaux-threads) (#:d #:cl-fips.daemon) (#:tcp #:cl-transport.tcp))
  (:export #:start-fips-client #:start-fips-gateway #:stop-fips-endpoint #:fips-dial
           #:*fips-client* #:+stream-port+ #:endpoint-daemon #:run-gateway-main))

(in-package #:cl-fips.stream)

(defconstant +stream-port+ 7100 "The service port streams use, on both ends.")
(defconstant +segment+ 1100)
(defconstant +window+ 32)
(defconstant +rto-ms+ 1000)
(defconstant +max-tries+ 8)
(defconstant +header+ 13)
(defconstant +syn+ 1) (defconstant +syn-ok+ 2) (defconstant +syn-fail+ 3)
(defconstant +data+ 4) (defconstant +ack+ 5) (defconstant +fin+ 6) (defconstant +rst+ 7)

(defun u8v (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0))
(defun ascii (s) (map '(vector (unsigned-byte 8)) #'char-code s))
(defun text (v) (map 'string #'code-char v))

(defun encode (type id seq ack &optional (payload (u8v 0)))
  (let ((out (u8v (+ +header+ (length payload)))))
    (setf (aref out 0) type)
    (replace out (cl-fips:encode-u32le id) :start1 1)
    (replace out (cl-fips:encode-u32le seq) :start1 5)
    (replace out (cl-fips:encode-u32le ack) :start1 9)
    (replace out payload :start1 +header+)
    out))

;;; --- connections ------------------------------------------------------------------

(defstruct conn
  ep peer id (state :connecting)     ; :connecting :open :closed :failed
  peer-key                           ; the client's: the gateway's npub, so a send opens the session
  (done-at nil)                      ; when it closed or failed
  (error nil) target
  ;; sending
  (next-seq 0) (unacked (make-hash-table)) (outq '()) (fin-queued nil) (fin-sent nil)
  (ctrl '())                         ; control frames to send (from any thread)
  (syn nil) (syn-at 0) (syn-tries 0)
  ;; receiving
  (expect 0) (ooo (make-hash-table)) (inbox '()) (eof nil) (ack-due nil)
  ;; the gateway's side: the TCP socket it bridges to
  socket (tcp-eof nil)
  ;; a stream to a FIPS node's own TCP, through the IPv6 shim: our TCP engine
  tcp
  (cv (bt:make-condition-variable)))

(defstruct (endpoint (:constructor %make-endpoint))
  daemon (lock (bt:make-lock "fips-stream"))
  (conns (make-hash-table :test 'equalp))   ; (peer . id) -> conn
  role gateway-key allow thread (stop nil))

(defvar *fips-client* nil "The endpoint cl-transport's :FIPS dials through.")

(defun now-ms (ep) (cl-fips.daemon::daemon-now (endpoint-daemon ep)))

(defun %key (peer id) (cons (coerce peer '(vector (unsigned-byte 8))) id))

(defun %wake (c) (bt:condition-notify (conn-cv c)))

(defun %fail (c why)
  (unless (member (conn-state c) '(:failed :closed))
    (setf (conn-state c) :failed (conn-error c) why))
  (%close-socket c)
  (%wake c))

(defun %close-socket (c)
  (when (conn-socket c) (ignore-errors (usocket:socket-close (conn-socket c))) (setf (conn-socket c) nil)))

;;; --- the daemon thread: sending -------------------------------------------------------

(defun %send (c frame)
  "Send FRAME to C's peer (daemon thread only).  NIL if the daemon refused it."
  (handler-case
      (progn (d:daemon-send (endpoint-daemon (conn-ep c)) (or (conn-peer-key c) (conn-peer c)) frame
                            :src-port +stream-port+ :dst-port +stream-port+)
             t)
    (error () nil)))

(defun %pump-tcp (c now)
  "Move bytes between the caller's queues and our TCP engine, then send what it has."
  (let ((tc (conn-tcp c)))
    (when (conn-outq c)
      (dolist (b (conn-outq c)) (tcp:tcp-write tc b))
      (setf (conn-outq c) '()))
    (when (and (conn-fin-queued c) (not (conn-fin-sent c)))
      (tcp:tcp-close tc) (setf (conn-fin-sent c) t))
    (multiple-value-bind (segs events) (tcp:tcp-output tc now)
      (dolist (seg segs) (%send-shim c seg))
      (%tcp-events c events))))

(defun %send-shim (c seg)
  (handler-case
      (d:daemon-send (endpoint-daemon (conn-ep c)) (or (conn-peer-key c) (conn-peer c))
                     (cl-fips:ipv6-shim-wrap seg)
                     :src-port cl-fips:+fsp-port-ipv6-shim+ :dst-port cl-fips:+fsp-port-ipv6-shim+)
    (error () nil)))

(defun %tcp-events (c events)
  (let ((tc (conn-tcp c)))
    (dolist (e events)
      (case e
        (:established (setf (conn-state c) :open))
        (:data (let ((bytes (tcp:tcp-read tc)))
                 (when (plusp (length bytes)) (setf (conn-inbox c) (append (conn-inbox c) (list bytes))))))
        (:eof (setf (conn-eof c) t))
        (:reset (%fail c (if (eq (conn-state c) :connecting) "connection refused or unanswered"
                             "connection reset")))
        (:closed (setf (conn-eof c) t (conn-state c) :closed))))
    (when events (%wake c))))

(defun %on-shim (ep peer shim)
  "A shim packet from PEER: a TCP segment for one of our connections, if it names one."
  (multiple-value-bind (seg next) (cl-fips:ipv6-shim-unwrap shim)
    (when (and seg (= next 6) (>= (length seg) 4))
      (let* ((sport (logior (ash (aref seg 0) 8) (aref seg 1)))
             (dport (logior (ash (aref seg 2) 8) (aref seg 3)))
             (c (gethash (%key peer (list :tcp dport sport)) (endpoint-conns ep))))
        (when c
          (%tcp-events c (tcp:tcp-input (conn-tcp c) seg (now-ms ep))))))))

(defun %pump-conn (c now)
  (when (conn-tcp c) (return-from %pump-conn (%pump-tcp c now)))
  (let ((ep (conn-ep c)))
    (declare (ignore ep))
    ;; control frames queued by the caller's thread
    (loop while (conn-ctrl c) do (%send c (pop (conn-ctrl c))))
    ;; the SYN, until it is answered
    (when (and (conn-syn c) (eq (conn-state c) :connecting)
               (>= (- now (conn-syn-at c)) (* +rto-ms+ (ash 1 (max 0 (1- (conn-syn-tries c)))))))
      (if (>= (conn-syn-tries c) +max-tries+)
          (%fail c "the gateway did not answer")
          (progn (%send c (conn-syn c)) (setf (conn-syn-at c) now) (incf (conn-syn-tries c)))))
    (when (eq (conn-state c) :open)
      ;; new segments, while the window allows
      (loop while (and (< (hash-table-count (conn-unacked c)) +window+)
                       (or (conn-outq c) (and (conn-fin-queued c) (not (conn-fin-sent c)))))
            do (if (conn-outq c)
                   (let* ((all (apply #'concatenate '(vector (unsigned-byte 8)) (conn-outq c)))
                          (n (min +segment+ (length all)))
                          (seg (subseq all 0 n)))
                     (setf (conn-outq c) (if (< n (length all)) (list (subseq all n)) '()))
                     (let ((seq (conn-next-seq c)))
                       (incf (conn-next-seq c))
                       (setf (gethash seq (conn-unacked c)) (list (cons +data+ seg) now 1))
                       (%send c (encode +data+ (conn-id c) seq (conn-expect c) seg))
                       (setf (conn-ack-due c) nil)))
                   (let ((seq (conn-next-seq c)))
                     (incf (conn-next-seq c))
                     (setf (conn-fin-sent c) t
                           (gethash seq (conn-unacked c)) (list (cons +fin+ (u8v 0)) now 1))
                     (%send c (encode +fin+ (conn-id c) seq (conn-expect c)))
                     (setf (conn-ack-due c) nil))))
      ;; retransmissions
      (maphash (lambda (seq entry)
                 (destructuring-bind ((type . payload) sent tries) entry
                   (when (>= (- now sent) (* +rto-ms+ (ash 1 (1- tries))))
                     (if (>= tries +max-tries+)
                         (%fail c "the peer stopped acknowledging")
                         (progn (setf (gethash seq (conn-unacked c)) (list (cons type payload) now (1+ tries)))
                                (%send c (encode type (conn-id c) seq (conn-expect c) payload)))))))
               (conn-unacked c)))
    ;; a bare ack when nothing carried one
    (when (conn-ack-due c)
      (%send c (encode +ack+ (conn-id c) 0 (conn-expect c)))
      (setf (conn-ack-due c) nil))))

;;; --- the daemon thread: receiving -----------------------------------------------------

(defun %deliver (c payload)
  "In-order bytes for the local side: the caller's inbox, or the gateway's socket."
  (if (conn-socket c)
      (handler-case (let ((s (usocket:socket-stream (conn-socket c))))
                      (write-sequence payload s) (finish-output s))
        (error () (%fail c "the TCP connection failed")))
      (setf (conn-inbox c) (append (conn-inbox c) (list payload)))))

(defun %peer-fin (c)
  (setf (conn-eof c) t)
  (when (conn-socket c)
    (ignore-errors (usocket:socket-shutdown (conn-socket c) :output))))

(defun %on-frame (ep peer frame)
  (when (< (length frame) +header+) (return-from %on-frame))
  (let* ((type (aref frame 0))
         (id (cl-fips:decode-u32le frame 1))
         (seq (cl-fips:decode-u32le frame 5))
         (ack (cl-fips:decode-u32le frame 9))
         (payload (subseq frame +header+))
         (c (gethash (%key peer id) (endpoint-conns ep))))
    (cond
      ((= type +syn+)
       (if (eq (endpoint-role ep) :gateway)
           (%gateway-syn ep peer id payload c)
           nil))
      ((null c) nil)
      ((= type +syn-ok+)
       (when (eq (conn-state c) :connecting) (setf (conn-state c) :open)) (%wake c))
      ((= type +syn-fail+) (%fail c (format nil "the gateway refused: ~a" (text payload))))
      ((= type +rst+) (%fail c "reset by the peer"))
      (t
       ;; every DATA / FIN / ACK carries a cumulative ack
       (let ((done '()))
         (maphash (lambda (s e) (declare (ignore e)) (when (< s ack) (push s done))) (conn-unacked c))
         (dolist (s done) (remhash s (conn-unacked c))))
       (when (member type (list +data+ +fin+))
         (setf (conn-ack-due c) t)
         (when (>= seq (conn-expect c))
           (setf (gethash seq (conn-ooo c)) (cons type payload)))
         (loop for next = (gethash (conn-expect c) (conn-ooo c))
               while next
               do (remhash (conn-expect c) (conn-ooo c))
                  (incf (conn-expect c))
                  (if (= (car next) +fin+) (%peer-fin c) (%deliver c (cdr next)))))
       (%maybe-done c)
       (%wake c)))))

(defun %maybe-done (c)
  "Both directions finished and everything acknowledged: the stream is closed."
  (when (and (conn-eof c) (conn-fin-sent c) (zerop (hash-table-count (conn-unacked c))))
    (setf (conn-state c) :closed)
    (%close-socket c)))

;;; --- the gateway ----------------------------------------------------------------------

(defun %gateway-syn (ep peer id payload c)
  (cond
    (c ;; a resent SYN: answer as before
     (case (conn-state c)
       (:open (push (encode +syn-ok+ id 0 0) (conn-ctrl c)))
       (:failed (push (encode +syn-fail+ id 0 0 (ascii (or (conn-error c) "failed"))) (conn-ctrl c)))))
    ((not (or (eq (endpoint-allow ep) :any)
              (member peer (endpoint-allow ep) :test #'equalp)))
     (let ((tmp (make-conn :ep ep :peer peer :id id)))
       (%send tmp (encode +syn-fail+ id 0 0 (ascii "not allowed")))))
    (t
     (let* ((target (text payload))
            (colon (position #\: target :from-end t))
            (c (make-conn :ep ep :peer peer :id id :target target)))
       (setf (gethash (%key peer id) (endpoint-conns ep)) c)
       (if (null colon)
           (%gateway-answer c nil "bad target")
           ;; connecting can take seconds: not on the daemon thread
           (let ((host (subseq target 0 colon))
                 (port (ignore-errors (parse-integer target :start (1+ colon)))))
             (bt:make-thread
              (lambda ()
                (let ((sock (handler-case (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                                                            :timeout 10)
                              (error (e) (princ-to-string e)))))
                  (bt:with-lock-held ((endpoint-lock ep))
                    (if (stringp sock)
                        (%gateway-answer c nil sock)
                        (%gateway-answer c sock nil)))))
              :name "fips-gateway-connect")))))))

(defun %gateway-answer (c sock why)
  (if sock
      (setf (conn-socket c) sock (conn-state c) :open
            (conn-ctrl c) (append (conn-ctrl c) (list (encode +syn-ok+ (conn-id c) 0 0))))
      (setf (conn-state c) :failed (conn-error c) why
            (conn-ctrl c) (append (conn-ctrl c)
                                  (list (encode +syn-fail+ (conn-id c) 0 0 (ascii (or why "failed"))))))))

(defun %gateway-read (ep)
  "Bytes the TCP side has for each open gateway stream, as much as the window can
   take soon; the TCP side closing becomes our FIN."
  (let ((socks '()))
    (maphash (lambda (k c) (declare (ignore k))
               (when (and (conn-socket c) (eq (conn-state c) :open) (not (conn-tcp-eof c))
                          (< (length (conn-outq c)) 64))
                 (push c socks)))
             (endpoint-conns ep))
    (when socks
      (let ((ready (ignore-errors (usocket:wait-for-input (mapcar #'conn-socket socks)
                                                          :timeout 0 :ready-only t))))
        (dolist (c socks)
          (when (member (conn-socket c) ready)
            (multiple-value-bind (bytes eof) (cl-fips.transport:tcp-read-available (conn-socket c))
              (when (plusp (length bytes)) (setf (conn-outq c) (append (conn-outq c) (list bytes))))
              (when eof (setf (conn-tcp-eof c) t (conn-fin-queued c) t)))))))))

;;; --- the endpoint thread --------------------------------------------------------------

(defun %start (ep)
  (setf (endpoint-thread ep)
        (bt:make-thread
         (lambda ()
           (loop until (endpoint-stop ep)
                 do (bt:with-lock-held ((endpoint-lock ep))
                      (handler-case
                          (progn
                            (d:daemon-step (endpoint-daemon ep) :max-wait-ms 5)
                            (when (eq (endpoint-role ep) :gateway) (%gateway-read ep))
                            (let ((now (now-ms ep)) (gone '()))
                              (maphash (lambda (k c)
                                         (%pump-conn c now)
                                         (when (member (conn-state c) '(:closed :failed))
                                           (push k gone)))
                                       (endpoint-conns ep))
                              ;; a finished stream lingers 30 s, to answer stray resends
                              (dolist (k gone)
                                (let ((c (gethash k (endpoint-conns ep))))
                                  (cond ((null (conn-done-at c)) (setf (conn-done-at c) now))
                                        ((> (- now (conn-done-at c)) 30000)
                                         (remhash k (endpoint-conns ep))))))))
                        (error (e) (format *error-output* "~&fips-stream: ~a~%" e))))
                    (sleep 0.001)))
         :name "fips-stream"))
  ep)

(defun %make (config role &key gateway allow (log nil))
  (let ((ep (%make-endpoint :role role)))
    (setf (endpoint-daemon ep)
          (d:make-daemon config :log log
                                :on-event (lambda (dmn ev)
                                            (declare (ignore dmn))
                                            (when (eq (first ev) :data)
                                              (cond ((= (fourth ev) +stream-port+)
                                                     (%on-frame ep (second ev) (fifth ev)))
                                                    ((= (fourth ev) cl-fips:+fsp-port-ipv6-shim+)
                                                     (%on-shim ep (second ev) (fifth ev)))))))
          (endpoint-gateway-key ep) (and gateway (cl-fips:npub-decode gateway))
          (endpoint-allow ep) (if (eq allow :any) :any
                                  (mapcar (lambda (n) (cl-fips:node-addr (cl-fips:npub-decode n))) allow)))
    (d:daemon-start (endpoint-daemon ep))
    (%start ep)))

(defun start-fips-client (config &key gateway log)
  "Run a cl-fips node for CONFIG in a thread and make it cl-transport's :FIPS backend:
   (cl-transport:dial host port :transport :fips) then reaches HOST:PORT through
   the gateway node GATEWAY (an npub)."
  (setf *fips-client* (%make config :client :gateway gateway :log log))
  (cl-transport:register-transport :fips #'fips-dial)
  *fips-client*)

(defun start-fips-gateway (config &key allow log)
  "Run a cl-fips node for CONFIG that opens TCP connections for the nodes in ALLOW
   (npubs, or :ANY -- an open relay to whatever this host can reach)."
  (%make config :gateway :allow allow :log log))

(defun stop-fips-endpoint (ep)
  (setf (endpoint-stop ep) t)
  (ignore-errors (bt:join-thread (endpoint-thread ep)))
  (bt:with-lock-held ((endpoint-lock ep))
    (maphash (lambda (k c) (declare (ignore k)) (%close-socket c)) (endpoint-conns ep))
    (d:daemon-stop (endpoint-daemon ep))))

;;; --- the caller's side: a binary stream -------------------------------------------------

(defclass fips-stream (sb-gray:fundamental-binary-input-stream sb-gray:fundamental-binary-output-stream)
  ((conn :initarg :conn :reader stream-conn)
   (timeout-ms :initarg :timeout-ms :initform 60000 :reader stream-timeout-ms)
   (buf :initform nil) (pos :initform 0)
   (open :initform t)))

(defmethod stream-element-type ((s fips-stream)) '(unsigned-byte 8))
(defmethod open-stream-p ((s fips-stream)) (slot-value s 'open))

(defun %await (s pred)
  "Wait, under the endpoint lock, until PRED is true of the connection or it fails."
  (let* ((c (stream-conn s)) (ep (conn-ep c))
         (deadline (+ (get-internal-real-time)
                      (* (stream-timeout-ms s) (/ internal-time-units-per-second 1000)))))
    (loop
      (cond ((funcall pred c) (return t))
            ((eq (conn-state c) :failed) (error "fips stream: ~a" (conn-error c)))
            ((> (get-internal-real-time) deadline) (error "fips stream: timed out")))
      (bt:condition-wait (conn-cv c) (endpoint-lock ep) :timeout 0.1))))

(defun %next-chunk (s)
  "Fill BUF from the inbox; NIL at end of stream."
  (with-slots (buf pos) s
    (let* ((c (stream-conn s)) (ep (conn-ep c)))
      (bt:with-lock-held ((endpoint-lock ep))
        (%await s (lambda (c) (or (conn-inbox c) (conn-eof c))))
        (if (conn-inbox c)
            (setf buf (apply #'concatenate '(vector (unsigned-byte 8)) (conn-inbox c))
                  (conn-inbox c) '() pos 0)
            nil)))))

(defmethod sb-gray:stream-read-byte ((s fips-stream))
  (with-slots (buf pos) s
    (when (or (null buf) (>= pos (length buf)))
      (unless (%next-chunk s) (return-from sb-gray:stream-read-byte :eof)))
    (prog1 (aref buf pos) (incf pos))))

(defmethod sb-gray:stream-read-sequence ((s fips-stream) seq &optional (start 0) end)
  (let ((end (or end (length seq))) (i start))
    (loop while (< i end)
          do (let ((b (sb-gray:stream-read-byte s)))
               (when (eq b :eof) (return))
               (setf (elt seq i) b) (incf i)))
    i))

(defmethod sb-gray:stream-listen ((s fips-stream))
  (with-slots (buf pos) s
    (or (and buf (< pos (length buf)))
        (let ((c (stream-conn s)))
          (bt:with-lock-held ((endpoint-lock (conn-ep c)))
            (and (conn-inbox c) t))))))

(defmethod sb-gray:stream-write-sequence ((s fips-stream) seq &optional (start 0) end)
  (let* ((c (stream-conn s)) (ep (conn-ep c))
         (bytes (coerce (subseq seq start (or end (length seq))) '(vector (unsigned-byte 8)))))
    (bt:with-lock-held ((endpoint-lock ep))
      ;; back-pressure: wait while a lot is already queued
      (%await s (lambda (c) (< (reduce #'+ (conn-outq c) :key #'length) (* 4 +window+ +segment+))))
      (setf (conn-outq c) (append (conn-outq c) (list bytes))))
    seq))

(defmethod sb-gray:stream-write-byte ((s fips-stream) b)
  (sb-gray:stream-write-sequence s (make-array 1 :element-type '(unsigned-byte 8) :initial-element b))
  b)

(defmethod sb-gray:stream-finish-output ((s fips-stream))
  (bt:with-lock-held ((endpoint-lock (conn-ep (stream-conn s))))
    (%await s (lambda (c) (and (null (conn-outq c)) (zerop (hash-table-count (conn-unacked c)))))))
  nil)

(defmethod sb-gray:stream-force-output ((s fips-stream)) nil)

(defmethod close ((s fips-stream) &key abort)
  (declare (ignore abort))
  (when (slot-value s 'open)
    (setf (slot-value s 'open) nil)
    (let ((c (stream-conn s)))
      (bt:with-lock-held ((endpoint-lock (conn-ep c)))
        (unless (member (conn-state c) '(:failed :closed)) (setf (conn-fin-queued c) t)))))
  t)

(defun %fips-host-key (host)
  "The key a <npub>.fips host name names, or NIL."
  (let ((n (length host)))
    (when (and (> n 5) (string-equal ".fips" host :start2 (- n 5)))
      (ignore-errors (cl-fips:npub-decode (subseq host 0 (- n 5)))))))

(defun %dial-fips-tcp (ep key port timeout)
  "A TCP connection to PORT on the FIPS node KEY, through the IPv6 shim: our TCP
   engine at one end, the node's own TCP stack at the other."
  (let* ((daemon (endpoint-daemon ep))
         (own (cl-fips:fips-node-own (d:daemon-node daemon)))
         (peer (cl-fips:node-addr key))
         (lport (+ 49152 (mod (cl-fips:decode-u32le (natrium:random-bytes 4) 0) 16384)))
         (c (make-conn :ep ep :peer peer :id (list :tcp lport port)
                       :peer-key (cl-fips:npub-encode key)))
         (s (make-instance 'fips-stream :conn c :timeout-ms (* 1000 (or timeout 60)))))
    (bt:with-lock-held ((endpoint-lock ep))
      (multiple-value-bind (tc syns)
          (tcp:tcp-open (cl-fips:fips-address own) (cl-fips:fips-address peer) lport port (now-ms ep)
                        :iss (cl-fips:decode-u32le (natrium:random-bytes 4) 0)
                        ;; a full segment fits one DataPacket on a UDP link: 1280 - 110
                        ;; bytes of FIPS framing - 7 of shim - 20 of TCP header
                        :mss 1100)
        (setf (conn-tcp c) tc
              (gethash (%key peer (conn-id c)) (endpoint-conns ep)) c)
        (dolist (seg syns) (%send-shim c seg)))
      (%await s (lambda (c) (eq (conn-state c) :open))))
    (values s (lambda () (close s)))))

(defun fips-dial (host port timeout)
  "cl-transport's :FIPS backend: a stream to HOST:PORT through the client's gateway.
   Returns (values stream closer)."
  (let ((key (%fips-host-key host)))
    (when key
      (return-from fips-dial
        (%dial-fips-tcp (or *fips-client* (error "fips: start-fips-client first")) key port timeout))))
  (let* ((ep (or *fips-client* (error "fips: start-fips-client first")))
         (gw (or (endpoint-gateway-key ep) (error "fips: no gateway configured")))
         (peer (cl-fips:node-addr gw))
         (id (cl-fips:decode-u32le (natrium:random-bytes 4) 0))
         (c (make-conn :ep ep :peer peer :id id))
         (s (make-instance 'fips-stream :conn c :timeout-ms (* 1000 (or timeout 60)))))
    (bt:with-lock-held ((endpoint-lock ep))
      (setf (conn-peer-key c) (cl-fips:npub-encode gw))
      (setf (gethash (%key peer id) (endpoint-conns ep)) c
            (conn-syn c) (encode +syn+ id 0 0 (ascii (format nil "~a:~d" host port))))
      (%await s (lambda (c) (eq (conn-state c) :open))))
    (values s (lambda () (close s)))))

;;; --- a gateway as a process ---------------------------------------------------------------

(defun run-gateway-main (config-path allow)
  "Run a gateway for CONFIG-PATH until interrupted.  ALLOW: npubs, or :ANY."
  (let ((ep (start-fips-gateway (d:load-config config-path) :allow allow :log *standard-output*)))
    (format t "GATEWAY npub=~a udp=~a~%" (d:daemon-npub (endpoint-daemon ep))
            (d:daemon-udp-port (endpoint-daemon ep)))
    (finish-output)
    (handler-case (loop (sleep 1))
      (sb-sys:interactive-interrupt () (stop-fips-endpoint ep)))))
