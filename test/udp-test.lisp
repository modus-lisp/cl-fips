;;;; udp-test.lisp -- links over REAL UDP sockets on loopback.
;;;;
;;;;   U1  handshake both ways through one endpoint each, then frames both ways
;;;;   U2  the first msg1 is lost: the initiator resends it about 1 s later
;;;;   U3  the first msg2 is lost: the resent msg1 reaches the responder's
;;;;       established link, which answers it again with the same msg2
;;;;   U4  a malformed datagram and an over-MTU frame drop only themselves; the
;;;;       link stays up and the next frame arrives
;;;;   U5  a stranger's non-msg1 datagram is dropped; a stranger's msg1 is accepted
;;;;   U6  two FIPS-NODEs over UDP: an FSP session and a DataPacket each way
;;;;
;;;; The responder runs in a thread (SB-THREAD, test-only), since an initiator
;;;; blocks until its msg2 arrives.  Every socket is 127.0.0.1, ephemeral.

(in-package #:cl-fips.test)

(defun udp-accept-in-thread (ep static &key (routing nil) (mtu cl-fips.transport:+udp-mtu+)
                                          wrap)
  "Start a thread that accepts one link on EP.  Returns a function that joins it and
   returns the link (or the condition it died with)."
  (let ((th (sb-thread:make-thread
             (lambda ()
               (handler-case
                   (let ((port (loop for p = (cl-fips.transport:udp-accept ep :timeout-ms 200)
                                     repeat 100 when p return p)))
                     (when wrap (setf port (funcall wrap port)))
                     (stream-link-accept port static (random-epoch) :mtu mtu :timeout-ms 5000
                                                                  :routing routing))
                 (error (e) e))))))
    (lambda () (sb-thread:join-thread th))))

(defun dropping-port (port pred)
  "PORT, except that a write for which PRED (called with the octets) is true is lost."
  (make-datagram-port (cl-fips::byte-port-read-packet port)
                      (lambda (o) (if (funcall pred o) :ok (funcall (cl-fips::byte-port-write-all port) o)))
                      (cl-fips::byte-port-close-fn port)))

(defun drop-first (phase)
  (let ((done nil))
    (lambda (o) (and (not done) (= (prefix-phase o) phase) (setf done t)))))

(defmacro with-udp-pair ((a b) &body body)
  `(let ((,a (cl-fips.transport:udp-open)) (,b (cl-fips.transport:udp-open)))
     (unwind-protect (progn ,@body)
       (cl-fips.transport:udp-close ,a) (cl-fips.transport:udp-close ,b))))

(defun udp-dial (ep-a ep-b ka kb &key wrap-a wrap-b (routing-a nil) (routing-b nil))
  "A dials B.  Returns (values link-a link-b ms)."
  (let* ((join (udp-accept-in-thread ep-b kb :wrap wrap-b :routing routing-b))
         (port (cl-fips.transport:udp-peer-port ep-a "127.0.0.1"
                                                (cl-fips.transport:udp-endpoint-local-port ep-b)))
         (port (if wrap-a (funcall wrap-a port) port))
         (t0 (now-ms))
         (la (handler-case (stream-link-initiate port ka (keypair-public-bytes kb) (random-epoch)
                                                 :mtu cl-fips.transport:+udp-mtu+ :timeout-ms 8000
                                                 :routing routing-a)
               (error (e) e)))
         (ms (- (now-ms) t0)))
    (values la (funcall join) ms)))

(defun udp-round-trip (la lb label)
  (stream-link-send la (octets #x51 (ascii "ping")))
  (let ((m (handler-case (stream-link-receive lb :timeout-ms 3000) (error () nil))))
    (check (format nil "~a B opens A's frame off UDP" label) (equalp m (octets #x51 (ascii "ping")))))
  (stream-link-send lb (octets #x51 (ascii "pong")))
  (let ((m (handler-case (stream-link-receive la :timeout-ms 3000) (error () nil))))
    (check (format nil "~a A opens B's frame off UDP" label) (equalp m (octets #x51 (ascii "pong"))))))

(defun test-udp-handshake ()
  (with-udp-pair (ea eb)
    (let ((ka (generate-keypair)) (kb (generate-keypair)))
      (multiple-value-bind (la lb ms) (udp-dial ea eb ka kb)
        (check "U1 A's handshake over UDP completed" (cl-fips::stream-link-p la))
        (check "U1 B accepted over UDP" (cl-fips::stream-link-p lb))
        (when (and (cl-fips::stream-link-p la) (cl-fips::stream-link-p lb))
          (check "U1 no resend was needed on a quiet loopback" (< ms 900))
          (check "U1 handshake hashes agree"
                 (equalp (stream-link-handshake-hash la) (stream-link-handshake-hash lb)))
          (udp-round-trip la lb "U1")
          ;; and the frame ceiling is the UDP MTU, not TCP's
          (check "U1 a frame over 1280 bytes is refused locally"
                 (handler-case (progn (stream-link-send la (octets #x51 (filler 1300 1))) nil)
                   (link-error (e) (eq (link-error-reason e) :mtu-exceeded)))))))))

(defun test-udp-lost-msg1 ()
  (with-udp-pair (ea eb)
    (let ((ka (generate-keypair)) (kb (generate-keypair)))
      (multiple-value-bind (la lb ms)
          (udp-dial ea eb ka kb :wrap-a (lambda (p) (dropping-port p (drop-first +phase-msg1+))))
        (check "U2 the handshake completed although the first msg1 was lost"
               (and (cl-fips::stream-link-p la) (cl-fips::stream-link-p lb)))
        (check (format nil "U2 ... by the resend about 1 s later (~d ms)" ms) (<= 900 ms 2500))
        (when (and (cl-fips::stream-link-p la) (cl-fips::stream-link-p lb)) (udp-round-trip la lb "U2"))))))

(defun test-udp-lost-msg2 ()
  (with-udp-pair (ea eb)
    (let* ((ka (generate-keypair)) (kb (generate-keypair))
           ;; B's link has to be reading for the resent msg1 to be answered
           (lb-box nil)
           (join (udp-accept-in-thread
                  eb kb :wrap (lambda (p) (dropping-port p (drop-first +phase-msg2+)))))
           (reader (sb-thread:make-thread
                    (lambda ()
                      (let ((lb (funcall join)))
                        (setf lb-box lb)
                        (when (cl-fips::stream-link-p lb)
                          (handler-case (multiple-value-list (stream-link-receive lb :timeout-ms 5000))
                            (error (e) e)))))))
           (port (cl-fips.transport:udp-peer-port ea "127.0.0.1"
                                                  (cl-fips.transport:udp-endpoint-local-port eb)))
           (t0 (now-ms))
           (la (handler-case (stream-link-initiate port ka (keypair-public-bytes kb) (random-epoch)
                                                   :mtu cl-fips.transport:+udp-mtu+ :timeout-ms 8000)
                 (error (e) e)))
           (ms (- (now-ms) t0))
           (answered (sb-thread:join-thread reader)))
      (check "U3 the handshake completed although the first msg2 was lost" (cl-fips::stream-link-p la))
      (check (format nil "U3 ... after the msg1 resend (~d ms)" ms) (<= 900 ms 2500))
      (check "U3 B's established link answered the resent msg1 again"
             (and (consp answered) (null (first answered)) (eq (second answered) :rekey-answered)))
      (when (and (cl-fips::stream-link-p la) (cl-fips::stream-link-p lb-box))
        (check "U3 both sides hold one session" (equalp (stream-link-handshake-hash la)
                                                        (stream-link-handshake-hash lb-box)))
        (udp-round-trip la lb-box "U3")))))

(defun raw-udp-send (to-port octets)
  (let ((s (usocket:socket-connect "127.0.0.1" to-port :protocol :datagram
                                                       :element-type '(unsigned-byte 8))))
    (unwind-protect (usocket:socket-send s octets (length octets))
      (usocket:socket-close s))))

(defun test-udp-malformed ()
  (with-udp-pair (ea eb)
    (let ((ka (generate-keypair)) (kb (generate-keypair)))
      (multiple-value-bind (la lb) (udp-dial ea eb ka kb)
        (when (and (cl-fips::stream-link-p la) (cl-fips::stream-link-p lb))
          ;; garbage from A's own address reaches B's link queue: forge it by
          ;; sending from A's port is not possible, so send it through A's port object
          (let ((write (cl-fips::byte-port-write-all (stream-link-port la))))
            (funcall write (octets 1 2 3))                               ; under a prefix
            (funcall write (octets #x00 #x00 #x10 #x00 1 2 3 4 5))       ; length mismatch
            (funcall write (octets #x00 #x00 #xff #x04))                 ; over the MTU
            (funcall write (concatenate '(vector (unsigned-byte 8))      ; a frame that does not open
                                        (octets #x00 #x00 #x01 #x00) (filler 12 0) (octets 9) (filler 16 7))))
          (let ((reasons (loop repeat 4
                               collect (handler-case (progn (stream-link-receive lb :timeout-ms 2000) :accepted)
                                         (link-error (e) (if (link-error-fatal-p e) :fatal (link-error-reason e)))))))
            (check (format nil "U4 each bad datagram is a non-fatal drop ~s" reasons)
                   (equal reasons '(:truncated :length-mismatch :payload-too-large :wrong-receiver-index))))
          (check "U4 B's port is still open" (not (cl-fips::byte-port-closed (stream-link-port lb))))
          (udp-round-trip la lb "U4")
          (check "U4 a read with nothing to read is a non-fatal :timeout"
                 (handler-case (progn (stream-link-receive lb :timeout-ms 100) nil)
                   (link-error (e) (and (not (link-error-fatal-p e)) (eq (link-error-reason e) :timeout))))))))))

(defun test-udp-strangers ()
  (let ((ep (cl-fips.transport:udp-open)))
    (unwind-protect
         (let ((port (cl-fips.transport:udp-endpoint-local-port ep)))
           (raw-udp-send port (octets #x00 #x00 #x01 #x00 1 2 3 4))
           (check "U5 a stranger's established frame is not offered as a dial"
                  (null (cl-fips.transport:udp-accept ep :timeout-ms 300)))
           (check "U5 ... it was counted as dropped" (= (cl-fips.transport:udp-endpoint-dropped ep) 1))
           (raw-udp-send port (cl-fips::build-msg1 7 (filler 106 1)))
           (multiple-value-bind (p host) (cl-fips.transport:udp-accept ep :timeout-ms 1000)
             (check "U5 a stranger's msg1 is offered as a dial" (and p (equal host "127.0.0.1")))
             (when p
               (check "U5 ... with the msg1 queued on its port"
                      (= (length (funcall (cl-fips::byte-port-read-packet p) nil)) 114))
               (check "U5 a second accept finds nothing"
                      (null (cl-fips.transport:udp-accept ep :timeout-ms 100))))))
      (cl-fips.transport:udp-close ep))))

(defun test-udp-nodes ()
  (with-udp-pair (ea eb)
    (let* ((na (new-test-node)) (nb (new-test-node))
           (ka (cl-fips::fips-node-static na)) (kb (cl-fips::fips-node-static nb)))
      (multiple-value-bind (la lb) (udp-dial ea eb ka kb :routing-a (fips-node-tree na)
                                                         :routing-b (fips-node-tree nb))
        (check "U6 the two nodes linked over UDP" (and (cl-fips::stream-link-p la) (cl-fips::stream-link-p lb)))
        (when (and (cl-fips::stream-link-p la) (cl-fips::stream-link-p lb))
          (node-add-link na la) (node-add-link nb lb)
          (let ((events '()) (t0 (now-ms)))
            (flet ((run (ms)
                     (loop with end = (+ (now-ms) ms)
                           while (< (now-ms) end)
                           do (let ((now (- (now-ms) t0)))
                                (setf events (append events (node-tick na now) (node-tick nb now)))
                                (cl-fips.transport:udp-pump ea :timeout-ms 20)
                                (cl-fips.transport:udp-pump eb :timeout-ms 20)
                                (loop for (n ep l) in (list (list na ea la) (list nb eb lb))
                                      do (loop while (cl-fips.transport:udp-port-ready-p ep (stream-link-port l))
                                               do (setf events (append events (node-receive n l :timeout-ms 0
                                                                                                :now now)))))))))
              (run 300)
              (node-open-session na (node-pub nb) :now (- (now-ms) t0))
              (run 500)
              (check "U6 A's session with B is established over UDP"
                     (has-event events :established))
              (handler-case
                  (progn (node-send-data na (fips-node-own nb) (ascii "over udp") :dst-port 9 :now (- (now-ms) t0))
                         (node-send-data na (fips-node-own nb) (filler (- 1280 cl-fips::+fsp-data-overhead+) 3)
                                         :dst-port 9 :now (- (now-ms) t0)))
                (error (e) (check (format nil "U6 send: ~a" e) nil)))
              (check "U6 one byte past the UDP DataPacket limit is refused"
                     (handler-case (progn (node-send-data na (fips-node-own nb)
                                                          (filler (- 1281 cl-fips::+fsp-data-overhead+) 3)
                                                          :now (- (now-ms) t0))
                                          nil)
                       (node-error (e) (eq (node-error-reason e) :too-big))))
              (run 500)
              (let ((data (loop for e in events when (eq (first e) :data) collect (fifth e))))
                (check "U6 B received both DataPackets, the second at the UDP limit"
                       (and (= (length data) 2) (equalp (first data) (ascii "over udp"))
                            (= (length (second data)) (- 1280 cl-fips::+fsp-data-overhead+))))))))))))

(defun test-udp ()
  (flet ((arm (name fn)
           (handler-case (funcall fn)
             (error (e) (incf *checks*) (incf *failures*)
               (format t "  FAIL ~a aborted: ~a~%" name e)))))
    (arm "U1" #'test-udp-handshake)
    (arm "U2" #'test-udp-lost-msg1)
    (arm "U3" #'test-udp-lost-msg2)
    (arm "U4" #'test-udp-malformed)
    (arm "U5" #'test-udp-strangers)
    (arm "U6" #'test-udp-nodes)))

(let ((tcp *tcp-suite*))
  (setf *tcp-suite* (lambda () (funcall tcp) (test-udp))))
