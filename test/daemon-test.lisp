;;;; daemon-test.lisp -- the SBCL daemon: identity files, config, two daemons
;;;; talking over real loopback UDP and TCP, and a redial after a peer restarts.
;;;;
;;;;   D1  identity: a key file is created (nsec, mode 0600, .pub beside it) and
;;;;       read back as the same key; a hex key file is read too
;;;;   D2  config: a plist file, relative key file resolved against it
;;;;   D3  A dials B over UDP from config; A sends to B's npub before any session
;;;;       exists, the data waits, B's echo port answers, A gets the echo
;;;;   D4  the same over TCP
;;;;   D5  B stops: A sees the TCP link close and schedules a redial; B comes back
;;;;       with the same key on the same port and A's link comes back up
;;;;
;;;; Both daemons run in this one thread, stepped in turn.

(in-package #:cl-fips.test)

(defun tmp-dir ()
  (let ((d (format nil "/tmp/cl-fips-daemon-test-~d-~d/" (sb-posix:getpid) (random 1000000))))
    (ensure-directories-exist d)
    d))

(defun daemon-pair-step (ds &optional (ms 10))
  (dolist (d ds) (cl-fips.daemon:daemon-step d :max-wait-ms ms)))

(defun step-until (ds pred &key (timeout-ms 10000))
  (let ((end (+ (now-ms) timeout-ms)))
    (loop until (or (funcall pred) (> (now-ms) end))
          do (daemon-pair-step ds))
    (funcall pred)))

(defun event-recorder ()
  (let ((events '()))
    (values (lambda (d e) (declare (ignore d)) (push e events))
            (lambda () (reverse events)))))

(defun test-daemon-identity ()
  (let* ((dir (tmp-dir)) (path (format nil "~afips.key" dir)))
    (multiple-value-bind (kp created) (cl-fips.daemon:load-or-create-identity path)
      (check "D1 a missing key file is created" created)
      (let ((line (with-open-file (in path) (read-line in))))
        (check "D1 ... holding an nsec" (and (> (length line) 5) (string= "nsec1" line :end2 5))))
      (check "D1 ... with mode 0600"
             (= (logand (sb-posix:stat-mode (sb-posix:stat path)) #o777) #o600))
      (check "D1 ... and its npub beside it"
             (string= (with-open-file (in (format nil "~afips.pub" dir)) (read-line in))
                      (npub-encode (keypair-public-bytes kp))))
      (multiple-value-bind (again created2) (cl-fips.daemon:load-or-create-identity path)
        (check "D1 reading it back gives the same key, without creating one"
               (and (not created2) (equalp (keypair-public-bytes again) (keypair-public-bytes kp))))))
    (let ((hex-path (format nil "~ahex.key" dir)))
      (with-open-file (o hex-path :direction :output)
        (write-line "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa" o))
      (check "D1 a hex key file is read as the same secret its nsec names"
             (equalp (keypair-public-bytes (cl-fips.daemon:load-or-create-identity hex-path))
                     (keypair-public-bytes
                      (secp256k1-fast.ecdh:keypair-from-secret
                       (nsec-decode "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"))))))))

(defun test-daemon-config ()
  (let* ((dir (tmp-dir)) (path (format nil "~anode.conf" dir)))
    (with-open-file (o path :direction :output)
      (write-string "(:identity (:key-file \"id/fips.key\") :udp (:bind \"127.0.0.1:0\") :echo-ports (7))" o))
    (ensure-directories-exist (format nil "~aid/" dir))
    (let* ((config (cl-fips.daemon:load-config path))
           (d (cl-fips.daemon:make-daemon config :log nil)))
      (check "D2 the relative key file is created beside the config"
             (probe-file (format nil "~aid/fips.key" dir)))
      (check "D2 the daemon's npub is that file's"
             (string= (cl-fips.daemon:daemon-npub d)
                      (with-open-file (in (format nil "~aid/fips.pub" dir)) (read-line in)))))
    (with-open-file (o path :direction :output :if-exists :supersede)
      (write-string "(:udp #.(error \"read-eval\"))" o))
    (check "D2 the config is read with *READ-EVAL* off"
           (handler-case (progn (cl-fips.daemon:load-config path) nil) (error () t)))))

(defun daemon-echo-arm (transport label)
  (let* ((kb (generate-keypair))
         (b (cl-fips.daemon:daemon-start
             (cl-fips.daemon:make-daemon
              (list transport (list :bind "127.0.0.1:0") :echo-ports '(7))
              :keypair kb :log nil)))
         (b-port (if (eq transport :udp) (cl-fips.daemon:daemon-udp-port b) (cl-fips.daemon:daemon-tcp-port b)))
         (b-npub (npub-encode (keypair-public-bytes kb))))
    (multiple-value-bind (hook events) (event-recorder)
      (let ((a (cl-fips.daemon:daemon-start
                (cl-fips.daemon:make-daemon
                 (list :udp (list :bind "127.0.0.1:0")
                       :peers (list (list :npub b-npub :transport transport
                                          :addr (format nil "127.0.0.1:~d" b-port) :alias "b")))
                 :on-event hook :log nil))))
        (unwind-protect
             (progn
               (check (format nil "~a A's link to B comes up" label)
                      (step-until (list a b) (lambda () (find :peer-up (funcall events) :key #'first))))
               (check (format nil "~a the first send waits for the session" label)
                      (eq (cl-fips.daemon:daemon-send a b-npub (ascii "echo me") :src-port 9 :dst-port 7)
                          :queued))
               (check (format nil "~a B's echo comes back to A's port 9" label)
                      (step-until (list a b)
                                  (lambda () (has-event (funcall events) :data
                                                        (node-addr (keypair-public-bytes kb)) 7 9 (ascii "echo me")))))
               (check (format nil "~a with the session up, a send goes at once" label)
                      (eq (cl-fips.daemon:daemon-send a b-npub (ascii "again") :src-port 9 :dst-port 7) :sent))
               (check (format nil "~a ... and is echoed" label)
                      (step-until (list a b)
                                  (lambda () (has-event (funcall events) :data
                                                        (node-addr (keypair-public-bytes kb)) 7 9 (ascii "again")))))
               (values a b kb b-port events))
          (cl-fips.daemon:daemon-stop a)
          (cl-fips.daemon:daemon-stop b))))))

(defun test-daemon-restart ()
  "D5: B goes away and comes back on the same port with the same key."
  (let* ((kb (generate-keypair))
         (mk-b (lambda (port) (cl-fips.daemon:daemon-start
                               (cl-fips.daemon:make-daemon (list :tcp (list :bind (format nil "127.0.0.1:~d" port)))
                                                           :keypair kb :log nil))))
         (b (funcall mk-b 0))
         (port (cl-fips.daemon:daemon-tcp-port b)))
    (multiple-value-bind (hook events) (event-recorder)
      (let ((a (cl-fips.daemon:daemon-start
                (cl-fips.daemon:make-daemon
                 (list :peers (list (list :npub (npub-encode (keypair-public-bytes kb)) :transport :tcp
                                          :addr (format nil "127.0.0.1:~d" port))))
                 :on-event hook :log nil))))
        (unwind-protect
             (progn
               (check "D5 A's TCP link to B comes up"
                      (step-until (list a b) (lambda () (find :peer-up (funcall events) :key #'first))))
               (cl-fips.daemon:daemon-stop b)
               (check "D5 A sees the link close when B stops"
                      (step-until (list a) (lambda () (find :peer-down (funcall events) :key #'first))
                                  :timeout-ms 5000))
               (setf b (funcall mk-b port))
               (check "D5 A redials and the link is back once B returns"
                      (step-until (list a b)
                                  (lambda () (= 2 (count :peer-up (funcall events) :key #'first)))
                                  :timeout-ms 15000))
               (check "D5 A holds exactly one link"
                      (= 1 (length (fips-node-links (cl-fips.daemon:daemon-node a))))))
          (cl-fips.daemon:daemon-stop a)
          (cl-fips.daemon:daemon-stop b))))))

(defun test-daemon-udp-junk ()
  "Review 2: junk from an address must not register it."
  (let* ((d (cl-fips.daemon:daemon-start
             (cl-fips.daemon:make-daemon (list :udp (list :bind "127.0.0.1:0")) :log nil)))
         (ep (cl-fips.daemon::daemon-udp d))
         (port (cl-fips.daemon:daemon-udp-port d)))
    (unwind-protect
         (progn
           (raw-udp-send port (octets 1 0 0 0))
           (raw-udp-send port (cl-fips::build-msg1 7 (filler 106 1)))   ; the right size, not a handshake
           (loop repeat 20 do (cl-fips.daemon:daemon-step d :max-wait-ms 20))
           (check "D6 a short datagram that looks like a msg1 registers nothing, nor does a forged msg1"
                  (and (zerop (hash-table-count (cl-fips.transport::udp-endpoint-peers ep)))
                       (null (cl-fips.transport::udp-endpoint-fresh ep)))))
      (cl-fips.daemon:daemon-stop d))))

(defun test-daemon-replay ()
  "Review 1: a second, authentic dial from a peer whose link is alive is refused."
  (let* ((ka (generate-keypair)) (kb (generate-keypair))
         (b (cl-fips.daemon:daemon-start
             (cl-fips.daemon:make-daemon (list :udp (list :bind "127.0.0.1:0")) :keypair kb :log nil)))
         (bport (cl-fips.daemon:daemon-udp-port b))
         (a (cl-fips.daemon:daemon-start
             (cl-fips.daemon:make-daemon
              (list :udp (list :bind "127.0.0.1:0")
                    :peers (list (list :npub (npub-encode (keypair-public-bytes kb)) :transport :udp
                                       :addr (format nil "127.0.0.1:~d" bport))))
              :keypair ka :log nil)))
         (refused nil))
    (setf (cl-fips.daemon::daemon-on-event b)
          (lambda (d e) (declare (ignore d)) (when (eq (first e) :link-refused) (setf refused t))))
    (unwind-protect
         (progn
           (step-until (list a b) (lambda () (= 1 (length (fips-node-links (cl-fips.daemon:daemon-node b))))))
           (let ((live (first (fips-node-links (cl-fips.daemon:daemon-node b)))))
             ;; the same key dials again from a new address (an attacker replaying, or a
             ;; second process with A's key): authentic, but A's link is alive
             (let* ((ep (cl-fips.transport:udp-open))
                    (port (cl-fips.transport:udp-peer-port ep "127.0.0.1" bport)))
               (unwind-protect
                    (progn
                      (cl-fips:stream-link-dial port ka (keypair-public-bytes kb) (random-epoch)
                                                :mtu cl-fips.transport:+udp-mtu+ :now-ms 0)
                      (step-until (list a b) (lambda () refused) :timeout-ms 3000))
                 (cl-fips.transport:udp-close ep)))
             (check "D7 B refuses a new link while A's is alive" refused)
             (check "D7 ... and keeps A's link"
                    (equal (fips-node-links (cl-fips.daemon:daemon-node b)) (list live)))))
      (cl-fips.daemon:daemon-stop a) (cl-fips.daemon:daemon-stop b))))

(defun test-daemon-slow-tcp ()
  "Review 7: a TCP connection that never sends its msg1 does not stall the loop."
  (let* ((d (cl-fips.daemon:daemon-start
             (cl-fips.daemon:make-daemon (list :tcp (list :bind "127.0.0.1:0")) :log nil)))
         (socks (loop repeat 5 collect (usocket:socket-connect "127.0.0.1" (cl-fips.daemon:daemon-tcp-port d)
                                                               :element-type '(unsigned-byte 8)))))
    (unwind-protect
         (progn
           (dolist (s socks) (write-byte 1 (usocket:socket-stream s)) (finish-output (usocket:socket-stream s)))
           (let ((t0 (now-ms)))
             (loop repeat 20 do (cl-fips.daemon:daemon-step d :max-wait-ms 10))
             (check (format nil "D8 five stalled connections do not stall the loop (~d ms for 20 steps)"
                            (- (now-ms) t0))
                    (< (- (now-ms) t0) 2000)))
           (check "D8 they are held, waiting" (= 5 (length (cl-fips.daemon::daemon-accepting d)))))
      (dolist (s socks) (ignore-errors (usocket:socket-close s)))
      (cl-fips.daemon:daemon-stop d))))

(defun test-daemon-crossing ()
  "Review 10: two daemons that each list the other come up together."
  (let* ((ka (generate-keypair)) (kb (generate-keypair))
         (ea (cl-fips.transport:udp-open)) (pa (cl-fips.transport:udp-endpoint-local-port ea))
         (eb (cl-fips.transport:udp-open)) (pb (cl-fips.transport:udp-endpoint-local-port eb)))
    (cl-fips.transport:udp-close ea) (cl-fips.transport:udp-close eb)
    (let* ((a (cl-fips.daemon:daemon-start
               (cl-fips.daemon:make-daemon
                (list :udp (list :bind (format nil "127.0.0.1:~d" pa))
                      :peers (list (list :npub (npub-encode (keypair-public-bytes kb)) :transport :udp
                                         :addr (format nil "127.0.0.1:~d" pb))))
                :keypair ka :log nil)))
           (b (cl-fips.daemon:daemon-start
               (cl-fips.daemon:make-daemon
                (list :udp (list :bind (format nil "127.0.0.1:~d" pb))
                      :peers (list (list :npub (npub-encode (keypair-public-bytes ka)) :transport :udp
                                         :addr (format nil "127.0.0.1:~d" pa))))
                :keypair kb :log nil)))
           (t0 (now-ms)))
      (unwind-protect
           (check (format nil "D9 two daemons dialling each other link within 5 s (~d ms)" (- (now-ms) t0))
                  (and (step-until (list a b)
                                   (lambda () (and (= 1 (length (fips-node-links (cl-fips.daemon:daemon-node a))))
                                                   (= 1 (length (fips-node-links (cl-fips.daemon:daemon-node b))))))
                                   :timeout-ms 5000)
                       (progn (setf t0 (- (now-ms) (- (now-ms) t0))) t)))
        (cl-fips.daemon:daemon-stop a) (cl-fips.daemon:daemon-stop b)))))

(defun test-daemon ()
  (flet ((arm (name fn)
           (handler-case (funcall fn)
             (error (e) (incf *checks*) (incf *failures*)
               (format t "  FAIL ~a aborted: ~a~%" name e)))))
    (arm "D1" #'test-daemon-identity)
    (arm "D2" #'test-daemon-config)
    (arm "D3" (lambda () (daemon-echo-arm :udp "D3 (UDP)")))
    (arm "D4" (lambda () (daemon-echo-arm :tcp "D4 (TCP)")))
    (arm "D5" #'test-daemon-restart)
    (arm "D6" #'test-daemon-udp-junk)
    (arm "D7" #'test-daemon-replay)
    (arm "D8" #'test-daemon-slow-tcp)
    (arm "D9" #'test-daemon-crossing)))

(let ((prev *tcp-suite*))
  (setf *tcp-suite* (lambda () (funcall prev) (test-daemon))))
