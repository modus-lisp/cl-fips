;;;; tcp-test.lisp -- FMP over REAL TCP on loopback, against the upstream oracle.
;;;;
;;;;   T1  oracle serve-tcp : Rust IK responder listens; Lisp initiator dials.
;;;;   T2  oracle dial-tcp  : Lisp IK responder listens; Rust initiator dials.
;;;;       Both: handshake hash, keys, epochs and indices cross-checked; three
;;;;       Rust frames opened by Lisp; Lisp frames (one at 1368 bytes of payload,
;;;;       the MTU ceiling) opened by Rust and ECHOED back, the echoes opened by
;;;;       Lisp; a tampered Lisp frame that Rust must refuse; Rust's stream
;;;;       reader must end on a clean EOF when Lisp closes.
;;;;   T3  oracle dial-raw  : malformed bytes on the wire to a Lisp responder --
;;;;       each must end in a specific LINK-ERROR and a close the Rust side
;;;;       OBSERVES (EOF or RST), with controls.
;;;;   T4  timeouts: a peer that stops mid-packet, and one that drips a packet
;;;;       slower than the deadline, are dropped on time; controls show a slow
;;;;       but in-deadline packet is accepted and that the timing check can fail.
;;;;
;;;; Every socket is 127.0.0.1 on an ephemeral port.  Test-only: uses
;;;; SB-EXT:RUN-PROGRAM (via noise-test.lisp) and the cl-fips/transport adapter.

(in-package #:cl-fips.test)

(defparameter *tcp-timeout-ms* 10000 "Generous: a wedged test fails, it never hangs.")

(defun now-ms () (floor (* 1000 (get-internal-real-time)) internal-time-units-per-second))

(defun int-field-or (op name) (let ((v (field op name))) (and v (parse-integer v))))

(defun oracle-command (op string)
  (write-line string (oproc-in op)) (force-output (oproc-in op)))

;;; --- the exchange shared by T1 and T2 ----------------------------------------------

(defun tcp-lisp-messages ()
  (list (octets #x20 (ascii "lisp frame zero"))
        (octets #x21 (filler 1363 #x5a))     ; inner 4 + 1364 = 1368 = MTU 1400 - 32
        (octets #x22)))

(defun tcp-exchange-checks (label op link)
  ;; Rust's three frames, as printed on its stdout before it wrote them.
  (oracle-read-until op "frames_ready")
  (dotimes (n 3)
    (multiple-value-bind (m ts flags counter) (stream-link-receive link)
      (check (format nil "~a Lisp opens upstream frame ~d off the socket" label n)
             (and (equalp m (field-bytes op (format nil "frame_~d_message" n)))
                  (= ts (int-field op (format nil "frame_~d_timestamp" n)))
                  (= flags (int-field op (format nil "frame_~d_flags" n)))
                  (= counter n)))))
  ;; Lisp frames, each opened by upstream and echoed back.
  (loop for msg in (tcp-lisp-messages) for k from 0
        do (let ((wire (stream-link-send link msg :timestamp-ms (* 100 (1+ k)))))
             (when (= k 1)
               (check (format nil "~a the MTU-ceiling frame is exactly 1400 bytes" label)
                      (= (length wire) 1400)))
             (oracle-read-until op "frame_result")
             (check (format nil "~a upstream opens Lisp frame ~d" label k)
                    (and (equal (field op "frame_result") "ok")
                         (equalp (field-bytes op "frame_message") msg)
                         (= (int-field op "frame_timestamp") (* 100 (1+ k)))
                         (= (int-field op "frame_counter") k)
                         (equal (field op "frame_payload_len_ok") "1")))
             (multiple-value-bind (m ts) (stream-link-receive link)
               (check (format nil "~a Lisp opens upstream's echo of frame ~d" label k)
                      (and (equalp m msg) (= ts (1+ (* 100 (1+ k)))))))))
  ;; Negative control: upstream must refuse a tampered Lisp frame.
  (let* ((wire (fmp-seal-frame (stream-link-session link) (stream-link-their-index link)
                               1 (octets #x23 (ascii "tampered"))))
         (bad (flip wire 30)))
    (write-fmp-packet (stream-link-port link) bad)
    (oracle-read-until op "frame_result")
    (check (format nil "~a control: upstream REFUSES a tampered Lisp frame" label)
           (equal (field op "frame_result") "error")))
  (stream-link-close link)
  (oracle-read-until op "frames_received")
  (check (format nil "~a upstream's stream reader saw 3 good frames then EOF" label)
         (and (equal (field op "frames_received") "3")
              (search "io:" (or (field op "stream_end") "")))))

(defun t1-lisp-initiator ()
  (let ((op (oracle-start "serve-tcp")) (epoch (random-epoch)) (static (generate-keypair)))
    (unwind-protect
         (progn
           (oracle-read-until op "ready")
           (let* ((port (cl-fips.transport:tcp-connect "127.0.0.1" (int-field op "port")))
                  (link (stream-link-initiate port static (field-bytes op "responder_static")
                                              epoch :timeout-ms *tcp-timeout-ms*)))
             (oracle-read-until op "oracle_receiver_idx")
             (check "T1 upstream responder accepted Lisp's msg1 over TCP"
                    (equal (field op "result") "ok"))
             (check "T1 handshake hash matches upstream"
                    (equalp (stream-link-handshake-hash link) (field-bytes op "handshake_hash")))
             (check "T1 upstream learned Lisp's static key and epoch"
                    (and (equalp (field-bytes op "initiator_static") (keypair-public-bytes static))
                         (equalp (field-bytes op "remote_epoch") epoch)))
             (check "T1 indices agree both ways"
                    (and (= (int-field op "lisp_receiver_idx") (stream-link-our-index link))
                         (= (int-field op "oracle_receiver_idx") (stream-link-their-index link))))
             (tcp-exchange-checks "T1" op link)))
      (oracle-finish op))))

(defun t2-lisp-responder ()
  (let ((listener (cl-fips.transport:tcp-listen)) (op (oracle-start "dial-tcp"))
        (static (generate-keypair)) (epoch (random-epoch)))
    (unwind-protect
         (progn
           (oracle-command op (princ-to-string (cl-fips.transport:tcp-listener-port listener)))
           (oracle-send op (keypair-public-bytes static))
           (let ((port (cl-fips.transport:tcp-accept listener :timeout-ms *tcp-timeout-ms*)))
             (check "T2 the upstream initiator connected" port)
             (when port
               (let ((link (stream-link-accept port static epoch :timeout-ms *tcp-timeout-ms*)))
                 (oracle-read-until op "oracle_receiver_idx")
                 (check "T2 upstream initiator accepted Lisp's msg2 over TCP"
                        (equal (field op "result") "ok"))
                 (check "T2 handshake hash matches upstream"
                        (equalp (stream-link-handshake-hash link)
                                (field-bytes op "handshake_hash")))
                 (check "T2 Lisp learned upstream's static key; upstream read Lisp's epoch"
                        (and (equalp (stream-link-remote-static link)
                                     (field-bytes op "initiator_static"))
                             (equalp (field-bytes op "remote_epoch") epoch)))
                 (check "T2 indices agree both ways"
                        (and (= (int-field op "lisp_receiver_idx") (stream-link-our-index link))
                             (= (int-field op "oracle_receiver_idx")
                                (stream-link-their-index link))))
                 (tcp-exchange-checks "T2" op link)))))
      (cl-fips.transport:tcp-listener-close listener)
      (oracle-finish op))))

;;; --- T3 / T4: a raw peer -----------------------------------------------------------

(defun raw-peer (commands lisp-side &key (wait-ms 4000))
  "Start dial-raw, connect it to a fresh listener, queue COMMANDS (strings; ~d is
   the port) and `wait-close WAIT-MS`, accept, and call LISP-SIDE with the port.
   Returns (values what-lisp-side-returned elapsed-ms oracle)."
  (let* ((listener (cl-fips.transport:tcp-listen))
         (p (cl-fips.transport:tcp-listener-port listener))
         (op (oracle-start "dial-raw")))
    (unwind-protect
         (progn
           (oracle-command op (format nil "connect ~d" p))
           (dolist (c commands) (oracle-command op c))
           (oracle-command op (format nil "wait-close ~d" wait-ms))
           (oracle-command op "end")
           (let ((port (cl-fips.transport:tcp-accept listener :timeout-ms *tcp-timeout-ms*))
                 (t0 (now-ms)))
             (if (null port)
                 (values :no-connection 0 op)
                 (let ((result (funcall lisp-side port)))
                   (let ((elapsed (- (now-ms) t0)))
                     (byte-port-close port)
                     (oracle-read-until op "bytes_received")
                     (values result elapsed op))))))
      (cl-fips.transport:tcp-listener-close listener)
      (oracle-finish op))))

(defun accept-outcome (port &key (timeout-ms 2000))
  "Run the responder handshake; return the LINK-ERROR, or :established."
  (handler-case (progn (stream-link-accept port (generate-keypair) (random-epoch)
                                           :timeout-ms timeout-ms)
                       :established)
    (link-error (e) e)))

(defun send-hex (&rest parts) (format nil "send ~a" (hex (apply #'octets parts))))

(defun raw-case (label commands expect &key (timeout-ms 2000))
  "One malformed-input case: the handshake must fail with reason EXPECT, the port
   must be closed by the link layer itself, and upstream must see the close."
  (multiple-value-bind (outcome elapsed op)
      (raw-peer commands (lambda (port)
                           (let ((o (accept-outcome port :timeout-ms timeout-ms)))
                             (list o (byte-port-closed port)))))
    (destructuring-bind (o closed-by-link) outcome
      (check (format nil "T3 ~a: link-error ~s" label expect)
             (and (typep o 'link-error) (eq (link-error-reason o) expect)
                  (link-error-fatal-p o)))
      (check (format nil "T3 ~a: the link layer closed the socket" label) closed-by-link)
      (check (format nil "T3 ~a: upstream observed the close promptly" label)
             (and (equal (field op "peer_closed") "1")
                  (< (int-field op "waited_ms") 3000)))
      (values o elapsed op))))

(defun test-tcp-malformed ()
  (let ((rs (generate-keypair)))
    (raw-case "msg1 declaring payload_len 50"
              (list (send-hex 1 0 50 0 (filler 50))) :handshake-size-mismatch)
    (raw-case "msg1 declaring payload_len 111"
              (list (send-hex 1 0 111 0 (filler 111))) :handshake-size-mismatch)
    (raw-case "unknown phase 0x5" (list (send-hex 5 0 10 0 (filler 10))) :unknown-phase)
    (raw-case "TLS ClientHello" (list (send-hex #x16 3 1 0 #xa5 1 0 0 (filler 40 0)))
              :unknown-version)
    (raw-case "msg1 truncated at 44 of 114 bytes, then FIN"
              (list (send-hex 1 0 110 0 (filler 40)) "shutdown") :truncated)
    (raw-case "an established frame before any handshake"
              (list (send-hex 0 0 10 0 (filler 38))) :unexpected-phase)
    (raw-case "control: a 114-byte msg1 of garbage gets past framing"
              (list (send-hex 1 0 110 0 (filler 110))) :handshake-failed)
    ;; Control: a genuine msg1 sent raw is accepted and answered with a msg2.
    (multiple-value-bind (outcome elapsed op)
        (raw-peer (list (format nil "send ~a" (hex (genuine-msg1-to rs))))
                  (lambda (port) (handler-case (progn (stream-link-accept port rs (random-epoch)
                                                                           :timeout-ms 2000)
                                                      :established)
                                   (link-error (e) e))))
      (declare (ignore elapsed))
      (check "T3 control: a genuine msg1 over the raw socket establishes the link"
             (eq outcome :established))
      (check "T3 control: upstream received exactly one 69-byte msg2"
             (= (int-field op "bytes_received") 69)))
    ;; Control for the close observer: Lisp holds the socket open past the
    ;; window, so upstream must report NO close.
    (multiple-value-bind (outcome elapsed op)
        (raw-peer '() (lambda (port) (declare (ignore port)) (sleep 1.2) :held) :wait-ms 400)
      (declare (ignore outcome elapsed))
      (check "T3 control: upstream's close observer answers 0 when nothing closed"
             (and (equal (field op "peer_closed") "0") (equal (field op "close_kind") "timeout"))))))

(defun test-tcp-write-to-closed ()
  ;; The peer connects and closes at once.  Writing must end in :write-failed
  ;; (EPIPE / RST), not succeed forever and not crash.
  (multiple-value-bind (outcome)
      (raw-peer '() (lambda (port)
                      (sleep 0.3)
                      (handler-case
                          (loop repeat 200 do (write-fmp-packet port (octets 0 0 0 0 (filler 28)))
                                finally (return :wrote-everything))
                        (link-error (e) (list (link-error-reason e) (byte-port-closed port)))))
                :wait-ms 0)
    (check "T3 writing to a peer that closed is :write-failed and closes the socket"
           (equal outcome '(:write-failed t)))))

(defun genuine-msg1-to (rs) (values (genuine-msg1 rs)))

(defun timed-reason (port timeout-ms)
  "(values reason elapsed-ms) for one READ-FMP-PACKET with TIMEOUT-MS."
  (let ((t0 (now-ms)))
    (let ((reason (handler-case (progn (read-fmp-packet port :timeout-ms timeout-ms) :packet)
                    (link-error (e) (link-error-reason e)))))
      (values reason (- (now-ms) t0)))))

(defun test-tcp-timeouts ()
  ;; A peer that sends 24 bytes of a msg1 and then nothing, holding the socket open.
  (multiple-value-bind (outcome elapsed op)
      (raw-peer (list (send-hex 1 0 110 0 (filler 20)))
                (lambda (port) (multiple-value-list (timed-reason port 500))))
    (declare (ignore elapsed))
    (destructuring-bind (reason ms) outcome
      (check "T4 a peer stalled mid-packet is dropped with :timeout" (eq reason :timeout))
      (check (format nil "T4 ... after the 500 ms deadline, not before or long after (~d ms)" ms)
             (<= 480 ms 2000))
      (check "T4 ... and upstream saw the close while still holding its socket open"
             (and (equal (field op "peer_closed") "1") (< (int-field op "waited_ms") 2500)))))
  ;; Dripping: a byte burst every 300 ms never lets a 700 ms packet deadline pass.
  ;; A per-READ timeout would never fire here; the deadline is per packet.
  (multiple-value-bind (outcome)
      (raw-peer (list* (send-hex 1 0 110 0)
                       (loop repeat 8 append (list "sleep 300" (send-hex (filler 10)))))
                (lambda (port) (multiple-value-list (timed-reason port 700))))
    (destructuring-bind (reason ms) outcome
      (check (format nil "T4 a packet dripped slower than its deadline is :timeout (~d ms)" ms)
             (and (eq reason :timeout) (<= 680 ms 1500)))))
  ;; Control: a genuine msg1 split in two with a 300 ms gap arrives inside a
  ;; 2000 ms deadline, so the packet is read whole.
  (let ((m1 (genuine-msg1 (generate-keypair))))
    (multiple-value-bind (outcome)
        (raw-peer (list (format nil "send ~a" (hex (subseq m1 0 30))) "sleep 300"
                        (format nil "send ~a" (hex (subseq m1 30))))
                  (lambda (port) (multiple-value-list (timed-reason port 2000))))
      (destructuring-bind (reason ms) outcome
        (check (format nil "T4 control: a slow packet inside its deadline is read (~d ms)" ms)
               (and (eq reason :packet) (>= ms 250))))))
  ;; Control that the timing check can fail: with NO deadline the same stall is
  ;; ended only by the peer's FIN 1500 ms later, as :truncated -- the T4 predicate
  ;; (:timeout within 2000 ms of a 500 ms deadline) must be false for it.
  (multiple-value-bind (outcome)
      (raw-peer (list (send-hex 1 0 110 0 (filler 20)) "sleep 1500" "shutdown")
                (lambda (port) (multiple-value-list (timed-reason port nil))))
    (destructuring-bind (reason ms) outcome
      (check (format nil "T4 control: without a deadline the stall lasts until FIN (~d ms)" ms)
             (and (eq reason :truncated) (>= ms 1400)))
      (check "T4 control: ... so the timeout predicate rejects that run"
             (not (and (eq reason :timeout) (<= 480 ms 2000)))))))

(defun test-tcp ()
  (cond
    ((sb-ext:posix-getenv "CL_FIPS_NO_ORACLE")
     (format t "  SKIPPED: TCP arms (CL_FIPS_NO_ORACLE set; they need the oracle as the far peer)~%"))
    ((not (oracle-binary))
     (incf *checks*) (incf *failures*)
     (format t "  FAIL oracle binary unavailable (set CL_FIPS_NO_ORACLE=1 to skip)~%"))
    (t (flet ((arm (name fn)
                ;; An unexpected LINK-ERROR (e.g. a deadline expiring because the
                ;; peer refused something) is a recorded failure, not an abort.
                (handler-case (funcall fn)
                  (link-error (e) (incf *checks*) (incf *failures*)
                    (format t "  FAIL ~a aborted: ~a~%" name e)))))
         (dotimes (k 2) (arm "T1" #'t1-lisp-initiator) (arm "T2" #'t2-lisp-responder))
         (arm "T3" #'test-tcp-malformed)
         (arm "T3 write" #'test-tcp-write-to-closed)
         (arm "T4" #'test-tcp-timeouts)))))

(setf *tcp-suite* 'test-tcp)
