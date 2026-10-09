;;;; mmp-test.lisp -- MMP link reports (src/mmp.lisp) and the stream link's rekey
;;;; and report wiring (src/link.lisp).  Pure: in-memory ports, time passed in.
;;;;
;;;;   M1  SenderReport bytes, offset by offset, from wire.rs's layout table
;;;;   M2  ReceiverReport bytes, likewise; a negative owd_trend round-trips
;;;;   M3  negative controls: truncated, overlong, wrong msg_type, empty
;;;;   M4  the receiver's counting: highest / cumulative / reorder, bursts, the
;;;;       interval reset, the timestamp echo and dwell; and upstream's delivery
;;;;       rule (delivery.rs delivered(), Base::Zero) over the report it built
;;;;   M5  reset_for_rekey keeps the cumulative counts and nothing else
;;;;   M6  the peer's reports: stale / duplicate dropped, an RTT sample taken
;;;;   M7  the sender's interval
;;;;   S1  two Lisp stream links over an in-memory pipe: a rekey started by the
;;;;       poll, answered on the stream, cut over, adopted -- keys and indices
;;;;       rotate and frames flow both ways; ReceiverReports cross and decode
;;;;   S2  negative control: with reports off the poll emits none

(in-package #:cl-fips.test)

(defun le (v n) (coerce (encode-uint-le-test v n) 'list))
(defun encode-uint-le-test (v n)
  (let ((out (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n out) (setf (aref out i) (ldb (byte 8 (* 8 i)) v)))))

;;; --- M1 / M2 ------------------------------------------------------------------------

(defun m1-sender-report ()
  (let* ((sr (make-sender-report :interval-start-counter #x0102030405060708
                                 :interval-end-counter #x1112131415161718
                                 :interval-start-timestamp #xa1a2a3a4
                                 :interval-end-timestamp #xb1b2b3b4
                                 :interval-bytes-sent #xc1c2c3c4
                                 :cumulative-packets-sent #xd1d2d3d4d5d6d7d8
                                 :cumulative-bytes-sent #xe1e2e3e4e5e6e7e8))
         (w (encode-sender-report sr))
         (expected (append '(#x01 0 0 0)
                           (le #x0102030405060708 8) (le #x1112131415161718 8)
                           (le #xa1a2a3a4 4) (le #xb1b2b3b4 4) (le #xc1c2c3c4 4)
                           (le #xd1d2d3d4d5d6d7d8 8) (le #xe1e2e3e4e5e6e7e8 8))))
    (check "M1 SenderReport is 48 bytes" (= (length w) 48))
    (check "M1 SenderReport bytes match wire.rs [0]..[47]" (equal (coerce w 'list) expected))
    (check "M1 SenderReport round trip" (equalp (decode-sender-report w) sr))))

(defun m2-receiver-report ()
  (let* ((rr (make-receiver-report :highest-counter #x0102030405060708
                                   :cumulative-packets-recv #x1112131415161718
                                   :cumulative-bytes-recv #x2122232425262728
                                   :timestamp-echo #x31323334 :dwell-time #x4142
                                   :max-burst-loss #x5152 :mean-burst-loss #x6162
                                   :jitter #x71727374 :ecn-ce-count #x81828384
                                   :owd-trend -2 :burst-loss-count #x91929394
                                   :cumulative-reorder-count #xa1a2a3a4
                                   :interval-packets-recv #xb1b2b3b4
                                   :interval-bytes-recv #xc1c2c3c4))
         (w (encode-receiver-report rr))
         (expected (append '(#x02 0 0 0)
                           (le #x0102030405060708 8) (le #x1112131415161718 8)
                           (le #x2122232425262728 8) (le #x31323334 4) (le #x4142 2)
                           (le #x5152 2) (le #x6162 2) '(0 0) (le #x71727374 4)
                           (le #x81828384 4) '(#xfe #xff #xff #xff) (le #x91929394 4)
                           (le #xa1a2a3a4 4) (le #xb1b2b3b4 4) (le #xc1c2c3c4 4))))
    (check "M2 ReceiverReport is 68 bytes" (= (length w) 68))
    (check "M2 ReceiverReport bytes match wire.rs [0]..[67]" (equal (coerce w 'list) expected))
    (check "M2 ReceiverReport round trip, owd_trend -2 signed"
           (equalp (decode-receiver-report w) rr))
    (let ((w2 (copy-seq w)))
      (setf (aref w2 38) #xff (aref w2 39) #xff (aref w2 1) #xaa)
      (check "M2 reserved bytes are skipped unchecked, as upstream"
             (equalp (decode-receiver-report w2) rr)))))

;;; --- M3 -----------------------------------------------------------------------------

(defun m3-negative-controls ()
  (let ((sr (encode-sender-report (make-sender-report :cumulative-packets-sent 3)))
        (rr (encode-receiver-report (make-receiver-report :highest-counter 3))))
    (check "M3 control: the intact reports decode"
           (and (decode-sender-report sr) (decode-receiver-report rr)))
    (check "M3 truncated SenderReport (47 bytes) rejected" (null (decode-sender-report (subseq sr 0 47))))
    (check "M3 truncated ReceiverReport (67 bytes) rejected"
           (null (decode-receiver-report (subseq rr 0 67))))
    (check "M3 truncated ReceiverReport (36 bytes) rejected"
           (null (decode-receiver-report (subseq rr 0 36))))
    (check "M3 overlong SenderReport (49 bytes) rejected"
           (null (decode-sender-report (concatenate '(vector (unsigned-byte 8)) sr #(0)))))
    (check "M3 overlong ReceiverReport (69 bytes) rejected"
           (null (decode-receiver-report (concatenate '(vector (unsigned-byte 8)) rr #(0)))))
    (check "M3 a ReceiverReport body is not a SenderReport" (null (decode-sender-report rr)))
    (check "M3 a 48-byte body typed 0x02 is not a SenderReport"
           (null (decode-sender-report (let ((x (copy-seq sr))) (setf (aref x 0) 2) x))))
    (check "M3 empty message rejected"
           (and (null (decode-sender-report (bytes))) (null (decode-receiver-report (bytes)))))
    (let ((mmp (make-mmp-peer)))
      (check "M3 the dispatcher calls a truncated report :malformed"
             (eq (mmp-handle-report mmp (subseq rr 0 60) 0) :malformed))
      (check "M3 ... and ignores other msg_types" (null (mmp-handle-report mmp (bytes #x51) 0))))))

;;; --- M4 / M5 ------------------------------------------------------------------------

(defun upstream-delivered-from-zero-p (rr announce-counter)
  "delivery.rs delivered(Base::Zero, rr), for an announce sent with
   ANNOUNCE-COUNTER: the report covers it and every counter 0..highest arrived."
  (let* ((highest (receiver-report-highest-counter rr))
         (got (receiver-report-cumulative-packets-recv rr))
         (sure (- got (receiver-report-cumulative-reorder-count rr)))
         (span (1+ highest)))
    (and (>= highest announce-counter) (>= got span) (= sure span))))

(defun m4-receiver ()
  (let ((r (make-mmp-receiver)))
    (check "M4 nothing received: no report, not due"
           (and (null (mmp-receiver-build-report r 0)) (not (mmp-receiver-due-p r 0))))
    (loop for c from 0 to 4 for now from 1000 by 100
          do (mmp-receiver-record r c (* 10 c) 100 nil now))
    (check "M4 due at once (first report)" (mmp-receiver-due-p r 1400))
    (let ((rr (mmp-receiver-build-report r 1410)))
      (check "M4 highest 4, cumulative 5 packets / 500 bytes, no reorder"
             (and (= (receiver-report-highest-counter rr) 4)
                  (= (receiver-report-cumulative-packets-recv rr) 5)
                  (= (receiver-report-cumulative-bytes-recv rr) 500)
                  (= (receiver-report-cumulative-reorder-count rr) 0)
                  (= (receiver-report-interval-packets-recv rr) 5)))
      (check "M4 echo = last sender timestamp, dwell = 10 ms"
             (and (= (receiver-report-timestamp-echo rr) 40) (= (receiver-report-dwell-time rr) 10)))
      (check "M4 upstream's delivery rule confirms counter 0 and 4 from this report"
             (and (upstream-delivered-from-zero-p rr 0) (upstream-delivered-from-zero-p rr 4)))
      (check "M4 ... and does not cover counter 5" (not (upstream-delivered-from-zero-p rr 5))))
    (check "M4 the interval reset: no data, no report" (null (mmp-receiver-build-report r 1500)))
    ;; a gap of two (5, 6 missing), then a late 6
    (mmp-receiver-record r 7 70 100 nil 1600)
    (mmp-receiver-record r 8 80 100 t 1700)
    (check "M4 cold-start interval: not due 199 ms after the last report"
           (not (mmp-receiver-due-p r 1609)))
    (check "M4 ... due at 200 ms" (mmp-receiver-due-p r 1610))
    (mmp-receiver-record r 6 60 100 nil 1750)
    (let ((rr (mmp-receiver-build-report r 1800)))
      (check "M4 one burst of 2: count 1, max 2, mean 2.0 (u8.8 = 512)"
             (and (= (receiver-report-burst-loss-count rr) 1)
                  (= (receiver-report-max-burst-loss rr) 2)
                  (= (receiver-report-mean-burst-loss rr) 512)))
      (check "M4 the late 6 is a reorder; highest stays 8; ECN CE counted"
             (and (= (receiver-report-cumulative-reorder-count rr) 1)
                  (= (receiver-report-highest-counter rr) 8)
                  (= (receiver-report-ecn-ce-count rr) 1)
                  (= (receiver-report-cumulative-packets-recv rr) 8)))
      (check "M4 a hole (counter 5) is not delivery"
             (not (upstream-delivered-from-zero-p rr 8))))
    ;; M5
    (mmp-receiver-reset-for-rekey r 2000)
    (mmp-receiver-record r 0 0 50 nil 2100)
    (let ((rr (mmp-receiver-build-report r 2200)))
      (check "M5 after reset: highest 0, reorder 0, cumulative KEPT (9 / 850)"
             (and (= (receiver-report-highest-counter rr) 0)
                  (= (receiver-report-cumulative-reorder-count rr) 0)
                  (= (receiver-report-cumulative-packets-recv rr) 9)
                  (= (receiver-report-cumulative-bytes-recv rr) 850)
                  (= (receiver-report-interval-packets-recv rr) 1))))))

;;; --- M6 / M7 ------------------------------------------------------------------------

(defun m6-metrics ()
  (let ((mmp (make-mmp-peer))
        (rr (make-receiver-report :highest-counter 4 :cumulative-packets-recv 5
                                  :cumulative-bytes-recv 500 :timestamp-echo 100 :dwell-time 5)))
    (check "M6 first report accepted"
           (eq (mmp-handle-report mmp (encode-receiver-report rr) 150) :accepted))
    (check "M6 RTT = 150 - (100 + 5) = 45 ms, SRTT initialised"
           (= (cl-fips::mm-srtt-us (mmp-metrics mmp)) 45000))
    (check "M6 the receiver interval re-tuned: 45 ms -> cold-start floor 200"
           (= (cl-fips::mr-interval-ms (mmp-receiver mmp)) 200))
    (check "M6 an identical report is stale"
           (eq (mmp-handle-report mmp (encode-receiver-report rr) 160) :stale))
    (setf (receiver-report-highest-counter rr) 3)
    (check "M6 a regressed highest counter is stale"
           (eq (mmp-handle-report mmp (encode-receiver-report rr) 170) :stale))
    (check "M6 a SenderReport is recorded"
           (and (eq (mmp-handle-report mmp (encode-sender-report (make-sender-report)) 0)
                    :sender-report)))))

(defun m7-sender ()
  (let ((s (make-mmp-sender)))
    (check "M7 no sends: nothing due" (null (mmp-sender-build-report s 0)))
    (mmp-sender-record s 10 1000 80)
    (mmp-sender-record s 11 1200 90)
    (let ((sr (mmp-sender-build-report s 1300)))
      (check "M7 interval 10..11, ts 1000..1200, 170 bytes; cumulative 2 / 170"
             (and (= (sender-report-interval-start-counter sr) 10)
                  (= (sender-report-interval-end-counter sr) 11)
                  (= (sender-report-interval-start-timestamp sr) 1000)
                  (= (sender-report-interval-end-timestamp sr) 1200)
                  (= (sender-report-interval-bytes-sent sr) 170)
                  (= (sender-report-cumulative-packets-sent sr) 2))))
    (mmp-sender-record s 12 1400 10)
    (check "M7 the next interval starts at the next send"
           (= (sender-report-interval-start-counter (mmp-sender-build-report s 1600)) 12))))

;;; --- S1 / S2: two stream links over an in-memory pipe ------------------------------

(defun make-pipe-port (inbox outbox &optional on-write)
  "A byte port reading INBOX and appending to OUTBOX (conses holding a vector).
   A read that cannot be satisfied answers :timeout.  ON-WRITE runs after each
   write (it lets the responder answer during the initiator's handshake)."
  (make-byte-port
   (lambda (n deadline)
     (declare (ignore deadline))
     (let ((have (car inbox)))
       (if (< (length have) n)
           (values (u8 0) :timeout)
           (progn (setf (car inbox) (subseq have n)) (values (subseq have 0 n) :ok)))))
   (lambda (octets)
     (setf (car outbox) (concatenate '(vector (unsigned-byte 8)) (car outbox) octets))
     (when on-write (funcall on-write))
     :ok)
   (lambda () nil)))

(defun u8 (n) (make-array n :element-type '(unsigned-byte 8)))

(defun make-stream-pair (&key a-config (a-reports t) (b-reports t))
  "A dials B over a pipe.  Returns (values a b a->b b->a)."
  (let* ((ka (generate-keypair)) (kb (generate-keypair))
         (ab (list (u8 0))) (ba (list (u8 0))) (b nil)
         (port-b (make-pipe-port ab ba))
         (port-a (make-pipe-port ba ab
                                 (lambda () (unless b
                                              (setf b (stream-link-accept port-b kb (random-epoch)
                                                                          :reports b-reports)))))))
    (let ((a (stream-link-initiate port-a ka (keypair-public-bytes kb) (random-epoch)
                                   :rekey-config a-config :reports a-reports)))
      (values a b ab ba))))

(defun drain (link inbox now)
  "Receive every packet waiting in INBOX for LINK; a list of (msg slot) for a
   frame, (nil event) for a rekey packet, (:error reason) for a drop."
  (loop while (plusp (length (car inbox)))
        collect (let ((r (handler-case (multiple-value-list (stream-link-receive link :now-ms now))
                           (link-error (e) (list :error (link-error-reason e))))))
                  (if (and (first r) (not (eq (first r) :error))) (list (first r) (fifth r)) r))))

(defun slots-of (got) (mapcar #'second got))

(defun s1-stream-rekey ()
  (multiple-value-bind (a b ab ba) (make-stream-pair
                                    :a-config (make-rekey-config :after-secs 40))
    (check "S1 handshake over the pipe" (and a b (= (stream-link-their-index a) (stream-link-our-index b))))
    ;; traffic before the rekey, with polls emitting reports both ways
    (loop for now from 1000 to 5000 by 1000
          do (stream-link-send a (msg "a") :now-ms now) (stream-link-send b (msg "b") :now-ms now)
             (stream-link-poll a :now-ms now) (stream-link-poll b :now-ms now)
             (drain a ba now) (drain b ab now))
    (check "S1 A accepted B's ReceiverReports about A's frames"
           (plusp (cl-fips::mm-reports-accepted (mmp-metrics (stream-link-mmp a)))))
    (check "S1 B accepted A's ReceiverReports"
           (plusp (cl-fips::mm-reports-accepted (mmp-metrics (stream-link-mmp b)))))
    (let ((old-a-idx (stream-link-our-index a)) (old-b-idx (stream-link-our-index b))
          (old-a-session (stream-link-session a)) (old-b-session (stream-link-session b)))
      (check "S1 39.9 s: no rekey yet" (null (stream-link-poll a :now-ms 39900)))
      (check "S1 40 s: A initiates (msg1 written on the stream)"
             (equal (stream-link-poll a :now-ms 40000) '(:initiate)))
      (check "S1 B answers the msg1 with a msg2"
             (member '(nil :rekey-answered) (drain b ab 40000) :test #'equal))
      (check "S1 A completes its side"
             (member '(nil :rekey-complete) (drain a ba 40000) :test #'equal))
      (check "S1 A's next poll cuts over" (equal (stream-link-poll a :now-ms 40100) '(:cutover)))
      (check "S1 A rotated: new session, new index, K = 1"
             (and (not (eq (stream-link-session a) old-a-session))
                  (/= (stream-link-our-index a) old-a-idx) (stream-link-k-bit a)))
      (stream-link-send a (msg "new") :now-ms 40200)
      (let ((got (drain b ab 40200)))
        (check "S1 B adopts on A's first new-epoch frame, and the frame is delivered"
               (and (eq (second (first got)) :adopted)
                    (member (msg "new") got :key #'first :test #'equalp)
                    (every (lambda (x) (member (second x) '(:adopted :current))) got))))
      (check "S1 B rotated too: new session, new index, K = 1"
             (and (not (eq (stream-link-session b) old-b-session))
                  (/= (stream-link-our-index b) old-b-idx) (stream-link-k-bit b)
                  (= (stream-link-their-index a) (stream-link-our-index b))
                  (= (stream-link-their-index b) (stream-link-our-index a))))
      (check "S1 B's receiver restarted on the new session's counters, cumulative kept"
             (let ((r (mmp-receiver (stream-link-mmp b))))
               (and (< (cl-fips::mr-highest r) 3) (> (cl-fips::mr-cum-packets r) 5)
                    (= (cl-fips::mr-cum-reorder r) 0))))
      (stream-link-send b (msg "reply") :now-ms 40300)
      (check "S1 A opens B's new-epoch reply on its current session"
             (equal (slots-of (drain a ba 40300)) '(:current)))
      (loop for now from 41000 to 45000 by 1000
            do (stream-link-send a (msg "a") :now-ms now) (stream-link-send b (msg "b") :now-ms now)
               (stream-link-poll a :now-ms now) (stream-link-poll b :now-ms now)
               (check "S1 after the rekey, frames keep flowing both ways"
                      (and (member :current (slots-of (drain a ba now)))
                           (member :current (slots-of (drain b ab now))))))
      (check "S1 the drain ends 10 s after the cutover"
             (equal (stream-link-poll a :now-ms 50100) '(:drain))))))

(defun s2-reports-off ()
  (multiple-value-bind (a b ab ba) (make-stream-pair :a-reports nil :b-reports :no-rr)
    (stream-link-send b (msg "b") :now-ms 100)
    (drain a ba 100)
    (check "S2 control: a received a frame (a report would be due)"
           (mmp-receiver-due-p (mmp-receiver (stream-link-mmp a)) 200))
    (check "S2 reports off: the poll emits nothing" (null (nth-value 1 (stream-link-poll a :now-ms 200))))
    (stream-link-send a (msg "a") :now-ms 300)
    (stream-link-send b (msg "b") :now-ms 300)
    (drain b ab 300)
    (check "S2 :no-rr emits a SenderReport and no ReceiverReport"
           (equal (nth-value 1 (stream-link-poll b :now-ms 400)) (list +msg-type-sender-report+)))
    (check "S2 control: the default emits both"
           (multiple-value-bind (c d cd dc) (make-stream-pair)
             (declare (ignore cd))
             (stream-link-send d (msg "d") :now-ms 100)
             (stream-link-send c (msg "c") :now-ms 100)
             (drain c dc 100)
             (equal (nth-value 1 (stream-link-poll c :now-ms 200)) '(1 2))))))

(defun test-mmp ()
  (m1-sender-report)
  (m2-receiver-report)
  (m3-negative-controls)
  (m4-receiver)
  (m6-metrics)
  (m7-sender)
  (s1-stream-rekey)
  (s2-reports-off))
