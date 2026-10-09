;;;; mmp.lisp -- MMP (metrics measurement protocol) link reports, pure.
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510, the CODE:
;;;;   src/proto/mmp/wire.rs      SenderReport layout (lines 18-29), encode
;;;;                              (83-95), decode (100-114); ReceiverReport
;;;;                              layout (43-62), encode (118-139), decode (144-169)
;;;;   src/proto/mmp/receiver.rs  GapTracker (30-131), ReceiverState::record_recv
;;;;                              (255-317), build_report (323-369),
;;;;                              should_send_report (372-380), the SRTT interval
;;;;                              (388-408), reset_for_rekey (228-244)
;;;;   src/proto/mmp/sender.rs    record_sent (76), build_report (93),
;;;;                              should_send_report (120), interval (167-190)
;;;;   src/proto/mmp/algorithms.rs JitterEstimator (RFC 3550, x16), SrttEstimator
;;;;                              (RFC 6298), OwdTrendDetector (linear regression)
;;;;   src/proto/mmp/metrics.rs   process_receiver_report (170-260): the stale /
;;;;                              duplicate drop and the RTT sample
;;;;   src/proto/mmp/limits.rs    cold start 200 ms (18), floor 1000 (26),
;;;;                              ceiling 5000 (29), 5 cold-start samples (36),
;;;;                              OWD window 32 (39)
;;;;   src/node/dataplane/encrypted.rs  record_recv only for frames on the CURRENT
;;;;                              slot (339-349; an adopted pending frame is
;;;;                              delivered as Current, 190-193); bytes = the
;;;;                              whole wire packet
;;;;   src/node/mod.rs            sender.record_sent(counter, ts, wire bytes)
;;;;                              (4061, 4112)
;;;;   src/peer/active.rs         mmp.reset_for_rekey at the initiator cutover
;;;;                              (1401) and at the responder's promotion (1447)
;;;;
;;;; Wire, as LINK MESSAGES (the msg_type byte included):
;;;;   SenderReport, 48 bytes
;;;;     [0] 0x01  [1-3] reserved 0  [4-11] interval_start_counter u64
;;;;     [12-19] interval_end_counter u64  [20-23] interval_start_timestamp u32
;;;;     [24-27] interval_end_timestamp u32  [28-31] interval_bytes_sent u32
;;;;     [32-39] cumulative_packets_sent u64  [40-47] cumulative_bytes_sent u64
;;;;   ReceiverReport, 68 bytes
;;;;     [0] 0x02  [1-3] reserved 0  [4-11] highest_counter u64
;;;;     [12-19] cumulative_packets_recv u64  [20-27] cumulative_bytes_recv u64
;;;;     [28-31] timestamp_echo u32  [32-33] dwell_time u16
;;;;     [34-35] max_burst_loss u16  [36-37] mean_burst_loss u16 (u8.8)
;;;;     [38-39] reserved  [40-43] jitter u32 (us)  [44-47] ecn_ce_count u32
;;;;     [48-51] owd_trend i32 (us/s)  [52-55] burst_loss_count u32
;;;;     [56-59] cumulative_reorder_count u32  [60-63] interval_packets_recv u32
;;;;     [64-67] interval_bytes_recv u32
;;;;   All little-endian.
;;;;
;;;; WHY THE NODE NEEDS OUR RECEIVER REPORTS (proto/mmp/delivery.rs): a
;;;; TreeAnnounce or FilterAnnounce is held as outstanding until the peer's
;;;; ReceiverReports show every link counter from a base up to the announce's own
;;;; arrived.  With no report yet in the first session the base is ZERO, and
;;;; delivery is concluded when highest_counter >= the announce's counter and
;;;; cumulative_packets_recv - cumulative_reorder_count = highest_counter + 1
;;;; (delivered(), 226-246); a report with highest_counter >= the node's next
;;;; send counter is ignored (usable_rr, 88-90).  No usable report within 30 s
;;;; (FALLBACK_MS) is the "Resending unconfirmed ..." the node logs.  So the three
;;;; fields that matter are highest_counter, cumulative_packets_recv and
;;;; cumulative_reorder_count, counted over every frame that authenticates on the
;;;; current session -- whatever its msg_type.
;;;;
;;;; DECODE IS STRICTER THAN UPSTREAM.  wire.rs decode() uses Reader::require(47 /
;;;; 67), a LOWER bound, so upstream accepts trailing bytes.  Upstream's encode
;;;; never produces them, so here a body of any length but the exact one is
;;;; rejected (NIL).  Reserved bytes are skipped unchecked, as upstream does.
;;;;
;;;; Pure: no clock is read; every entry point takes NOW-MS.  Floats only where
;;;; upstream uses f64 (the mean burst and the OWD regression).

(in-package #:cl-fips)

(defconstant +msg-type-sender-report+ #x01)
(defconstant +msg-type-receiver-report+ #x02)
(defconstant +sender-report-size+ 48 "wire.rs: 48 bytes including msg_type.")
(defconstant +receiver-report-size+ 68 "wire.rs: 68 bytes including msg_type.")
(defconstant +mmp-cold-start-interval-ms+ 200 "limits.rs DEFAULT_COLD_START_INTERVAL_MS.")
(defconstant +mmp-min-report-interval-ms+ 1000 "limits.rs MIN_REPORT_INTERVAL_MS.")
(defconstant +mmp-max-report-interval-ms+ 5000 "limits.rs MAX_REPORT_INTERVAL_MS.")
(defconstant +mmp-cold-start-samples+ 5 "limits.rs COLD_START_SAMPLES.")
(defconstant +mmp-owd-window+ 32 "limits.rs DEFAULT_OWD_WINDOW_SIZE.")
(defconstant +rekey-jitter-grace-ms+ 15000 "receiver.rs REKEY_JITTER_GRACE_SECS = 15.")

;;; --- Integer casts, as Rust spells them --------------------------------------------

(defun %sat (v bits) (min v (1- (ash 1 bits))))                 ; saturating_add result
(defun %wrap-signed (v bits)                                      ; `as iN` from a wider int
  (let ((u (ldb (byte bits 0) v)))
    (if (logbitp (1- bits) u) (- u (ash 1 bits)) u)))
(defun %f64-as-int (x lo hi)                                      ; `f64 as iN/uN`: trunc, saturate
  (max lo (min hi (truncate x))))

;;; --- The reports and their codecs ---------------------------------------------------

(defstruct sender-report
  (interval-start-counter 0) (interval-end-counter 0)
  (interval-start-timestamp 0) (interval-end-timestamp 0) (interval-bytes-sent 0)
  (cumulative-packets-sent 0) (cumulative-bytes-sent 0))

(defstruct receiver-report
  (highest-counter 0) (cumulative-packets-recv 0) (cumulative-bytes-recv 0)
  (timestamp-echo 0) (dwell-time 0) (max-burst-loss 0) (mean-burst-loss 0)
  (jitter 0) (ecn-ce-count 0) (owd-trend 0) (burst-loss-count 0)
  (cumulative-reorder-count 0) (interval-packets-recv 0) (interval-bytes-recv 0))

(defun %put (out offset value nbytes)
  (replace out (encode-uint-le (ldb (byte (* 8 nbytes) 0) value) nbytes) :start1 offset))

(defun encode-sender-report (sr)
  "wire.rs SenderReport::encode: the 48-byte link message (msg_type 0x01 first)."
  (let ((out (u8-vector +sender-report-size+)))
    (setf (aref out 0) +msg-type-sender-report+)
    (%put out 4 (sender-report-interval-start-counter sr) 8)
    (%put out 12 (sender-report-interval-end-counter sr) 8)
    (%put out 20 (sender-report-interval-start-timestamp sr) 4)
    (%put out 24 (sender-report-interval-end-timestamp sr) 4)
    (%put out 28 (sender-report-interval-bytes-sent sr) 4)
    (%put out 32 (sender-report-cumulative-packets-sent sr) 8)
    (%put out 40 (sender-report-cumulative-bytes-sent sr) 8)
    out))

(defun decode-sender-report (link-message)
  "LINK-MESSAGE starts at msg_type.  A SENDER-REPORT, or NIL for a wrong
   msg_type or any length but 48."
  (when (and (= (length link-message) +sender-report-size+)
             (= (aref link-message 0) +msg-type-sender-report+))
    (make-sender-report
     :interval-start-counter (decode-u64le link-message 4)
     :interval-end-counter (decode-u64le link-message 12)
     :interval-start-timestamp (decode-u32le link-message 20)
     :interval-end-timestamp (decode-u32le link-message 24)
     :interval-bytes-sent (decode-u32le link-message 28)
     :cumulative-packets-sent (decode-u64le link-message 32)
     :cumulative-bytes-sent (decode-u64le link-message 40))))

(defun encode-receiver-report (rr)
  "wire.rs ReceiverReport::encode: the 68-byte link message (msg_type 0x02 first)."
  (let ((out (u8-vector +receiver-report-size+)))
    (setf (aref out 0) +msg-type-receiver-report+)
    (%put out 4 (receiver-report-highest-counter rr) 8)
    (%put out 12 (receiver-report-cumulative-packets-recv rr) 8)
    (%put out 20 (receiver-report-cumulative-bytes-recv rr) 8)
    (%put out 28 (receiver-report-timestamp-echo rr) 4)
    (%put out 32 (receiver-report-dwell-time rr) 2)
    (%put out 34 (receiver-report-max-burst-loss rr) 2)
    (%put out 36 (receiver-report-mean-burst-loss rr) 2)
    (%put out 40 (receiver-report-jitter rr) 4)
    (%put out 44 (receiver-report-ecn-ce-count rr) 4)
    (%put out 48 (receiver-report-owd-trend rr) 4)            ; i32, two's complement
    (%put out 52 (receiver-report-burst-loss-count rr) 4)
    (%put out 56 (receiver-report-cumulative-reorder-count rr) 4)
    (%put out 60 (receiver-report-interval-packets-recv rr) 4)
    (%put out 64 (receiver-report-interval-bytes-recv rr) 4)
    out))

(defun decode-receiver-report (link-message)
  "LINK-MESSAGE starts at msg_type.  A RECEIVER-REPORT, or NIL for a wrong
   msg_type or any length but 68."
  (when (and (= (length link-message) +receiver-report-size+)
             (= (aref link-message 0) +msg-type-receiver-report+))
    (make-receiver-report
     :highest-counter (decode-u64le link-message 4)
     :cumulative-packets-recv (decode-u64le link-message 12)
     :cumulative-bytes-recv (decode-u64le link-message 20)
     :timestamp-echo (decode-u32le link-message 28)
     :dwell-time (decode-u16le link-message 32)
     :max-burst-loss (decode-u16le link-message 34)
     :mean-burst-loss (decode-u16le link-message 36)
     :jitter (decode-u32le link-message 40)
     :ecn-ce-count (decode-u32le link-message 44)
     :owd-trend (%wrap-signed (decode-u32le link-message 48) 32)
     :burst-loss-count (decode-u32le link-message 52)
     :cumulative-reorder-count (decode-u32le link-message 56)
     :interval-packets-recv (decode-u32le link-message 60)
     :interval-bytes-recv (decode-u32le link-message 64))))

;;; --- The report interval (receiver.rs 388-408, sender.rs 167-190) -------------------

(defun %srtt-interval (srtt-us samples multiplier)
  "Interval in ms from SRTT: MULTIPLIER x SRTT (1 for receiver, 2 for sender),
   clamped to [floor, 5000]; the floor is 200 ms for the first 5 samples."
  (let ((floor (if (<= samples +mmp-cold-start-samples+)
                   +mmp-cold-start-interval-ms+ +mmp-min-report-interval-ms+)))
    (max floor (min +mmp-max-report-interval-ms+ (floor (* srtt-us multiplier) 1000)))))

;;; --- Receiver side (receiver.rs ReceiverState, GapTracker) --------------------------

(defstruct (mmp-receiver (:conc-name mr-))
  (cum-packets 0) (cum-bytes 0) (cum-reorder 0) (highest 0)
  (interval-packets 0) (interval-bytes 0)
  (jitter-q4 0) (owd-samples '()) (owd-seq 0)
  ;; gap tracker
  (expected-next nil) (in-burst nil) (burst-len 0)
  (burst-count 0) (max-burst 0) (total-burst 0)
  (ecn-ce 0) (last-sender-ts 0) (last-recv-ms nil) (grace-until nil)
  (last-report-ms nil) (interval-ms +mmp-cold-start-interval-ms+) (has-data nil)
  (srtt-samples 0))

(defun %gap-finish (r)
  (when (mr-in-burst r)
    (setf (mr-max-burst r) (max (mr-max-burst r) (mr-burst-len r)))
    (incf (mr-total-burst r) (mr-burst-len r))
    (setf (mr-in-burst r) nil (mr-burst-len r) 0)))

(defun %gap-observe (r counter)
  "GapTracker::observe."
  (let ((expected (mr-expected-next r)))
    (cond ((null expected) (setf (mr-expected-next r) (1+ counter)))
          (t (if (> counter expected)
                 (let ((gap (ldb (byte 16 0) (- counter expected))))   ; `gap as u16`
                   (if (mr-in-burst r)
                       (setf (mr-burst-len r) (%sat (+ (mr-burst-len r) gap) 16))
                       (setf (mr-in-burst r) t (mr-burst-len r) gap
                             (mr-burst-count r) (1+ (mr-burst-count r)))))
                 (%gap-finish r))
             (when (>= counter expected) (setf (mr-expected-next r) (1+ counter)))))))

(defun %owd-trend (samples)
  "OwdTrendDetector::trend_us_per_sec over SAMPLES ((seq . owd-us) ...)."
  (let ((n (length samples)))
    (if (< n 2)
        0
        (let* ((mx (/ (reduce #'+ samples :key (lambda (s) (float (car s) 1d0))) n))
               (my (/ (reduce #'+ samples :key (lambda (s) (float (cdr s) 1d0))) n))
               (num 0d0) (den 0d0))
          (dolist (s samples)
            (let ((dx (- (car s) mx)) (dy (- (cdr s) my)))
              (incf num (* dx dy)) (incf den (* dx dx))))
          (if (< den double-float-epsilon)
              0
              (%f64-as-int (* (/ num den) 1000d0) (- (ash 1 31)) (1- (ash 1 31))))))))

(defun mmp-receiver-record (r counter sender-ts bytes ce now-ms)
  "ReceiverState::record_recv: one authenticated frame on the current session.
   BYTES is the whole wire packet; SENDER-TS the inner timestamp."
  (setf (mr-has-data r) t)
  (incf (mr-cum-packets r)) (incf (mr-cum-bytes r) bytes)
  (setf (mr-interval-packets r) (%sat (1+ (mr-interval-packets r)) 32)
        (mr-interval-bytes r) (%sat (+ (mr-interval-bytes r) bytes) 32))
  (if (< counter (mr-highest r))
      (incf (mr-cum-reorder r))
      (setf (mr-highest r) counter))
  (%gap-observe r counter)
  (when ce (setf (mr-ecn-ce r) (%sat (1+ (mr-ecn-ce r)) 32)))
  (let ((sender-us (* sender-ts 1000)))
    (unless (and (mr-grace-until r) (< now-ms (mr-grace-until r)))
      (setf (mr-grace-until r) nil)
      (when (mr-last-recv-ms r)
        (let* ((recv-delta-us (* 1000 (max 0 (- now-ms (mr-last-recv-ms r)))))
               (send-delta-us (- sender-us (* 1000 (mr-last-sender-ts r))))
               (d (%wrap-signed (- recv-delta-us send-delta-us) 32)))
          ;; J_q4 += |D| - J_q4 >> 4
          (incf (mr-jitter-q4 r) (- (abs d) (ash (mr-jitter-q4 r) -4))))))
    ;; OWD: upstream's reference is the PREVIOUS receive time (or now)
    (let* ((first (or (mr-last-recv-ms r) now-ms))
           (owd (- (* 1000 (max 0 (- now-ms first))) sender-us)))
      (setf (mr-owd-seq r) (ldb (byte 32 0) (1+ (mr-owd-seq r))))
      (setf (mr-owd-samples r)
            (let ((s (append (mr-owd-samples r) (list (cons (mr-owd-seq r) owd)))))
              (if (> (length s) +mmp-owd-window+) (rest s) s)))))
  (setf (mr-last-sender-ts r) sender-ts (mr-last-recv-ms r) now-ms)
  r)

(defun mmp-receiver-due-p (r now-ms)
  "ReceiverState::should_send_report."
  (and (mr-has-data r)
       (or (null (mr-last-report-ms r))
           (>= (- now-ms (mr-last-report-ms r)) (mr-interval-ms r)))))

(defun mmp-receiver-build-report (r now-ms)
  "ReceiverState::build_report: a RECEIVER-REPORT and the interval reset, or NIL
   when nothing arrived since the last report."
  (when (mr-has-data r)
    (multiple-value-bind (echo dwell)
        (if (mr-last-recv-ms r)
            (let ((d (max 0 (- now-ms (mr-last-recv-ms r)))))
              (if (> d #xffff) (values 0 #xffff) (values (mr-last-sender-ts r) d)))
            (values 0 0))
      (%gap-finish r)
      (let* ((count (mr-burst-count r))
             (mean (if (plusp count)
                       (%f64-as-int (* 256d0 (/ (float (mr-total-burst r) 1d0) count)) 0 #xffff)
                       0))
             (rr (make-receiver-report
                  :highest-counter (mr-highest r)
                  :cumulative-packets-recv (mr-cum-packets r)
                  :cumulative-bytes-recv (mr-cum-bytes r)
                  :timestamp-echo echo :dwell-time dwell
                  :max-burst-loss (mr-max-burst r) :mean-burst-loss mean
                  :jitter (ldb (byte 32 0) (ash (mr-jitter-q4 r) -4))
                  :ecn-ce-count (mr-ecn-ce r)
                  :owd-trend (%owd-trend (mr-owd-samples r))
                  :burst-loss-count count
                  :cumulative-reorder-count (ldb (byte 32 0) (mr-cum-reorder r))
                  :interval-packets-recv (mr-interval-packets r)
                  :interval-bytes-recv (mr-interval-bytes r))))
        (setf (mr-burst-count r) 0 (mr-max-burst r) 0 (mr-total-burst r) 0
              (mr-interval-packets r) 0 (mr-interval-bytes r) 0
              (mr-has-data r) nil (mr-last-report-ms r) now-ms)
        rr))))

(defun mmp-receiver-reset-for-rekey (r now-ms)
  "ReceiverState::reset_for_rekey: the new session's counters start at 0.
   Cumulative packets/bytes and the report schedule are KEPT."
  (setf (mr-highest r) 0 (mr-cum-reorder r) 0
        (mr-expected-next r) nil (mr-in-burst r) nil (mr-burst-len r) 0
        (mr-burst-count r) 0 (mr-max-burst r) 0 (mr-total-burst r) 0
        (mr-interval-packets r) 0 (mr-interval-bytes r) 0
        (mr-jitter-q4 r) 0 (mr-owd-samples r) '() (mr-owd-seq r) 0
        (mr-last-sender-ts r) 0 (mr-last-recv-ms r) nil
        (mr-grace-until r) (+ now-ms +rekey-jitter-grace-ms+)
        (mr-ecn-ce r) 0 (mr-has-data r) nil)
  r)

;;; --- Sender side (sender.rs SenderState) --------------------------------------------

(defstruct (mmp-sender (:conc-name ms-))
  (cum-packets 0) (cum-bytes 0)
  (start-counter 0) (start-ts 0) (interval-bytes 0) (last-counter 0) (last-ts 0)
  (has-data nil) (last-report-ms nil) (interval-ms +mmp-cold-start-interval-ms+)
  (srtt-samples 0))

(defun mmp-sender-record (s counter timestamp bytes)
  "SenderState::record_sent."
  (unless (ms-has-data s)
    (setf (ms-start-counter s) counter (ms-start-ts s) timestamp (ms-has-data s) t))
  (setf (ms-last-counter s) counter (ms-last-ts s) timestamp
        (ms-interval-bytes s) (%sat (+ (ms-interval-bytes s) bytes) 32))
  (incf (ms-cum-packets s)) (incf (ms-cum-bytes s) bytes)
  s)

(defun mmp-sender-due-p (s now-ms)
  (and (ms-has-data s)
       (or (null (ms-last-report-ms s))
           (>= (- now-ms (ms-last-report-ms s)) (ms-interval-ms s)))))

(defun mmp-sender-build-report (s now-ms)
  (when (ms-has-data s)
    (prog1 (make-sender-report
            :interval-start-counter (ms-start-counter s) :interval-end-counter (ms-last-counter s)
            :interval-start-timestamp (ms-start-ts s) :interval-end-timestamp (ms-last-ts s)
            :interval-bytes-sent (ms-interval-bytes s)
            :cumulative-packets-sent (ms-cum-packets s) :cumulative-bytes-sent (ms-cum-bytes s))
      (setf (ms-has-data s) nil (ms-interval-bytes s) 0 (ms-last-report-ms s) now-ms))))

;;; --- What the peer reports about us (metrics.rs, the part we use) -------------------

(defstruct (mmp-metrics (:conc-name mm-))
  (has-prev nil) (prev-highest 0) (prev-packets 0) (prev-bytes 0) (prev-ecn 0) (prev-reorder 0)
  (srtt-us 0) (rttvar-us 0) (srtt-init nil)
  (reports-seen 0) (reports-accepted 0) (rtt-samples 0)
  (last-sr nil))

(defun %srtt-update (m rtt-us)
  (if (not (mm-srtt-init m))
      (setf (mm-srtt-us m) rtt-us (mm-rttvar-us m) (floor rtt-us 2) (mm-srtt-init m) t)
      (let ((err (abs (- (mm-srtt-us m) rtt-us))))
        (setf (mm-rttvar-us m) (+ (- (mm-rttvar-us m) (ash (mm-rttvar-us m) -2)) (ash err -2))
              (mm-srtt-us m) (+ (- (mm-srtt-us m) (ash (mm-srtt-us m) -3)) (ash rtt-us -3))))))

(defun mmp-metrics-process-rr (m rr our-timestamp-ms)
  "MmpMetrics::process_receiver_report, the stale gate and the RTT sample.
   Returns :stale (counters regressed or unchanged; dropped) or :accepted, and
   as a second value the RTT sample in ms, if any."
  (incf (mm-reports-seen m))
  (let ((h (receiver-report-highest-counter rr)) (p (receiver-report-cumulative-packets-recv rr))
        (b (receiver-report-cumulative-bytes-recv rr)) (e (receiver-report-ecn-ce-count rr))
        (o (receiver-report-cumulative-reorder-count rr)))
    (when (and (mm-has-prev m)
               (or (< h (mm-prev-highest m)) (< p (mm-prev-packets m)) (< b (mm-prev-bytes m))
                   (< e (mm-prev-ecn m)) (< o (mm-prev-reorder m))
                   (and (= h (mm-prev-highest m)) (= p (mm-prev-packets m)) (= b (mm-prev-bytes m))
                        (= e (mm-prev-ecn m)) (= o (mm-prev-reorder m)))))
      (return-from mmp-metrics-process-rr (values :stale nil)))
    (let ((rtt nil))
      (when (plusp (receiver-report-timestamp-echo rr))
        (let ((done (+ (receiver-report-timestamp-echo rr) (receiver-report-dwell-time rr))))
          (when (and (< done (ash 1 32)) (>= our-timestamp-ms done)
                     (plusp (- our-timestamp-ms done)))
            (setf rtt (- our-timestamp-ms done))
            (incf (mm-rtt-samples m))
            (%srtt-update m (* rtt 1000)))))
      (setf (mm-has-prev m) t (mm-prev-highest m) h (mm-prev-packets m) p (mm-prev-bytes m) b
            (mm-prev-ecn m) e (mm-prev-reorder m) o)
      (incf (mm-reports-accepted m))
      (values :accepted rtt))))

(defun mmp-metrics-reset-for-rekey (m)
  "MmpMetrics::reset_for_rekey: forget the prev-report counters, keep SRTT."
  (setf (mm-has-prev m) nil (mm-prev-highest m) 0 (mm-prev-packets m) 0 (mm-prev-bytes m) 0
        (mm-prev-ecn m) 0 (mm-prev-reorder m) 0)
  m)

;;; --- One peer's MMP state (state.rs MmpPeerState, mode Full) -----------------------

(defstruct (mmp-peer (:conc-name mmp-))
  (receiver (make-mmp-receiver)) (sender (make-mmp-sender)) (metrics (make-mmp-metrics))
  (send-rr t) (send-sr t))

(defun mmp-reset-for-rekey (mmp now-ms)
  (mmp-receiver-reset-for-rekey (mmp-receiver mmp) now-ms)
  (mmp-metrics-reset-for-rekey (mmp-metrics mmp))
  mmp)

(defun mmp-handle-report (mmp link-message our-timestamp-ms)
  "Dispatch an incoming 0x01/0x02 link message.  Returns :sender-report,
   :accepted, :stale, :malformed, or NIL for any other msg_type.  Once an RTT
   sample exists every ReceiverReport re-tunes both report intervals from SRTT,
   as handle_receiver_report (node/handlers/mmp.rs 219-224) does."
  (case (and (plusp (length link-message)) (aref link-message 0))
    (#.+msg-type-sender-report+
     (let ((sr (decode-sender-report link-message)))
       (if sr (progn (setf (mm-last-sr (mmp-metrics mmp)) sr) :sender-report) :malformed)))
    (#.+msg-type-receiver-report+
     (let ((rr (decode-receiver-report link-message)))
       (if (null rr)
           :malformed
           (let ((m (mmp-metrics mmp)))
             (multiple-value-bind (status) (mmp-metrics-process-rr m rr our-timestamp-ms)
               ;; handle_receiver_report re-tunes after EVERY report once SRTT
               ;; exists, a stale one included (srtt_us <= 0 is a no-op there)
               (when (and (mm-srtt-init m) (plusp (mm-srtt-us m)))
                 (let ((r (mmp-receiver mmp)) (s (mmp-sender mmp)))
                   (incf (mr-srtt-samples r)) (incf (ms-srtt-samples s))
                   (setf (mr-interval-ms r) (%srtt-interval (mm-srtt-us m) (mr-srtt-samples r) 1)
                         (ms-interval-ms s) (%srtt-interval (mm-srtt-us m) (ms-srtt-samples s) 2))))
               status)))))
    (t nil)))

(defun mmp-due-reports (mmp now-ms)
  "plan_link_reports for this peer (mode Full): the link messages to send now,
   SenderReport first, then ReceiverReport.  Builds them (resetting intervals)."
  (let ((out '()))
    (when (and (mmp-send-sr mmp) (mmp-sender-due-p (mmp-sender mmp) now-ms))
      (let ((sr (mmp-sender-build-report (mmp-sender mmp) now-ms)))
        (when sr (push (encode-sender-report sr) out))))
    (when (and (mmp-send-rr mmp) (mmp-receiver-due-p (mmp-receiver mmp) now-ms))
      (let ((rr (mmp-receiver-build-report (mmp-receiver mmp) now-ms)))
        (when rr (push (encode-receiver-report rr) out))))
    (nreverse out)))
