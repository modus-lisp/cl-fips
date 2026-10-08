;;;; rekey-test.lisp -- the FMP link rekey state machine (src/rekey.lisp).
;;;;
;;;; Deterministic: every step names its time in ms; indices come from counters.
;;;;
;;;;   K1  rekey by MESSAGE COUNT, Lisp <-> Lisp: new keys and indices after
;;;;       cutover, counter restarts at 0, the responder stays on the old session
;;;;       until a frame authenticates on the new one, late frames decrypt on the
;;;;       previous session inside the 10 s drain and are refused after it
;;;;   K2  rekey by TIME (120 s, jitter 0): the boundary, dampening, timers reset
;;;;   K3  the K-bit rule: the trial on a flipped bit, no trial without one, a bare
;;;;       flip never promotes, and the bit TOGGLES (second rekey sends K=0)
;;;;   K4  a responder's unadopted pending is retired at the 120 s hold
;;;;   K5  the dual-initiation race: the smaller NodeAddr stays initiator, both
;;;;       delivery orders
;;;;   O1  upstream (oracle verify-rekey) initiates, Lisp responds
;;;;   O2  Lisp initiates, upstream responds
;;;;   O3  both initiate at once: upstream's cross_connection_winner and Lisp's
;;;;       tie-break must pick the same initiator
;;;;   breaks  the K-bit toggle, the K-bit trial, the drain window and the
;;;;       tie-break, each broken in memory: the matching checks must FAIL

(in-package #:cl-fips.test)

(defun msg (string) (concatenate '(vector (unsigned-byte 8)) (bytes #x10) (ascii string)))

(defun counter-allocator (start)
  (let ((n start)) (lambda () (incf n))))

(defun frame-k (wire) (logbitp 0 (aref wire 1)))
(defun frame-idx (wire) (decode-u32le wire 4))
(defun frame-counter (wire) (decode-u64le wire 8))

(defun make-link-pair (&key (config (make-rekey-config)) (now 0))
  "Two Lisp peers over a fresh IK link: A dialled B.  Returns (values a b)."
  (let* ((ka (generate-keypair)) (kb (generate-keypair))
         (ea (random-epoch)) (eb (random-epoch))
         (i (fips-make-ik-initiator ka (keypair-public-bytes kb) ea))
         (r (fips-make-ik-responder kb eb)))
    (ik-read-message-1 r (ik-write-message-1 i))
    (ik-read-message-2 i (ik-write-message-2 r))
    (values (make-link (handshake-into-session i) 1001 2001
                       :static ka :peer-static-bytes (keypair-public-bytes kb)
                       :local-epoch ea :remote-epoch eb :now-ms now :config config
                       :allocate-index (counter-allocator 1100))
            (make-link (handshake-into-session r) 2001 1001
                       :static kb :peer-static-bytes (keypair-public-bytes ka)
                       :local-epoch eb :remote-epoch ea :now-ms now :config config
                       :allocate-index (counter-allocator 2100)))))

(defun recv (link wire now) (multiple-value-list (link-receive link wire now)))

(defun opened (result slot text)
  (and (eq (first result) :frame) (equalp (second result) (msg text)) (eq (third result) slot)))

(defun run-rekey (initiator responder now)
  "Drive one handshake the initiator has already started: returns T when the
   initiator holds the completed session as pending."
  (multiple-value-bind (packets) (link-tick initiator now)
    (and packets
         (destructuring-bind (kind msg2) (recv responder (first packets) now)
           (and (eq kind :msg2)
                (eq (first (recv initiator msg2 now)) :rekey-complete))))))

;;; --- K1: count-triggered --------------------------------------------------------

(defun k1-count-rekey ()
  (multiple-value-bind (a b) (make-link-pair :config (make-rekey-config :after-messages 5))
    (let ((old-a (link-session a)) (old-b (link-session b)) (late-a '()) (late-b '())
          (held-a '()))
      ;; 4 frames: below the threshold
      (dotimes (k 4) (check "K1 old session A->B" (opened (recv b (link-send a (msg "x") 1000) 1000)
                                                          :current "x")))
      (check "K1 four sent frames do not trigger" (null (rekey-decide (link-snapshot a 40000)
                                                                      (link-config a))))
      (push (link-send a (msg "late-a-1") 2000) late-a)
      (check "K1 the fifth sent frame triggers (counter >= after_messages)"
             (equal (rekey-decide (link-snapshot a 40000) (link-config a)) '(:initiate)))
      (dotimes (k 3) (push (link-send b (msg "late-b") 3000) late-b))
      ;; two old-epoch frames from A that B will only see after it has moved
      (dotimes (k 2) (push (link-send a (msg "held-a") 3000) held-a))
      (push (link-send a (msg "late-a-2") 3000) late-a)
      (multiple-value-bind (packets actions) (link-tick a 40000)
        (check "K1 tick initiates and emits one msg1" (and (equal actions '(:initiate))
                                                           (= (length packets) 1)))
        (let ((m1 (first packets)))
          (check "K1 the rekey msg1 is a CLEARTEXT phase-0x1 packet of 114 bytes with a new index"
                 (and (= (length m1) 114) (= (aref m1 0) 1) (= (aref m1 1) 0)
                      (= (decode-u32le m1 4) 1101)))
          (destructuring-bind (kind m2) (recv b m1 40000)
            (check "K1 responder answers with a 69-byte phase-0x2 msg2 naming both new indices"
                   (and (eq kind :msg2) (= (length m2) 69) (= (aref m2 0) 2)
                        (= (decode-u32le m2 4) 2101) (= (decode-u32le m2 8) 1101)))
            (check "K1 responder holds the new session as pending and stays on the old one"
                   (and (eq (link-pending-role b) :responder) (eq (link-session b) old-b)
                        (null (link-k-bit b))))
            (check "K1 a resent msg1 draws the same msg2" (equalp (second (recv b m1 40500)) m2))
            (check "K1 initiator completes msg2 into a pending session"
                   (eq (first (recv a m2 41000)) :rekey-complete))
            (check "K1 until its tick the initiator still sends on the old session, K=0"
                   (let ((f (link-send a (msg "pre") 41000)))
                     (and (not (frame-k f)) (= (frame-idx f) 2001)
                          (opened (recv b f 41000) :current "pre"))))
            (check "K1 the tick cuts over" (equal (nth-value 1 (link-tick a 42000)) '(:cutover)))
            (check "K1 initiator: new session current, old one previous, K flipped"
                   (and (eq (link-previous-session a) old-a) (not (eq (link-session a) old-a))
                        (link-k-bit a) (= (link-our-index a) 1101) (= (link-their-index a) 2101)))
            ;; the responder sees only old-session frames for a while: it stays put
            (dolist (f late-a)
              (check "K1 responder without the new-epoch frame: old frames open on CURRENT"
                     (eq (third (recv b f 43000)) :current)))
            (check "K1 ... and the responder is still on the old session, pending held, K=0"
                   (and (eq (link-session b) old-b) (link-pending-session b) (null (link-k-bit b))))
            (check "K1 ... its own ticks do not cut over a pending it answered"
                   (and (null (nth-value 1 (link-tick b 43500))) (eq (link-session b) old-b)))
            (let ((f (link-send a (msg "new-epoch") 44000)))
              (check "K1 first new-epoch frame: K set, to the responder's NEW index, counter 0"
                     (and (frame-k f) (= (frame-idx f) 2101) (= (frame-counter f) 0)))
              (check "K1 the old session cannot open it"
                     (rejects-p (lambda () (fmp-open-frame old-b f))))
              (check "K1 the responder adopts on it" (opened (recv b f 44000) :adopted "new-epoch"))
              (check "K1 responder now current = new, previous = old, K = the frame's"
                     (and (eq (link-previous-session b) old-b) (link-k-bit b)
                          (null (link-pending-session b)) (= (link-our-index b) 2101))))
            (let ((f (link-send b (msg "reply") 44000)))
              (check "K1 responder's reply: K set, to the initiator's new index, counter 0"
                     (and (frame-k f) (= (frame-idx f) 1101) (= (frame-counter f) 0)))
              (check "K1 initiator opens it on the new session" (opened (recv a f 44000) :current "reply")))
            ;; drain: A cut over at 42000, B adopted at 44000
            (check "K1 a late old-epoch frame opens on PREVIOUS inside the drain (A, +9.9 s)"
                   (and (null (nth-value 1 (link-tick a 51999)))
                        (opened (recv a (pop late-b) 51999) :previous "late-b")))
            (check "K1 the drain completes at exactly +10 s"
                   (and (equal (nth-value 1 (link-tick a 52000)) '(:drain))
                        (null (link-previous-session a))))
            (check "K1 after the drain a late old-epoch frame is REFUSED"
                   (equal (recv a (pop late-b) 52001) '(:drop :unknown-index)))
            (check "K1 the responder's drain runs from ITS adoption: +9.9 s still open"
                   (progn (link-tick b 53999)
                          (opened (recv b (pop held-a) 53999) :previous "held-a")))
            (link-tick b 54000)
            (check "K1 ... and refused after +10 s"
                   (equal (recv b (pop held-a) 54000) '(:drop :unknown-index)))))))))

;;; --- K2: time-triggered -----------------------------------------------------------

(defun k2-time-rekey ()
  (multiple-value-bind (a b) (make-link-pair)
    (check "K2 119.999 s: no trigger" (null (nth-value 1 (link-tick a 119999))))
    (check "K2 120 s: trigger" (link-rekey-in-progress (progn (link-tick a 120000) a)))
    (check "K2 a second tick does not start another cycle"
           (null (nth-value 1 (link-tick a 120001))))
    (let ((m1 (link-send-msg1 a)))
      (destructuring-bind (kind m2) (recv b m1 120100)
        (check "K2 responder answers" (eq kind :msg2))
        (check "K2 responder is dampened and holds a pending: its own timer does not fire"
               (null (nth-value 1 (link-tick b 125000))))
        (recv a m2 120200)
        (link-tick a 121000)
        (check "K2 initiator cut over" (link-k-bit a))
        (recv b (link-send a (msg "go") 121500) 121500)
        (check "K2 responder adopted" (link-k-bit b))
        (check "K2 session timers restart at the cutover: no trigger at cutover + 119 s"
               (not (member :initiate (nth-value 1 (link-tick a (+ 121000 119000))))))
        (check "K2 ... and a trigger at cutover + 120 s"
               (equal (nth-value 1 (link-tick a (+ 121000 120000))) '(:initiate)))))))

(defun link-send-msg1 (link) (cl-fips::link-rekey-msg1 link))

;;; --- K3: the K-bit rule -----------------------------------------------------------

(defun k3-pair-with-pending ()
  "A has cut over; B holds the pending.  Returns (values a b old-b-session)."
  (multiple-value-bind (a b) (make-link-pair)
    (link-tick a 120000)
    (recv a (second (recv b (link-send-msg1 a) 120000)) 120000)
    (link-tick a 120500)
    (values a b (link-session b))))

(defun seal-on (session idx flags text)
  (fmp-seal-frame session idx 0 (msg text) :flags flags))

(defun k3-k-bit ()
  ;; (a) sealed on the new session, addressed to B's CURRENT index, K flipped:
  ;;     the flipped bit alone selects the trial, and the frame authenticates
  (multiple-value-bind (a b) (k3-pair-with-pending)
    (check "K3 a flipped K-bit selects the pending trial even at the current index"
           (opened (recv b (seal-on (link-session a) 2001 +flag-key-epoch+ "k") 121000) :adopted "k")))
  ;; (b) the same frame with K NOT flipped, at the current index: no trial
  (multiple-value-bind (a b old) (k3-pair-with-pending)
    (check "K3 no flipped bit and not the pending index: the pending is NOT tried"
           (equal (recv b (seal-on (link-session a) 2001 0 "n") 121000) '(:drop :decrypt-failed)))
    (check "K3 ... and the responder stays on the old session" (eq (link-session b) old)))
  ;; (c) a bare flip that does not authenticate on the pending never promotes
  (multiple-value-bind (a b old) (k3-pair-with-pending)
    (let ((f (seal-on (link-previous-session a) 2001 +flag-key-epoch+ "stale")))
      (check "K3 a flipped K on an OLD-session frame falls through to current"
             (opened (recv b f 121000) :current "stale"))
      (check "K3 ... and does not promote" (and (eq (link-session b) old) (link-pending-session b)
                                                 (null (link-k-bit b))))))
  ;; (d) the bit toggles: a second rekey returns it to 0
  (multiple-value-bind (a b) (k3-pair-with-pending)
    (recv b (link-send a (msg "1") 121000) 121000)
    (check "K3 after the first rekey both sides send K=1"
           (and (frame-k (link-send a (msg "x") 121100)) (frame-k (link-send b (msg "y") 121100))))
    (link-tick a 241000)
    (recv a (second (recv b (link-send-msg1 a) 241000)) 241000)
    (link-tick a 241500)
    (let ((f (link-send a (msg "2") 242000)))
      (check "K3 after the second cutover the initiator sends K=0 (a toggle, not a mark)"
             (not (frame-k f)))
      (check "K3 the responder adopts on a K=0 frame naming its pending index"
             (opened (recv b f 242000) :adopted "2"))
      (check "K3 ... and takes K=0 from it" (null (link-k-bit b))))))

;;; --- K4: pending retirement -----------------------------------------------------------

(defun k4-retire ()
  (multiple-value-bind (a b) (make-link-pair)
    (link-tick a 120000)
    (recv b (link-send-msg1 a) 120000)   ; the msg2 is lost
    (check "K4 pending held at +119.999 s" (and (null (nth-value 1 (link-tick b 239999)))
                                                (link-pending-session b)))
    (check "K4 retired at +120 s" (and (equal (nth-value 1 (link-tick b 240000)) '(:retire))
                                       (null (link-pending-session b))))
    (check "K4 the old session still carries traffic" (opened (recv b (link-send a (msg "o") 240001) 240001)
                                                              :current "o"))
    (check "K4 a resend of that msg1 is refused as an ended cycle"
           (equal (recv b (link-send-msg1 a) 250000) '(:drop :answered-before)))))

;;; --- K5: the race ---------------------------------------------------------------------

(defun k5-race (smaller-first)
  (multiple-value-bind (a b) (make-link-pair)
    (link-tick a 120000) (link-tick b 120000)
    (let* ((a-small (node-addr< (link-our-addr a) (link-peer-addr a)))
           (s (if a-small a b)) (l (if a-small b a))
           (msg1-s (link-send-msg1 s)) (msg1-l (link-send-msg1 l))
           r-s r-l)
      (check "K5 both initiated" (and (link-rekey-in-progress a) (link-rekey-in-progress b)))
      (if smaller-first
          (setf r-s (recv s msg1-l 120100) r-l (recv l msg1-s 120100))
          (setf r-l (recv l msg1-s 120100) r-s (recv s msg1-l 120100)))
      (check "K5 the smaller NodeAddr refuses the larger's msg1" (equal r-s '(:drop :dual-rekey-won)))
      (check "K5 the larger abandons its own and answers" (and (eq (first r-l) :msg2)
                                                               (not (link-rekey-in-progress l))))
      (check "K5 the smaller completes as initiator" (eq (first (recv s (second r-l) 120200))
                                                         :rekey-complete))
      (link-tick s 121000)
      (check "K5 the smaller cut over; the larger adopts as responder"
             (and (link-k-bit s) (eq (link-pending-role l) :responder)
                  (opened (recv l (link-send s (msg "s") 121100) 121100) :adopted "s")))
      (check "K5 both directions work on the one new session"
             (opened (recv s (link-send l (msg "l") 121200) 121200) :current "l")))))

;;; --- breaks --------------------------------------------------------------------------

(defmacro with-broken ((name fn) &body body)
  `(let ((orig (fdefinition ',name)))
     (unwind-protect (progn (setf (fdefinition ',name) ,fn) ,@body)
       (setf (fdefinition ',name) orig))))

(defun test-rekey-breaks ()
  (with-broken (cl-fips::%cutover-k-bit (lambda (k restarted) (declare (ignore restarted)) k))
    (check "break: no K toggle at cutover makes K1/K3 FAIL"
           (and (plusp (quietly-count-failures #'k1-count-rekey))
                (plusp (quietly-count-failures #'k3-k-bit)))))
  (with-broken (cl-fips::%try-pending-p
                (lambda (link k idx) (declare (ignore k))
                  (and (link-pending-session link) (eql idx (link-pending-our-index link)))))
    (check "break: a trial that ignores the K-bit makes K3 FAIL"
           (plusp (quietly-count-failures #'k3-k-bit))))
  (with-broken (cl-fips::%drain-expired-p (constantly nil))
    (check "break: a drain that never expires makes K1 FAIL"
           (plusp (quietly-count-failures #'k1-count-rekey))))
  (with-broken (cl-fips::%drain-expired-p (lambda (link now)
                                            (and (cl-fips::link-drain-started link) now t)))
    (check "break: a drain that expires at once makes K1 FAIL"
           (plusp (quietly-count-failures #'k1-count-rekey))))
  (with-broken (rekey-tie-break-winner-p (lambda (o th out) (not (if (node-addr< o th) out (not out)))))
    (check "break: an inverted tie-break makes K5 FAIL"
           (and (plusp (quietly-count-failures (lambda () (k5-race t))))
                (plusp (quietly-count-failures (lambda () (k5-race nil)))))))
  (check "breaks restored: K1, K3, K5 pass again"
         (zerop (quietly-count-failures (lambda () (k1-count-rekey) (k3-k-bit) (k5-race t))))))

;;; --- O1-O3: against the upstream oracle -------------------------------------------------

(defun oracle-cmd (op line &rest stop)
  (clrhash (oproc-fields op))
  (oracle-send-line op line)
  (apply #'oracle-read-until op (or stop '("done"))))

(defun keypair-with-addr-byte (pred)
  "A fresh keypair whose node_addr's first byte satisfies PRED."
  (loop (let ((kp (generate-keypair)))
          (when (funcall pred (aref (node-addr (keypair-public-bytes kp)) 0)) (return kp)))))

(defun oracle-link (&key (static (generate-keypair)))
  "Upstream dials a Lisp responder.  Returns (values op lisp-link)."
  (let* ((op (oracle-start "verify-rekey"))
         (epoch (random-epoch))
         (hs (fips-make-ik-responder static epoch)))
    (oracle-send op (keypair-public-bytes static))
    (oracle-read-until op "ready")
    (ik-read-message-1 hs (field-bytes op "msg1"))
    (oracle-send op (ik-write-message-2 hs))
    (oracle-read-until op "ready2")
    (values op (make-link (handshake-into-session hs)
                          (int-field op "lisp_receiver_idx") (int-field op "oracle_receiver_idx")
                          :static static :peer-static-bytes (field-bytes op "initiator_static")
                          :local-epoch epoch :remote-epoch (hs-remote-epoch hs) :now-ms 0
                          :allocate-index (counter-allocator 5000)))))

(defun oracle-frame (op text)
  (oracle-cmd op (format nil "send ~a" (hex (msg text))))
  (field-bytes op "frame"))

(defun oracle-opens (op wire slot text)
  (oracle-cmd op (format nil "recv ~a" (hex wire)))
  (and (equal (field op "frame_result") "ok") (equal (field op "slot") slot)
       (equalp (field-bytes op "frame_message") (msg text))))

(defun o1-upstream-initiates ()
  (multiple-value-bind (op l) (oracle-link)
    (unwind-protect
         (let ((old (link-session l)) (late1 (oracle-frame op "late1")) (late2 (oracle-frame op "late2")))
           (check "O1 upstream frame opens on the Lisp link" (opened (recv l (oracle-frame op "a") 1000)
                                                                     :current "a"))
           (check "O1 Lisp frame opens upstream" (oracle-opens op (link-send l (msg "b") 1000) "current" "b"))
           (oracle-cmd op "rekey")
           (let ((m1 (field-bytes op "msg1")))
             (check "O1 upstream's rekey msg1 is a cleartext phase-0x1 packet"
                    (and (= (length m1) 114) (= (aref m1 0) 1)))
             (destructuring-bind (kind m2) (recv l m1 40000)
               (check "O1 Lisp answers upstream's msg1" (eq kind :msg2))
               (oracle-cmd op (format nil "recv ~a" (hex m2)))
               (check "O1 upstream reads Lisp's msg2" (equal (field op "msg2_result") "ok"))))
           (oracle-cmd op "cutover")
           (check "O1 upstream cuts over" (equal (field op "cutover") "ok"))
           (check "O1 Lisp still on the old session before the new-epoch frame"
                  (and (eq (link-session l) old) (link-pending-session l)))
           (let ((f (oracle-frame op "new")))
             (check "O1 upstream's new-epoch frame carries K and Lisp's new index"
                    (and (frame-k f) (= (frame-idx f) (link-pending-our-index l)) (= (frame-counter f) 0)))
             (check "O1 Lisp adopts on it" (opened (recv l f 41000) :adopted "new")))
           (check "O1 upstream opens Lisp's K frame on its new current"
                  (oracle-opens op (link-send l (msg "c") 41000) "current" "c"))
           (check "O1 upstream's late old frame opens on Lisp's previous in the drain"
                  (opened (recv l late1 50999) :previous "late1"))
           (link-tick l 51000)
           (check "O1 ... and is refused after it" (equal (recv l late2 51001) '(:drop :unknown-index))))
      (oracle-cmd op "end" "nothing")
      (oracle-finish op))))

(defun o2-lisp-initiates ()
  (multiple-value-bind (op l) (oracle-link)
    (unwind-protect
         (let ((late (link-send l (msg "late") 100000)))
           (multiple-value-bind (packets actions) (link-tick l 120000)
             (check "O2 Lisp triggers at 120 s" (equal actions '(:initiate)))
             (oracle-cmd op (format nil "recv ~a" (hex (first packets)))))
           (check "O2 upstream answers Lisp's msg1" (equal (field op "msg1_result") "ok"))
           (check "O2 Lisp reads upstream's msg2"
                  (eq (first (recv l (field-bytes op "msg2") 120100)) :rekey-complete))
           (oracle-cmd op "state")
           (check "O2 upstream holds a responder pending, K still 0"
                  (and (equal (field op "pending_role") "responder") (equal (field op "k_bit") "0")))
           (check "O2 upstream still opens Lisp's old-session frame on current"
                  (oracle-opens op (link-send l (msg "pre") 120200) "current" "pre"))
           (link-tick l 121000)
           (check "O2 Lisp cut over" (link-k-bit l))
           (check "O2 upstream adopts on Lisp's K frame"
                  (oracle-opens op (link-send l (msg "new") 121100) "adopted" "new"))
           (oracle-cmd op "state")
           (check "O2 upstream took K=1 and the new indices"
                  (and (equal (field op "k_bit") "1") (equal (field op "has_previous") "1")
                       (= (int-field op "their_idx") (link-our-index l))
                       (= (int-field op "our_idx") (link-their-index l))))
           (let ((f (oracle-frame op "back")))
             (check "O2 upstream's reply carries K, counter 0" (and (frame-k f) (= (frame-counter f) 0)))
             (check "O2 Lisp opens it on the new current" (opened (recv l f 121200) :current "back")))
           (check "O2 upstream opens Lisp's late old frame on its previous"
                  (oracle-opens op late "previous" "late")))
      (oracle-cmd op "end" "nothing")
      (oracle-finish op))))

(defvar *o3-branches* nil "Which side was smaller in each O3 run.")

(defun o3-race (&optional (static (generate-keypair)))
  (multiple-value-bind (op l) (oracle-link :static static)
    (unwind-protect
         (let* ((lisp-m1 (first (link-tick l 120000)))
                (up-m1 (progn (oracle-cmd op "rekey") (field-bytes op "msg1"))))
           (oracle-cmd op "state")
           (check "O3 both sides agree on the two NodeAddrs"
                  (and (equalp (field-bytes op "lisp_node_addr") (link-our-addr l))
                       (equalp (field-bytes op "oracle_node_addr") (link-peer-addr l))))
           (let ((lisp-small (node-addr< (link-our-addr l) (link-peer-addr l)))
                 (lr (recv l up-m1 120100)))
             (pushnew (if lisp-small :lisp-smaller :upstream-smaller) *o3-branches*)
             (oracle-cmd op (format nil "recv ~a" (hex lisp-m1)))
             (cond
               (lisp-small
                (check "O3 Lisp is smaller: Lisp refuses upstream's msg1"
                       (equal lr '(:drop :dual-rekey-won)))
                (check "O3 ... and upstream (larger) answers Lisp's"
                       (equal (field op "msg1_result") "ok"))
                (recv l (field-bytes op "msg2") 120200)
                (link-tick l 121000)
                (check "O3 ... and adopts Lisp's new epoch"
                       (oracle-opens op (link-send l (msg "w") 121100) "adopted" "w")))
               (t
                (check "O3 upstream is smaller: upstream refuses Lisp's msg1"
                       (and (equal (field op "msg1_result") "refused")
                            (equal (field op "reason") "dual rekey won")))
                (check "O3 ... and Lisp (larger) abandoned its own and answered"
                       (and (eq (first lr) :msg2) (not (link-rekey-in-progress l))))
                (oracle-cmd op (format nil "recv ~a" (hex (second lr))))
                (oracle-cmd op "cutover")
                (check "O3 ... and adopts upstream's new epoch"
                       (opened (recv l (oracle-frame op "w") 121100) :adopted "w"))))))
      (oracle-cmd op "end" "nothing")
      (oracle-finish op))))

(defun test-rekey ()
  (k1-count-rekey)
  (k2-time-rekey)
  (k3-k-bit)
  (k4-retire)
  (k5-race t)
  (k5-race nil)
  (test-rekey-breaks)
  (check "rekey defaults: 120 s, 65536 messages, 10 s drain, 120 s hold"
         (let ((c (make-rekey-config)))
           (and (= (rekey-config-after-secs c) 120) (= (rekey-config-after-messages c) 65536)
                (= +drain-window-secs+ 10) (= (rekey-config-pending-hold-ms c) 120000))))
  (check "rekey-decide: counter 65535 does not trigger, 65536 does"
         (let ((c (make-rekey-config)))
           (and (null (rekey-decide (make-rekey-snapshot :counter 65535) c))
                (equal (rekey-decide (make-rekey-snapshot :counter 65536) c) '(:initiate)))))
  (check "rekey-decide: jitter shifts the time threshold"
         (let ((c (make-rekey-config)))
           (and (null (rekey-decide (make-rekey-snapshot :elapsed-secs 134 :jitter-secs 15) c))
                (equal (rekey-decide (make-rekey-snapshot :elapsed-secs 105 :jitter-secs -15) c)
                       '(:initiate)))))
  (cond
    ((sb-ext:posix-getenv "CL_FIPS_NO_ORACLE")
     (format t "  SKIPPED: rekey oracle arms (CL_FIPS_NO_ORACLE set)~%"))
    ((not (oracle-binary))
     (incf *checks*) (incf *failures*)
     (format t "  FAIL oracle binary unavailable (set CL_FIPS_NO_ORACLE=1 to skip)~%"))
    (t
     (dotimes (k 2) (o1-upstream-initiates) (o2-lisp-initiates))
     ;; Steer the Lisp node_addr to the bottom and the top of the order so both
     ;; orderings are exercised (upstream's key is random: each steer misses
     ;; with probability 1/256, and then a few random runs make up for it).
     (setf *o3-branches* nil)
     (o3-race (keypair-with-addr-byte #'zerop))
     (o3-race (keypair-with-addr-byte (lambda (b) (= b 255))))
     (loop repeat 10 until (= (length *o3-branches*) 2) do (o3-race))
     (check "O3 exercised both orderings (Lisp smaller, upstream smaller)"
            (= (length *o3-branches*) 2)))))
