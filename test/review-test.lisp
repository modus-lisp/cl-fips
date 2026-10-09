;;;; review-test.lisp -- regressions for the second review's findings (node and FSP
;;;; level; the daemon's are in daemon-test.lisp).
;;;;
;;;;   R1  a lost msg3 is resent until a frame confirms it; a resent msg3 at the
;;;;       responder is a duplicate, not an error
;;;;   R2  a resent SessionSetup while we wait for msg3 gets the SAME ack; a
;;;;       different setup under that source does not displace the handshake
;;;;   R3  both nodes open at once: one session results, the smaller address
;;;;       initiating
;;;;   R4  a SessionSetup nobody answers expires, with :session-failed
;;;;   R5  a SessionSetup too big for the link is a node-error, never a link-error
;;;;       escaping the node
;;;;   R6  a flood of lookup requests from one link does not stop us answering
;;;;       another link's request for us; the forward limiter's table is purged
;;;;   R7  sessions rekey on their own after 120 s (+-15 s), and keep working

(in-package #:cl-fips.test)

(defun fsp-pair (&key (now 0))
  "An initiator and a responder with B's ack in hand.  Returns (values fi resp msg3)."
  (let* ((ka (generate-keypair)) (kb (generate-keypair))
         (a (node-addr (keypair-public-bytes ka))) (b (node-addr (keypair-public-bytes kb)))
         (fi (make-fsp-initiator ka (keypair-public-bytes kb) (random-epoch) a b (list a) (list b)))
         (d1 (fsp-setup-datagram fi now)))
    (multiple-value-bind (resp ack) (fsp-accept-setup kb (random-epoch) b (list b) (subseq d1 1) :now now)
      (values fi resp (fsp-handle-ack fi (subseq ack 1) :now now)))))

(defun test-review-msg3 ()
  (multiple-value-bind (fi resp msg3) (fsp-pair)
    (check "R1 no resend before the first interval" (null (cl-fips::fsp-resend-msg3 fi 999)))
    (let ((again (cl-fips::fsp-resend-msg3 fi 1000)))
      (check "R1 the lost msg3 is resent at 1 s, unchanged" (equalp again msg3))
      (check "R1 ... and the resend completes the responder's side"
             (fsp-complete-accept resp (subseq again 1) :now 1000)))
    (check "R1 a further copy of msg3 at the responder is a duplicate"
           (eq (fsp-handle-rekey-msg3 resp (subseq msg3 1) :now 1100) :duplicate))
    (check "R1 the next resend waits 2 s" (and (null (cl-fips::fsp-resend-msg3 fi 2999))
                                               (cl-fips::fsp-resend-msg3 fi 3000)))
    ;; the responder's first frame confirms msg3
    (let ((frame (fsp-data-datagram resp (ascii "ok") :now 3100)))
      (fsp-open-any fi (cl-fips::bytes-slice (subseq frame 1) 35) :now 3100))
    (check "R1 a frame from the peer stops the resends" (null (cl-fips::fsp-resend-msg3 fi 100000)))))

(defun test-review-dup-setup ()
  (let* ((b (new-test-node)) (ka (generate-keypair)) (kc (generate-keypair))
         (a (node-addr (keypair-public-bytes ka))) (bo (fips-node-own b))
         (fi (make-fsp-initiator ka (node-pub b) (random-epoch) a bo (list a) (list bo)))
         (setup (fsp-setup-datagram fi 0))
         (sent '()) (link 'fake))
    ;; capture what B sends instead of routing it
    (sb-int:encapsulate 'cl-fips::%node-send 'capture
                        (lambda (f node m &rest r) (declare (ignore f node r)) (push m sent) link))
    (unwind-protect
         (progn
           (cl-fips::node-local b link (subseq setup 1) 0)
           (cl-fips::node-local b link (subseq setup 1) 500)
           (check "R2 a resent setup is answered with the same ack"
                  (and (= (length sent) 2) (equalp (first sent) (second sent))))
           (let* ((other (make-fsp-initiator kc (node-pub b) (random-epoch) a bo (list a) (list bo)))
                  (forged (fsp-setup-datagram other 0)))
             (check "R2 a different setup under the same source is refused"
                    (has-event (cl-fips::node-local b link (subseq forged 1) 600) :session-error)))
           (check "R2 ... and the genuine handshake still completes"
                  (has-event (cl-fips::node-local b link (subseq (fsp-handle-ack fi (subseq (first sent) 1)) 1) 700)
                             :accepted a)))
      (sb-int:unencapsulate 'cl-fips::%node-send 'capture))))

(defun test-review-crossing ()
  (let* ((a (new-test-node)) (b (new-test-node)) (eps (connect-nodes a b)))
    (settle (list a b) eps 0)
    (node-open-session a (node-pub b) :now 1000)
    (node-open-session b (node-pub a) :now 1000)
    (let ((ev (pump eps 1000)))
      (check "R3 crossing setups end in one established session on each side"
             (and (eq (cl-fips::fsp-initiator-phase (node-session a (fips-node-own b))) :established)
                  (eq (cl-fips::fsp-initiator-phase (node-session b (fips-node-own a))) :established)))
      (check "R3 ... the smaller address kept initiating"
             (has-event ev :session-crossed))
      (node-send-data a (fips-node-own b) (ascii "x") :dst-port 3 :now 1100)
      (check "R3 ... and data flows" (has-event (pump eps 1100) :data (fips-node-own a))))))

(defun test-review-setup-expiry ()
  (let ((a (new-test-node)) (b (new-test-node)))
    (check "R4 an open with no route is queued"
           (eq (nth-value 1 (node-open-session a (node-pub b) :now 0)) :queued))
    (let ((ev (loop for now from 0 to 50000 by 1000 append (node-tick a now))))
      (check "R4 after its resends the unanswered setup fails" (has-event ev :session-failed (fips-node-own b)))
      (check "R4 ... and the session is gone" (null (node-session a (fips-node-own b)))))))

(defun test-review-big-setup ()
  (let* ((a (new-test-node)) (b (new-test-node)) (eps (connect-nodes a b))
         (huge (loop repeat 90 collect (filler 16 7))))
    (settle (list a b) eps 0)
    (check "R5 a setup too big for the link is queued, not signalled"
           (eq (nth-value 1 (handler-case (node-open-session a (node-pub b) :peer-coords huge :now 1000)
                              (error (e) (values nil e))))
               :queued))
    (check "R5 ... and ticking past its resends signals nothing"
           (handler-case (progn (loop for now from 1000 to 50000 by 1000 do (node-tick a now)) t)
             (error () nil)))))

(defun test-review-lookup-flood ()
  (multiple-value-bind (a m b eps) (chain-amb)
    (declare (ignore a))
    (let ((ma (second (second eps))) (mb (second (third eps))))
      ;; M's request table filled from A's link
      (loop for id from 1 to 4200
            do (cl-fips::node-lookup-request
                m ma (subseq (encode-lookup-request
                              (make-lookup-request id (filler 16 (mod id 250)) (filler 16 9) (list (filler 16 9))))
                             1)
                1000))
      (check "R6 the request table stays bounded"
             (<= (hash-table-count (cl-fips::fips-node-lookup-recent m)) 4096))
      (check "R6 a request for M from B's link is still answered"
             (has-event (cl-fips::node-lookup-request
                         m mb (subseq (encode-lookup-request
                                       (make-lookup-request 999999 (fips-node-own m) (fips-node-own b)
                                                            (node-our-coords b)))
                                      1)
                         1001)
                        :lookup-answered))
      (node-tick m 20000)
      (check "R6 the forward limiter forgets old targets"
             (zerop (hash-table-count (cl-fips::fips-node-lookup-forwarded-at m)))))))

(defun test-review-auto-rekey ()
  ;; three runs: the jitter decides which side rekeys first, and the side that
  ;; accepted the session rekeying with no data to send is the case that broke
  (dotimes (k 3) (review-auto-rekey-once)))

(defun review-auto-rekey-once ()
  (let* ((a (new-test-node)) (b (new-test-node)) (eps (connect-nodes a b)) (events '()))
    (settle (list a b) eps 0)
    (node-open-session a (node-pub b) :now 1000)
    (pump eps 1000)
    (loop for now from 2000 to 150000 by 1000
          do (setf events (append events (node-tick a now) (node-tick b now) (pump eps now))))
    (check "R7 a rekey started on its own by 136 s" (has-event events :rekey-started))
    (check "R7 ... and cut over" (has-event events :cutover))
    (node-send-data a (fips-node-own b) (ascii "after") :dst-port 8 :now 150500)
    (check "R7 the session still carries data"
           (has-event (pump eps 150500) :data (fips-node-own a) 0 8 (ascii-octets "after")))))

(defun test-review ()
  (test-review-msg3)
  (test-review-dup-setup)
  (test-review-crossing)
  (test-review-setup-expiry)
  (test-review-big-setup)
  (test-review-lookup-flood)
  (test-review-auto-rekey))
