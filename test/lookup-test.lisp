;;;; lookup-test.lisp -- coordinate discovery: codecs, the proof, and lookups on
;;;; three nodes joined by in-memory links (A - M - B).
;;;;
;;;;   L1  byte layout of both messages, written out from wire.rs, and round trips
;;;;   L2  the proof: a response verifies with the target's key, and not with
;;;;       another key, nor after a change to the id, the target or the coords
;;;;   L3  A looks B up through M: B answers, M passes the answer back, A verifies
;;;;       it and caches B's coordinates; a session A then opens carries them
;;;;   L4  M saw the request once: a replayed request is a duplicate, a response
;;;;       nobody asked for is unsolicited, a second copy is not forwarded twice
;;;;   L5  an answer signed by the wrong key is refused, and the lookup goes on
;;;;   L6  with nobody to ask, a lookup is retried on the 1/2/4/8 s schedule and
;;;;       then reported failed
;;;;   L7  TTL: a request that arrives with TTL 0 is not forwarded

(in-package #:cl-fips.test)

(defun test-lookup-codecs ()
  (let* ((target (filler 16 #x11)) (origin (filler 16 #x22)) (root (filler 16 #x33))
         (req (make-lookup-request #x0102030405060708 target origin (list origin root) :ttl 7 :min-mtu 1280))
         (wire (encode-lookup-request req)))
    (check "L1 request: [0x30][id LE][target][origin][ttl][min_mtu LE][coords]"
           (equalp wire (concatenate '(vector (unsigned-byte 8))
                                     (octets #x30 8 7 6 5 4 3 2 1) target origin (octets 7 0 5)
                                     (octets 2 0) origin root)))
    (let ((back (decode-lookup-request (subseq wire 1))))
      (check "L1 request round trip"
             (and (= (lookup-request-request-id back) #x0102030405060708)
                  (= (lookup-request-ttl back) 7)
                  (equalp (encode-lookup-request back) wire))))
    (check "L1 a short request is refused"
           (handler-case (progn (decode-lookup-request (filler 44 0)) nil) (error () t))))
  (let* ((target (filler 16 #x11)) (root (filler 16 #x33)) (proof (filler 64 #x44))
         (resp (make-lookup-response 9 target (list target root) proof :path-mtu 1400))
         (wire (encode-lookup-response resp)))
    (check "L1 response: [0x31][id LE][target][path_mtu LE][coords][proof]"
           (equalp wire (concatenate '(vector (unsigned-byte 8))
                                     (octets #x31 9 0 0 0 0 0 0 0) target (octets #x78 #x05)
                                     (octets 2 0) target root proof)))
    (check "L1 response round trip"
           (equalp (encode-lookup-response (decode-lookup-response (subseq wire 1))) wire))
    (check "L1 a response missing proof bytes is refused"
           (handler-case (progn (decode-lookup-response (subseq wire 1 (1- (length wire)))) nil)
             (error () t)))))

(defun test-lookup-proof ()
  (let* ((kp (generate-keypair))
         (secret (secp256k1-fast.ecdh::keypair-secret kp))
         (xonly (subseq (keypair-public-bytes kp) 1))
         (target (node-addr xonly))
         (coords (list target (filler 16 #x55)))
         (resp (make-lookup-response 77 target coords (sign-lookup-proof secret 77 target coords))))
    (check "L2 the target's proof verifies" (verify-lookup-response resp xonly))
    (check "L2 ... not with another key"
           (not (verify-lookup-response resp (subseq (keypair-public-bytes (generate-keypair)) 1))))
    (flet ((tampered (fn) (let ((r (copy-structure resp))) (funcall fn r) (not (verify-lookup-response r xonly)))))
      (check "L2 ... not for another request id"
             (tampered (lambda (r) (setf (cl-fips::lookup-response-request-id r) 78))))
      (check "L2 ... not with other coordinates"
             (tampered (lambda (r) (setf (cl-fips::lookup-response-target-coords r) (list target)))))
      (check "L2 path_mtu is not covered (each hop rewrites it)"
             (not (tampered (lambda (r) (setf (cl-fips::lookup-response-path-mtu r) 1280))))))))

(defun chain-amb ()
  "A - M - B, settled.  Returns (values a m b endpoints)."
  (let* ((a (new-test-node)) (m (new-test-node)) (b (new-test-node))
         (eps (append (connect-nodes a m) (connect-nodes m b))))
    (settle (list a m b) eps 0)
    (values a m b eps)))

(defun test-lookup-chain ()
  (multiple-value-bind (a m b eps) (chain-amb)
    (declare (ignorable m))
    (let ((asked (node-lookup a (node-pub b) :now 1000)))
      (check "L3 A asks one peer (M, its tree peer whose filter reaches B)" (= asked 1))
      (let ((ev (pump eps 1000)))
        (check "L3 M forwards the request" (has-event ev :lookup-forwarded (fips-node-own b) 1))
        (check "L3 B answers it" (has-event ev :lookup-answered (fips-node-own a)))
        (check "L3 M passes the answer back" (has-event ev :lookup-response-forwarded (fips-node-own b)))
        (let ((ok (has-event ev :lookup-ok (fips-node-own b))))
          (check "L3 A verifies the answer" ok)
          (check "L3 ... and B's coordinates are B's own ancestry"
                 (and ok (equalp (third ok) (node-our-coords b))))
          (check "L3 path_mtu is the smallest link MTU on the way (1400 here)"
                 (and ok (= (fourth ok) 1400)))))
      (check "L3 A caches B's coordinates" (equalp (node-cached-coords a (fips-node-own b)) (node-our-coords b)))
      (let ((fi (node-open-session a (node-pub b) :now 1100)))
        (check "L3 a session A opens carries B's looked-up coordinates"
               (equalp (cl-fips::fsp-initiator-peer-coords fi) (node-our-coords b))))
      (check "L3 ... and is established"
             (has-event (pump eps 1100) :established (fips-node-own b))))))

(defun test-lookup-replays ()
  (multiple-value-bind (a m b eps) (chain-amb)
    (let* ((am (second (first eps)))                 ; A's link to M
           (ma (second (second eps)))                ; M's link to A
           (req (make-lookup-request 4242 (fips-node-own b) (fips-node-own a) (node-our-coords a))))
      (check "L4 M forwards a request the first time"
             (has-event (cl-fips::node-lookup-request m ma (subseq (encode-lookup-request req) 1) 1000)
                        :lookup-forwarded))
      (check "L4 ... and drops the same request id again"
             (has-event (cl-fips::node-lookup-request m ma (subseq (encode-lookup-request req) 1) 1001)
                        :lookup-dropped :duplicate))
      (let ((stray (make-lookup-response 999 (fips-node-own b) (node-our-coords b) (filler 64 1))))
        (check "L4 a response to no request is unsolicited"
               (has-event (cl-fips::node-lookup-response a am (subseq (encode-lookup-response stray) 1) 1002)
                          :lookup-dropped :unsolicited)))
      (pump eps 1003)                                ; B's real answer goes back through M
      (let ((again (make-lookup-response 4242 (fips-node-own b) (node-our-coords b) (filler 64 1))))
        (check "L4 M does not pass back a second answer to the same request"
               (has-event (cl-fips::node-lookup-response m (second (third eps)) (subseq (encode-lookup-response again) 1) 1004)
                          :lookup-dropped :already-forwarded))))))

(defun test-lookup-bad-proof ()
  (multiple-value-bind (a m b eps) (chain-amb)
    (declare (ignore m))
    (node-lookup a (node-pub b) :now 1000)
    (let* ((pending (gethash (fips-node-own b) (cl-fips::fips-node-lookup-pending a)))
           (id (first (cl-fips::lookup-pending-ids pending)))
           (wrong (generate-keypair))
           (coords (list (fips-node-own b)))
           (forged (make-lookup-response id (fips-node-own b) coords
                                         (sign-lookup-proof (secp256k1-fast.ecdh::keypair-secret wrong)
                                                            id (fips-node-own b) coords))))
      (check "L5 an answer signed by another key is refused"
             (has-event (cl-fips::node-lookup-response a (second (first eps)) (subseq (encode-lookup-response forged) 1) 1001)
                        :lookup-dropped :bad-proof))
      (check "L5 ... nothing is cached" (null (node-cached-coords a (fips-node-own b))))
      (check "L5 ... and the real answer is still taken"
             (has-event (pump eps 1002) :lookup-ok (fips-node-own b))))))

(defun test-lookup-exhausted ()
  (let* ((a (new-test-node)) (b (new-test-node)))
    (check "L6 with no peers, nobody is asked" (zerop (node-lookup a (node-pub b) :now 0)))
    (let ((events (loop for now from 0 to 16000 by 250 append (node-tick a now))))
      (check "L6 the lookup fails once its four attempts (15 s) are spent"
             (has-event events :lookup-failed (fips-node-own b)))
      (check "L6 ... and is no longer pending"
             (zerop (hash-table-count (cl-fips::fips-node-lookup-pending a)))))
    ;; the schedule itself: attempts at 0, 1, 3, 7; failure at 15
    (let* ((c (new-test-node)) (d (new-test-node)) (fail-at nil) (attempts '()))
      (node-lookup c (node-pub d) :now 0)
      (loop for now from 0 to 16000 by 100
            do (let ((p (gethash (fips-node-own d) (cl-fips::fips-node-lookup-pending c))))
                 (when (and p (not (member (cl-fips::lookup-pending-sent-at p) attempts)))
                   (push (cl-fips::lookup-pending-sent-at p) attempts)))
               (when (and (null fail-at) (has-event (node-tick c now) :lookup-failed))
                 (setf fail-at now)))
      (check (format nil "L6 attempts at 0, 1, 3, 7 s (~a)" (reverse attempts))
             (equal (reverse attempts) '(0 1000 3000 7000)))
      (check (format nil "L6 failure at 15 s (~a)" fail-at) (eql fail-at 15000)))))

(defun test-lookup-ttl ()
  (multiple-value-bind (a m b eps) (chain-amb)
    (let ((req (make-lookup-request 5151 (fips-node-own b) (fips-node-own a) (node-our-coords a) :ttl 0)))
      (check "L7 a request that arrives with TTL 0 is not forwarded"
             (has-event (cl-fips::node-lookup-request m (second (second eps)) (subseq (encode-lookup-request req) 1) 1000)
                        :lookup-dropped :ttl)))))

(defun test-lookup ()
  (test-lookup-codecs)
  (test-lookup-proof)
  (test-lookup-chain)
  (test-lookup-replays)
  (test-lookup-bad-proof)
  (test-lookup-exhausted)
  (test-lookup-ttl))
