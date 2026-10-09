;;;; node-test.lisp -- the node (src/node.lisp), in memory: links over pipes, no
;;;; sockets, time passed in.
;;;;
;;;;   N1  two nodes: one opens a session, the other accepts it, data both ways
;;;;   N2  three nodes in a line: the middle one forwards, the ends hold a session
;;;;       through it
;;;;   N3  a session opened under another node's address is refused at msg3
;;;;   N4  the DataPacket size limit at the link MTU
;;;;   N5  a malformed SessionDatagram is dropped, not an error
;;;;   N6  a removed link's peer leaves the tree

(in-package #:cl-fips.test)

(defun new-test-node () (make-fips-node (generate-keypair)))

(defun node-pub (node) (keypair-public-bytes (cl-fips::fips-node-static node)))

(defun connect-nodes (na nb)
  "NA dials NB over an in-memory pipe.  Returns two endpoints, (node link inbox)."
  (let* ((ab (list (u8 0))) (ba (list (u8 0))) (lb nil)
         (port-b (make-pipe-port ab ba))
         (port-a (make-pipe-port ba ab
                                 (lambda () (unless lb
                                              (setf lb (stream-link-accept port-b (cl-fips::fips-node-static nb)
                                                                           (random-epoch)
                                                                           :routing (fips-node-tree nb)))))))
         (la (stream-link-initiate port-a (cl-fips::fips-node-static na) (node-pub nb) (random-epoch)
                                   :routing (fips-node-tree na))))
    (node-add-link na la)
    (node-add-link nb lb)
    (list (list na la ba) (list nb lb ab))))

(defun pump (endpoints now &optional (rounds 200))
  "Deliver everything waiting, until no inbox holds a packet.  Returns all events."
  (let ((events '()))
    (loop repeat rounds
          for moved = nil
          do (dolist (ep endpoints)
               (destructuring-bind (node link inbox) ep
                 (loop while (and (member link (fips-node-links node)) (>= (length (car inbox)) 4))
                       do (setf moved t)
                          (setf events (append events (node-receive node link :timeout-ms 0 :now now))))))
          while moved)
    events))

(defun tick-all (nodes now) (dolist (n nodes) (node-tick n now)))

(defun has-event (events kind &rest args)
  (find-if (lambda (e) (and (eq (first e) kind)
                            (every (lambda (want got) (equalp want got)) args (rest e))))
           events))

(defun settle (nodes endpoints now)
  "Tick and pump a few times so announces and filters reach every node."
  (loop for t0 from now by 100 repeat 6
        do (tick-all nodes t0) (pump endpoints t0)))

(defun test-node-two ()
  (let* ((a (new-test-node)) (b (new-test-node))
         (eps (connect-nodes a b)))
    (settle (list a b) eps 0)
    (node-open-session a (node-pub b) :now 1000)
    (let ((ev (pump eps 1000)))
      (check "N1: B answers the session A opens" (has-event ev :accept-answered (fips-node-own a)))
      (check "N1: A's session is established" (has-event ev :established (fips-node-own b)))
      (check "N1: B's side is established" (has-event ev :accepted (fips-node-own a))))
    (node-send-data a (fips-node-own b) (ascii-octets "hello") :dst-port 7 :now 1100)
    (check "N1: B receives A's data on its port"
           (has-event (pump eps 1100) :data (fips-node-own a) 0 7 (ascii-octets "hello")))
    (node-send-data b (fips-node-own a) (ascii-octets "back") :src-port 7 :dst-port 9 :now 1200)
    (check "N1: A receives B's reply"
           (has-event (pump eps 1200) :data (fips-node-own b) 7 9 (ascii-octets "back")))
    ;; N4: the size limit at the link MTU (1400 - 110)
    (check "N4: 1290 bytes fit"
           (handler-case (progn (node-send-data a (fips-node-own b) (make-array 1290 :element-type '(unsigned-byte 8)) :now 1300) t)
             (error () nil)))
    (check "N4: 1291 bytes are refused before sending"
           (eq (handler-case (progn (node-send-data a (fips-node-own b) (make-array 1291 :element-type '(unsigned-byte 8)) :now 1300) nil)
                 (node-error (e) (node-error-reason e)))
               :too-big))
    (pump eps 1300)
    ;; N5: a malformed datagram
    (check "N5: a SessionDatagram shorter than its header is dropped as malformed"
           (has-event (cl-fips::node-datagram a (second (first eps)) (octets 1 2 3) 1400) :dropped :malformed))
    ;; N6: removing the link takes its peer out of the tree
    (check "N6: before removal, B is a tree peer of A"
           (node-peer-coords a (fips-node-own b)))
    (node-remove-link a (second (first eps)))
    (check "N6: after removal, B is not"
           (null (node-peer-coords a (fips-node-own b))))))

(defun test-node-transit ()
  (let* ((a (new-test-node)) (m (new-test-node)) (b (new-test-node))
         (eps (append (connect-nodes a m) (connect-nodes m b)))
         (nodes (list a m b)))
    (settle nodes eps 0)
    (check "N2: A's route to B goes through M"
           (let ((l (node-route a (fips-node-own b))))
             (and l (equalp (node-link-peer l) (fips-node-own m)))))
    (node-open-session a (node-pub b) :now 1000)
    (let ((ev (pump eps 1000)))
      (check "N2: B accepts the session A opened through M" (has-event ev :accepted (fips-node-own a)))
      (check "N2: A's session with B is established" (has-event ev :established (fips-node-own b))))
    (node-send-data a (fips-node-own b) (ascii-octets "via m") :dst-port 5 :now 1100)
    (node-send-data b (fips-node-own a) (ascii-octets "and back") :dst-port 6 :now 1100)
    (let ((ev (pump eps 1100)))
      (check "N2: B receives A's data through M" (has-event ev :data (fips-node-own a) 0 5 (ascii-octets "via m")))
      (check "N2: A receives B's data through M" (has-event ev :data (fips-node-own b) 0 6 (ascii-octets "and back"))))
    (check "N2: M forwarded the traffic" (>= (fips-node-forwarded m) 5))
    (check "N2: M holds no session of its own" (null (node-session m (fips-node-own a))))))

(defun test-node-queued-open ()
  "N7: a session opened before any route to its peer exists is kept, and goes out
   once the filters arrive."
  (let* ((a (new-test-node)) (m (new-test-node)) (b (new-test-node))
         (eps (append (connect-nodes a m) (connect-nodes m b)))
         (nodes (list a m b)))
    (check "N7: with no filters yet, the open is queued"
           (eq (nth-value 1 (node-open-session a (node-pub b) :now 0)) :queued))
    (settle nodes eps 100)
    ;; the resend interval is 4 s: tick past it and deliver
    (loop for now from 5000 to 9000 by 1000 do (tick-all nodes now) (pump eps now))
    (check "N7: the queued session is established once a route exists"
           (eq (cl-fips::fsp-initiator-phase (node-session a (fips-node-own b))) :established))))

(defun test-node-addr-binding ()
  "N3: the key msg3 authenticates must be the one the source address names."
  (let* ((kb (generate-keypair)) (b (fsp-addr 20)) (a (fsp-addr 10)))
    (flet ((attempt (initiator-key claimed-addr)
             (let* ((fi (make-fsp-initiator initiator-key (keypair-public-bytes kb) (random-epoch)
                                            claimed-addr b (list claimed-addr) (list b)))
                    (d1 (fsp-setup-datagram fi)))
               (multiple-value-bind (resp ack) (fsp-accept-setup kb (random-epoch) b (list b) (subseq d1 1))
                 (let ((d3 (fsp-handle-ack fi (subseq ack 1))))
                   (handler-case (progn (fsp-complete-accept resp (subseq d3 1)) :accepted)
                     (error () :refused)))))))
      (check "N3: a session under another node's address is refused"
             (eq (attempt (generate-keypair) a) :refused))
      (let ((kc (generate-keypair)))
        (check "N3: the same session under the key's own address is accepted"
               (eq (attempt kc (node-addr (keypair-public-bytes kc))) :accepted))))))

(defun test-node-dead-link ()
  "N8: a link silent for 30 s is removed; one that keeps hearing its peer is not."
  (let* ((a (new-test-node)) (b (new-test-node))
         (eps (connect-nodes a b)))
    (settle (list a b) eps 0)
    ;; both sides keep talking: heartbeats every 5 s are delivered
    (loop for now from 1000 to 61000 by 1000 do (tick-all (list a b) now) (pump eps now))
    (check "N8: a link that is heard from stays up past the dead timeout"
           (= (length (fips-node-links a)) 1))
    ;; B goes silent: A ticks, nothing is delivered
    (let* ((heard (gethash (second (first eps)) (cl-fips::fips-node-last-heard a)))
           (events (loop for now from 62000 to (+ heard 30000) by 1000 append (node-tick a now))))
      (check "N8: A last heard B during the exchange" (<= 60000 heard 61000))
      (check "N8: ... it is not removed at 30 s of silence" (= (length (fips-node-links a)) 1))
      (setf events (append events (node-tick a (+ heard 30001))))
      (check "N8: it is removed just past 30 s of silence, as :dead"
             (and (null (fips-node-links a)) (has-event events :link-closed :dead)))
      (check "N8: the dead peer left A's tree" (null (node-peer-coords a (fips-node-own b)))))))

(defun test-node ()
  (test-node-dead-link)
  (test-node-two)
  (test-node-transit)
  (test-node-queued-open)
  (test-node-addr-binding))
