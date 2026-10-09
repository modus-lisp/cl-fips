;;;; node.lisp -- a FIPS node: links, one tree, FSP sessions, forwarding.
;;;;
;;;; The pieces below this file speak one protocol each.  A node is what a program
;;;; runs: it owns the stream links to its peers, the spanning tree they share, the
;;;; end-to-end sessions keyed by the far node's address, and the forwarding of
;;;; SessionDatagrams that are not for it.
;;;;
;;;; It does no I/O policy of its own.  The caller decides which link has input
;;;; (transport/: sb-bsd-sockets and poll, on SBCL and on hosted modus alike),
;;;; calls NODE-RECEIVE for it, and calls NODE-TICK periodically.  Each call returns
;;;; a list of events -- plists whose first element names them -- and prints
;;;; nothing.  Time (ms) is passed in.
;;;;
;;;; Events:
;;;;   (:frame TYPE LINK SLOT)         any frame that arrived, by link msg_type; SLOT
;;;;                                   is :current, :previous or :adopted (link rekey)
;;;;   (:link-event EVENT LINK)        a link rekey packet (:rekey-answered ...)
;;;;   (:link-action ACTION LINK)      a link rekey action from the tick (:cutover ...)
;;;;   (:link-drop REASON LINK)        a non-fatal link error: the frame was dropped
;;;;   (:link-closed REASON LINK [MSG1])  a fatal link error, :dead (silent too long),
;;;                                   :disconnect (the peer said it was going),
;;;                                   or :peer-restart (its peer restarted; MSG1 is
;;;                                   the new handshake, to accept): the link is gone
;;;;   (:forwarded DEST TTL LINK)      a SessionDatagram forwarded out of LINK
;;;;   (:dropped REASON DEST)          a transit datagram not forwarded
;;;;   (:established PEER)             our session with PEER completed its handshake
;;;;   (:accept-answered PEER)         PEER opened a session; we answered its msg1
;;;;   (:accepted PEER)                the session PEER opened is established
;;;;   (:data PEER SRC-PORT DST-PORT DATA TIMESTAMP)  a DataPacket on a session
;;;;   (:session-frame PEER MSG-TYPE)  another established FSP frame (reports)
;;;;   (:rekey-answered PEER)          we answered PEER's rekey msg1
;;;;   (:rekey-msg3 PEER RESULT)       PEER's rekey msg3 taken (T) or a resend (:duplicate)
;;;;   (:rekey-ack PEER)               PEER answered our rekey; our msg3 is sent
;;;;   (:cutover PEER WHO)             a rekeyed session became current (:theirs / :ours)
;;;;   (:setup-resent PEER)            an unanswered SessionSetup was sent again
;;;   (:rekey-started PEER)           the schedule started a rekey of our session with PEER
;;;   (:msg3-resent PEER)             our msg3, not yet confirmed by a frame, sent again
;;;   (:session-failed PEER)          our SessionSetup went unanswered; the session is gone
;;;   (:session-crossed PEER :kept-ours)  PEER opened to us while we opened to it; we
;;;                                   keep initiating (we have the smaller address)
;;;;   (:unsolicited SRC PHASE)        a datagram for us from a node we hold no session
;;;;                                   with (for example, an upstream error signal)
;;;;   (:session-error PEER MESSAGE)   a session message refused (forged, wrong key ...)
;;;   (:lookup-answered ORIGIN)       a LookupRequest for us was answered
;;;   (:lookup-forwarded TARGET N)    a LookupRequest was passed on to N peers
;;;   (:lookup-ok TARGET COORDS MTU)  our lookup was answered, the proof verified
;;;   (:lookup-failed TARGET)         our lookup ran out of attempts
;;;   (:lookup-dropped REASON)        a lookup message not acted on

(in-package #:cl-fips)

(defconstant +node-heartbeat-ms+ 5000)
(defconstant +disconnect-msg-type+ #x50
  "proto/link.rs Disconnect: [0x50][reason], reason 0 shutdown, 1 restart, ...
   (fmp/wire.rs DisconnectReason).  Authenticated like any link frame.")
(defconstant +fsp-setup-resend-ms+ 4000)
(defconstant +fsp-setup-max-tries+ 10)
(defconstant +restart-quiet-ms+ 15000
  "EPOCH_RESTART_MIN_INTERVAL_SECS: a msg1 under a new epoch from a peer we hold a
   link with replaces that link only once the link has been quiet this long.  The
   msg1 is authentic but may be a replay; a peer that is really alive keeps the
   link busy, so a replay cannot tear down a working peering.  A peer that really
   restarted stops talking, and its msg1 resends (1, 3, 7, 15 s) land past this.")
(defconstant +link-dead-ms+ 30000
  "link_dead_timeout_secs: a link we have heard nothing authentic on for this long
   is removed.  On TCP the peer's close usually comes first; on UDP this is the only
   way to learn that a peer has gone.")
(defconstant +fsp-data-overhead+ 110
  "Bytes of framing around a DataPacket's data on a stream link: the FMP header
   and tag, the inner timestamp, the SessionDatagram header, the FSP header and
   tag, and the inner and port headers.  Measured against a real node.")

(define-condition node-error (error)
  ((reason :initarg :reason :reader node-error-reason)
   (detail :initarg :detail :initform nil :reader node-error-detail))
  (:report (lambda (c s) (format s "node: ~(~a~)~@[: ~a~]" (node-error-reason c) (node-error-detail c)))))

(defstruct (fips-node (:constructor %make-fips-node (static own tree)))
  static own tree
  (links '())                                   ; stream links, oldest first
  (sessions (make-hash-table :test 'equalp))    ; peer node_addr -> FSP-INITIATOR
  (heartbeat-due (make-hash-table :test 'eq))   ; link -> ms
  (last-heard (make-hash-table :test 'eq))      ; link -> ms of its last authentic packet
  (dead-ms +link-dead-ms+)                      ; NIL: never reap a silent link
  (auto-rekey t)                                ; NIL: rekey sessions only when asked
  (forwarded 0) (no-route 0) (ttl-expired 0) (too-big 0) (malformed 0)
  ;; coordinate discovery (lookup.lisp)
  (lookup-recent (make-hash-table))                    ; request_id -> (link ms forwarded)
  (lookup-pending (make-hash-table :test 'equalp))     ; target -> LOOKUP-PENDING
  (lookup-forwarded-at (make-hash-table :test 'equalp)); target -> ms of the last forward
  (lookup-signed (make-hash-table :test 'eq))          ; link -> (window-start . count)
  (setups-admitted (make-hash-table :test 'eq))        ; link -> (window-start . count)
  (coord-cache (make-hash-table :test 'equalp))        ; target -> (coords path-mtu ms)
  (peer-epochs (make-hash-table :test 'equalp)))       ; peer -> the epoch its link last came up with

(defun make-fips-node (static)
  "A node for the key pair STATIC.  Links join it with NODE-ADD-LINK, and must be
   made with :ROUTING (FIPS-NODE-TREE node) so that they share its tree."
  (%make-fips-node static
                   (node-addr (secp256k1-fast.ecdh:keypair-public-bytes static))
                   (make-tree-state (secp256k1-fast.ecdh:keypair-secret static))))

(defun node-link-peer (link)
  "The node_addr at the far end of LINK."
  (node-addr (stream-link-remote-static link)))

(defun node-filters (node)
  (mapcar (lambda (l) (cons l (stream-link-peer-filter l))) (fips-node-links node)))

(defun %node-mark-tree-dirty (node)
  (dolist (l (fips-node-links node)) (setf (stream-link-tree-dirty l) t)))

(defun node-add-link (node link)
  "LINK joins the node: the filter it sends is the node's (our address and every
   other link's reach), and its peer's announces feed the shared tree."
  ;; a link with routing shares the node's tree; one without routing has none
  (unless (member (stream-link-tree link) (list nil (fips-node-tree node)))
    (error 'node-error :reason :link-not-on-node-tree))
  (setf (stream-link-filter-source link)
        (lambda (l) (route-filter-for (fips-node-own node) (node-filters node) l)))
  (setf (fips-node-links node) (append (fips-node-links node) (list link)))
  (%node-mark-tree-dirty node)
  ;; a peer that comes back under a new epoch restarted: whatever end-to-end session
  ;; we held with it, it no longer does
  (let* ((peer (node-link-peer link))
         (epoch (stream-link-remote-epoch link))
         (known (gethash peer (fips-node-peer-epochs node))))
    (when (and known epoch (not (equalp known epoch)))
      (remhash peer (fips-node-sessions node)))
    (when epoch (setf (gethash peer (fips-node-peer-epochs node)) epoch)))
  link)

(defun node-remove-link (node link)
  "Close LINK and drop it.  Its peer leaves the tree (STREAM-LINK-CLOSE)."
  (handler-case (stream-link-close link) (error () nil))
  (setf (fips-node-links node) (remove link (fips-node-links node)))
  (remhash link (fips-node-heartbeat-due node))
  (remhash link (fips-node-last-heard node))
  (remhash link (fips-node-lookup-signed node))
  (remhash link (fips-node-setups-admitted node))
  (%node-mark-tree-dirty node))

(defun %link-failed (node link e)
  "The event for a LINK-ERROR on LINK: a fatal one (the port is closed) takes the
   link off the node."
  (if (link-error-fatal-p e)
      (progn (node-remove-link node link)
             (list :link-closed (link-error-reason e) link))
      (list :link-drop (link-error-reason e) link)))

(defun node-disconnect-all (node &key (reason 0))
  "Tell every peer we are going (Disconnect, REASON 0 = shutdown, 1 = restart) and
   drop the links.  Best effort: a peer that misses it finds out by silence."
  (dolist (l (copy-list (fips-node-links node)))
    (ignore-errors (stream-link-send l (bytes-of +disconnect-msg-type+ reason)))
    (node-remove-link node l)))

(defun node-route (node dest &optional from-link)
  "The link toward DEST: the link whose peer is DEST, else the first other link
   whose peer filter may reach DEST.  NIL if none."
  (or (find-if (lambda (l) (and (not (eq l from-link)) (equalp (node-link-peer l) dest)))
               (fips-node-links node))
      (route-next-hop (node-filters node) from-link dest)))

(defun node-session (node peer) (gethash peer (fips-node-sessions node)))

(defun node-our-coords (node)
  "Our ancestry as addresses, root last, or just our address before the tree has
   computed one."
  (let ((entries (tree-state-entries (fips-node-tree node))))
    (if entries (mapcar #'coord-entry-node entries) (list (fips-node-own node)))))

(defun node-peer-coords (node peer)
  "PEER's ancestry if it is a tree peer whose announce we hold, else NIL."
  (let ((held (gethash peer (tree-state-peers (fips-node-tree node)))))
    (and held (mapcar #'coord-entry-node (cdr held)))))

(defun %node-send (node link-message &key via)
  "Send a SessionDatagram link message toward its destination, or out of VIA."
  (let* ((dest (sd-dest (subseq link-message 1)))
         (link (or via (node-route node dest))))
    (unless link (error 'node-error :reason :no-route :detail "no link reaches the destination"))
    (%send-or-drop-link node link link-message)
    link))

(defun %send-or-drop-link (node link link-message)
  "STREAM-LINK-SEND, except that a fatal failure (the port is gone) takes the link
   off the node and signals NODE-ERROR :link-failed."
  (handler-case (stream-link-send link link-message)
    (link-error (e)
      (when (link-error-fatal-p e)
        (node-remove-link node link)
        (error 'node-error :reason :link-failed :detail (link-error-reason e)))
      ;; a non-fatal one (a datagram over the link MTU) is the node's error too
      (error 'node-error :reason (link-error-reason e) :detail (link-error-detail e)))))

;;; --- sessions we open -----------------------------------------------------------

(defun node-open-session (node peer-static &key peer-coords via (now 0))
  "Open an FSP session with the node whose public key is PEER-STATIC (33 bytes).
   PEER-COORDS defaults to its ancestry if it is a tree peer, else (PEER): a node
   on the way learns the destination's coordinates from this SessionSetup.  VIA
   forces the first hop.  Returns (values session :sent), or (values session
   :queued) when no link reaches the peer yet; the tick resends it."
  (let* ((peer (node-addr peer-static))
         (fi (make-fsp-initiator (fips-node-static node) peer-static (natrium:random-bytes 8)
                                 (fips-node-own node) peer (node-our-coords node)
                                 (or peer-coords (node-cached-coords node peer)
                                     (node-peer-coords node peer) (list peer)))))
    (setf (gethash peer (fips-node-sessions node)) fi)
    ;; with no route yet (a relay's filter that has not reached us), the session is
    ;; kept: NODE-TICK resends its SessionSetup once a link reaches the peer
    (let ((setup (fsp-setup-datagram fi now)))
      (handler-case (progn (%node-send node setup :via via) (values fi :sent))
        (node-error () (values fi :queued))))))

(defun node-send-data (node peer data &key (src-port 0) (dst-port +fsp-port-ipv6-shim+) (now 0))
  "Send DATA to PEER on our established session.  Signals NODE-ERROR :too-big if
   it would not fit the outgoing link's MTU.  Returns T if this frame cut over a
   rekey we started."
  (let ((fi (node-session node peer)))
    (unless (and fi (eq (fsp-initiator-phase fi) :established))
      (error 'node-error :reason :no-session))
    (let ((link (node-route node peer)))
      (unless link (error 'node-error :reason :no-route))
      (let ((limit (- (stream-link-mtu link) +fsp-data-overhead+)))
        (when (> (length data) limit)
          (error 'node-error :reason :too-big
                             :detail (format nil "~d bytes over the ~d-byte limit" (length data) limit))))
      (let* ((cutting (fsp-initiator-rekey-initiator-p fi))
             (d (fsp-data-datagram fi data :src-port src-port :dst-port dst-port
                                           :timestamp-ms (ldb (byte 32 0) now) :now now)))
        (%send-or-drop-link node link d)
        (and cutting (not (fsp-initiator-rekey-initiator-p fi)))))))

(defun node-start-rekey (node peer &key (now 0))
  "Start a rekey of our session with PEER."
  (let ((fi (node-session node peer)))
    (unless fi (error 'node-error :reason :no-session))
    (%node-send node (fsp-start-rekey fi :now now))))

;;; --- the tick --------------------------------------------------------------------

(defun node-tick (node now)
  "Heartbeats, each link's poll (rekey, MMP, routing announces), and resends of
   unanswered SessionSetups.  Returns events."
  (let ((events '()))
    ;; a link silent for the dead timeout is gone (its first tick starts its clock)
    (dolist (link (fips-node-links node))
      (let ((heard (or (gethash link (fips-node-last-heard node))
                       (setf (gethash link (fips-node-last-heard node)) now))))
        (when (and (fips-node-dead-ms node) (> (- now heard) (fips-node-dead-ms node)))
          (node-remove-link node link)
          (push (list :link-closed :dead link) events))))
    (dolist (link (copy-list (fips-node-links node)))
      (let ((due (gethash link (fips-node-heartbeat-due node) 0)))
        (when (>= now due)
          (handler-case (stream-link-send link (make-array 1 :element-type '(unsigned-byte 8)
                                                             :initial-element #x51))
            (link-error (e) (push (%link-failed node link e) events)))
          (setf (gethash link (fips-node-heartbeat-due node)) (+ now +node-heartbeat-ms+))))
      (when (member link (fips-node-links node))
        (handler-case
            (dolist (a (stream-link-poll link))
              (push (list :link-action a link) events))
          (link-error (e) (push (%link-failed node link e) events)))))
    ;; a session a peer opened but never completed is dropped after the handshake timeout
    (let ((stale '()))
      (maphash (lambda (peer fi)
                 (when (or (and (member (fsp-initiator-phase fi) '(:ack-sent :refused))
                                (> (- now (fsp-initiator-setup-sent-at fi)) +fsp-handshake-timeout-ms+))
                           ;; ours, every resend spent and the last one unanswered
                           (and (eq (fsp-initiator-phase fi) :setup-sent)
                                (>= (fsp-initiator-setup-tries fi) +fsp-setup-max-tries+)
                                (> (- now (fsp-initiator-setup-sent-at fi)) +fsp-setup-resend-ms+)))
                   (push peer stale)))
               (fips-node-sessions node))
      (dolist (peer stale)
        (when (eq (fsp-initiator-phase (node-session node peer)) :setup-sent)
          (push (list :session-failed peer) events))
        (remhash peer (fips-node-sessions node))))
    (setf events (append (reverse (node-lookup-tick node now)) events))
    ;; the session rekey schedule (rekey.rs check_session_rekey)
    (let ((due '()))
      (maphash (lambda (peer fi)
                 (when (fsp-cutover-due-p fi now)
                   (fsp-cut-over-if-ours fi now)
                   ;; with no data going out, the peer would never see the new
                   ;; epoch: send a frame under it (upstream's session reports do)
                   (handler-case (%node-send node (fsp-warmup-datagram fi now))
                     (node-error () nil))
                   (push (list :cutover peer :ours) events))
                 (when (and (fips-node-auto-rekey node) (fsp-rekey-due-p fi now)) (push peer due)))
               (fips-node-sessions node))
      (dolist (peer due)
        (handler-case (progn (node-start-rekey node peer :now now)
                             (push (list :rekey-started peer) events))
          (error () nil))))
    (maphash (lambda (peer fi)
               (let ((again (fsp-resend-msg3 fi now)))
                 (when again
                   (handler-case (progn (%node-send node again) (push (list :msg3-resent peer) events))
                     (node-error () nil)))))
             (fips-node-sessions node))
    (maphash (lambda (peer fi)
               (let ((again (fsp-resend-setup fi now :interval-ms +fsp-setup-resend-ms+
                                                     :max-tries +fsp-setup-max-tries+)))
                 (when again
                   (handler-case (progn (%node-send node again) (push (list :setup-resent peer) events))
                     (node-error () nil)))))
             (fips-node-sessions node))
    (nreverse events)))

;;; --- receiving -----------------------------------------------------------------

(defun node-receive (node link &key (timeout-ms 2000) (now 0))
  "Read one packet from LINK and act on it.  Returns events."
  (handler-case
      (multiple-value-bind (m ev flags counter slot) (stream-link-receive link :timeout-ms timeout-ms)
        (declare (ignore flags counter))
        ;; anything that authenticated (a frame, or a handshake packet the link
        ;; took) shows the peer is alive; a dropped packet does not
        (setf (gethash link (fips-node-last-heard node)) now)
        (cond
          ((null m) (list (list :link-event ev link)))
          ((zerop (length m)) nil)
          (t
           ;; the peer says it is going: the link and our sessions with it go now, as
           ;; upstream's remove_active_peer does, so a restart re-peers at once
           (when (= (aref m 0) +disconnect-msg-type+)
             (let ((peer (node-link-peer link)))
               (node-remove-link node link)
               (remhash peer (fips-node-sessions node))
               (return-from node-receive
                 (list (list :link-closed :disconnect link nil
                             (if (> (length m) 1) (aref m 1) #xff))))))
           (when (member (aref m 0) (list +tree-announce-msg-type+ +filter-announce-msg-type+))
             ;; the tree and the filters are the node's: every link re-announces
             (%node-mark-tree-dirty node))
           (cons (list :frame (aref m 0) link slot)
                 (case (aref m 0)
                   (#.+session-datagram-msg-type+ (node-datagram node link (subseq m 1) now))
                   (#.+lookup-request-msg-type+ (node-lookup-request node link (subseq m 1) now))
                   (#.+lookup-response-msg-type+ (node-lookup-response node link (subseq m 1) now)))))))
    (link-error (e)
      (cond
        ((link-error-fatal-p e)
         (node-remove-link node link)
         (list (list :link-closed (link-error-reason e) link)))
        ;; a msg1 under a new epoch from this link's peer: it restarted.  Once the link
        ;; has been quiet long enough, it goes, and the msg1 is handed back so the
        ;; caller can accept it as the new link.
        ((and (eq (link-error-reason e) :peer-restart)
              (>= (- now (gethash link (fips-node-last-heard node) now)) +restart-quiet-ms+))
         (node-remove-link node link)
         (list (list :link-closed :peer-restart link (link-error-packet e))))
        (t (list (list :link-drop (link-error-reason e) link)))))))

(defun node-datagram (node link body now)
  "A SessionDatagram BODY (msg_type stripped) that arrived on LINK."
  (cond
    ((not (sd-body-valid-p body))
     (incf (fips-node-malformed node))
     (list (list :dropped :malformed nil)))
    ((equalp (sd-dest body) (fips-node-own node))
     (node-local node link body now))
    (t (node-forward node link body))))

(defun node-forward (node link body)
  "Forward a datagram that is not for us: TTL down, path_mtu capped at the
   outgoing link's MTU."
  (let* ((dest (sd-dest body))
         (target (node-route node dest link)))
    (cond
      ((null target)
       (incf (fips-node-no-route node))
       (list (list :dropped :no-route dest)))
      (t
       (let ((out (sd-forward-header body (stream-link-mtu target))))
         (cond
           ((null out)
            (incf (fips-node-ttl-expired node))
            (list (list :dropped :ttl dest)))
           (t
            (handler-case
                (progn
                  (stream-link-send target (concatenate '(vector (unsigned-byte 8))
                                                        (vector +session-datagram-msg-type+) out))
                  (incf (fips-node-forwarded node))
                  (list (list :forwarded dest (sd-ttl out) target)))
              (link-error (e)
                (if (link-error-fatal-p e)
                    (list (list :dropped :link-failed dest) (%link-failed node target e))
                    (progn (incf (fips-node-too-big node))
                           (list (list :dropped (link-error-reason e) dest)))))))))))))

(defconstant +setups-per-second+ 20
  "New sessions a link's peer may ask us to answer each second: each costs a
   handshake's work and a table entry before its source is authenticated.")

(defun node-local (node link body now)
  "A datagram for us: hand it to the session with its source."
  (let* ((src (sd-src body))
         (fi (node-session node src))
         (payload (bytes-slice body 35))
         (phase (and (>= (length payload) 4) (prefix-phase payload))))
    (when (and (eql phase 1) fi (eq (fsp-initiator-phase fi) :ack-sent))
      ;; a resend of the setup we answered gets the same ack; any other setup under
      ;; this source waits until that handshake ends (the source is not yet
      ;; authenticated, so it must not displace it)
      (return-from node-local
        (if (equalp (fsp-setup-digest body) (fsp-initiator-setup-digest fi))
            (handler-case (progn (%node-send node (fsp-initiator-ack-datagram fi))
                                 (list (list :accept-answered src)))
              (node-error (e) (list (list :session-error src (princ-to-string e)))))
            (list (list :session-error src "a handshake with this source is in progress")))))
    (when (and (eql phase 1) fi (eq (fsp-initiator-phase fi) :setup-sent))
      ;; both sides opened at once: the smaller node_addr stays initiator, the other
      ;; answers (session.rs initiation_winner)
      (if (bytes< (fips-node-own node) src)
          (return-from node-local (list (list :session-crossed src :kept-ours)))
          (setf fi nil)))
    (if (and (eql phase 1) (or (null fi) (eq (fsp-initiator-phase fi) :refused)))
        ;; a session the peer opens: we answer as responder
        (if (not (%rate-ok-p (fips-node-setups-admitted node) link now +setups-per-second+))
            (list (list :session-error src "setup rate limit for this link"))
        (handler-case
            (multiple-value-bind (new ack)
                (fsp-accept-setup (fips-node-static node) (natrium:random-bytes 8) (fips-node-own node)
                                  (node-our-coords node) body :now now)
              (setf (gethash src (fips-node-sessions node)) new)
              (%node-send node ack)
              (list (list :accept-answered src)))
          (error (e) (list (list :session-error src (princ-to-string e))))))
    (if (null fi)
        (list (list :unsolicited src phase))
        (handler-case
            (cond
              ((and (eql phase 3) (eq (fsp-initiator-phase fi) :ack-sent))
               (fsp-complete-accept fi body :now now)
               (list (list :accepted src)))
              ((not (member (fsp-initiator-phase fi) '(:setup-sent :established)))
               (list (list :unsolicited src phase)))
              ((and (eql phase 2) (eq (fsp-initiator-phase fi) :setup-sent))
               (%node-send node (fsp-handle-ack fi body :now now))
               (list (list :established src)))
              ((and (eql phase 2) (fsp-initiator-rekey-hs fi))
               (%node-send node (fsp-handle-rekey-ack fi body :now now))
               (list (list :rekey-ack src)))
              ((eql phase 1)
               (%node-send node (fsp-handle-rekey-setup fi body :now now))
               (list (list :rekey-answered src)))
              ((eql phase 3)
               (list (list :rekey-msg3 src (fsp-handle-rekey-msg3 fi body :now now))))
              ((eql phase 0)
               (let ((had-pending (fsp-initiator-pending-session fi)))
                 (multiple-value-bind (mt sp dp data ts) (fsp-open-any fi payload :now now)
                   (append
                    (when (and had-pending (null (fsp-initiator-pending-session fi)))
                      (list (list :cutover src :theirs)))
                    (if (eql mt +fsp-data-packet-msg-type+)
                        (list (list :data src sp dp data ts))
                        (list (list :session-frame src mt)))))))
              (t (list (list :unsolicited src phase))))
          (error (e) (list (list :session-error src (princ-to-string e)))))))))

;;; --- coordinate discovery ----------------------------------------------------------

(defstruct lookup-pending key (attempt 1) sent-at (ids '()))

(defun node-cached-coords (node target)
  "TARGET's coordinates from a verified LookupResponse, or NIL."
  (first (gethash target (fips-node-coord-cache node))))

(defun node-tree-peer-p (node addr)
  "ADDR is our parent, or a peer whose declared parent is us (core.rs is_tree_peer)."
  (let* ((tree (fips-node-tree node))
         (entries (tree-state-entries tree))
         (held (gethash addr (tree-state-peers tree))))
    (or (and (second entries) (equalp (coord-entry-node (second entries)) addr))
        (and held (equalp (parent-declaration-parent (car held)) (fips-node-own node))
             (not (equalp addr (fips-node-own node)))))))

(defun %links-reaching (node target from-link)
  "Links other than FROM-LINK whose peer is TARGET or whose filter may reach it,
   tree peers first: (values tree-links other-links)."
  (let ((tree '()) (other '()))
    (dolist (l (fips-node-links node))
      (unless (eq l from-link)
        (let ((peer (node-link-peer l)) (f (stream-link-peer-filter l)))
          (when (or (equalp peer target) (and f (bloom-contains-p f target)))
            (if (node-tree-peer-p node peer) (push l tree) (push l other))))))
    (values (nreverse tree) (nreverse other))))

(defun %lookup-send (node links bytes)
  (count-if (lambda (l)
              (handler-case (progn (stream-link-send l bytes) t)
                (link-error (e) (when (link-error-fatal-p e) (node-remove-link node l)) nil)))
            links))

(defun %lookup-attempt (node target pending now)
  (let* ((id (decode-u64le (natrium:random-bytes 8) 0))
         (req (make-lookup-request id target (fips-node-own node) (node-our-coords node))))
    (push id (lookup-pending-ids pending))
    (setf (lookup-pending-sent-at pending) now)
    ;; plan_initiate: tree peers whose filter may reach the target, no fallback
    (%lookup-send node (%links-reaching node target nil) (encode-lookup-request req))))

(defun node-lookup (node target-key &key (now 0))
  "Ask the mesh for the coordinates of the node whose key is TARGET-KEY (33 or 32
   bytes; the key verifies the answer).  Returns the number of peers asked; with
   none, the attempt still counts and the tick retries.  A lookup already pending
   is left alone.  The answer is a (:lookup-ok ...) event, and its coordinates are
   used by NODE-OPEN-SESSION from then on."
  (let ((target (node-addr target-key)))
    (unless (gethash target (fips-node-lookup-pending node))
      (let ((p (make-lookup-pending :key (if (= (length target-key) 33) (subseq target-key 1) target-key))))
        (setf (gethash target (fips-node-lookup-pending node)) p)
        (%lookup-attempt node target p now)))))

(defun node-lookup-tick (node now)
  "Retry pending lookups on the attempt schedule; expire old request records.
   Returns events."
  (let ((events '()) (done '()))
    (maphash (lambda (target p)
               (let ((wait (nth (1- (lookup-pending-attempt p)) *lookup-attempt-ms*)))
                 (when (>= (- now (lookup-pending-sent-at p)) wait)
                   (if (>= (lookup-pending-attempt p) (length *lookup-attempt-ms*))
                       (progn (push target done) (push (list :lookup-failed target) events))
                       (progn (incf (lookup-pending-attempt p))
                              (%lookup-attempt node target p now))))))
             (fips-node-lookup-pending node))
    (dolist (target done) (remhash target (fips-node-lookup-pending node)))
    (%lookup-purge node now)
    (nreverse events)))

(defun %lookup-purge (node now)
  (let ((old '()) (quiet '()))
    (maphash (lambda (id rec) (when (> (- now (second rec)) +lookup-recent-expiry-ms+) (push id old)))
             (fips-node-lookup-recent node))
    (dolist (id old) (remhash id (fips-node-lookup-recent node)))
    ;; the per-target forward limiter only needs entries inside its interval
    (maphash (lambda (target at) (when (>= (- now at) +lookup-forward-interval-ms+) (push target quiet)))
             (fips-node-lookup-forwarded-at node))
    (dolist (target quiet) (remhash target (fips-node-lookup-forwarded-at node)))))

(defconstant +lookup-recent-max+ 4096)

(defun %lookup-make-room (node link)
  "The request table is full: evict one entry, charged to whoever filled it (core.rs
   make_room).  The arriving link's oldest entry goes if that link holds at least
   its share; otherwise the oldest entry of the link holding the most."
  (let ((counts (make-hash-table :test 'eq)) (oldest (make-hash-table :test 'eq)))
    (maphash (lambda (id rec)
               (let ((l (first rec)))
                 (incf (gethash l counts 0))
                 (let ((o (gethash l oldest)))
                   (when (or (null o) (< (second rec) (second (gethash o (fips-node-lookup-recent node)))))
                     (setf (gethash l oldest) id)))))
             (fips-node-lookup-recent node))
    (let* ((share (max 1 (floor +lookup-recent-max+ (max 1 (length (fips-node-links node))))))
           (victim (if (>= (gethash link counts 0) share)
                       link
                       (let ((best nil) (n -1))
                         (maphash (lambda (l c) (when (> c n) (setf best l n c))) counts)
                         best))))
      (when victim (remhash (gethash victim oldest) (fips-node-lookup-recent node))))))

(defun %rate-ok-p (table key now limit)
  "At most LIMIT events a second for KEY, counted in TABLE."
  (let ((w (gethash key table)))
    (when (or (null w) (>= (- now (car w)) 1000))
      (setf w (cons now 0) (gethash key table) w))
    (when (< (cdr w) limit) (incf (cdr w)) t)))

(defun %may-sign-p (node link now)
  "At most 10 lookup proofs a second for each link (the discovery signing budget)."
  (%rate-ok-p (fips-node-lookup-signed node) link now 10))


(defun node-lookup-request (node link body now)
  "A LookupRequest from LINK's peer: answer it if it names us, else pass it on."
  (let ((req (handler-case (decode-lookup-request body) (error () nil))))
    (cond
      ((null req) (list (list :lookup-dropped :malformed)))
      (t
       (%lookup-purge node now)
       (let ((id (lookup-request-request-id req))
             (target (lookup-request-target req)))
         (cond
           ((gethash id (fips-node-lookup-recent node)) (list (list :lookup-dropped :duplicate)))
           ((let ((p (gethash target (fips-node-lookup-pending node))))
              (and p (member id (lookup-pending-ids p))))
            (list (list :lookup-dropped :own-request)))
           (t
            (when (>= (hash-table-count (fips-node-lookup-recent node)) +lookup-recent-max+)
              (%lookup-make-room node link))
            (setf (gethash id (fips-node-lookup-recent node)) (list link now nil))
            (cond
              ((equalp target (fips-node-own node))
               (if (not (%may-sign-p node link now))
                   (list (list :lookup-dropped :sign-budget))
                   (let* ((coords (node-our-coords node))
                          (resp (make-lookup-response
                                 id target coords
                                 (sign-lookup-proof (tree-state-privkey (fips-node-tree node)) id target coords)
                                 :path-mtu (min #xffff (stream-link-mtu link)))))
                     (%lookup-send node (list link) (encode-lookup-response resp))
                     (list (list :lookup-answered (lookup-request-origin req))))))
              ((zerop (lookup-request-ttl req)) (list (list :lookup-dropped :ttl)))
              ((let ((at (gethash target (fips-node-lookup-forwarded-at node))))
                 (and at (< (- now at) +lookup-forward-interval-ms+)))
               (list (list :lookup-dropped :rate-limited)))
              (t
               (setf (gethash target (fips-node-lookup-forwarded-at node)) now)
               (decf (lookup-request-ttl req))
               (multiple-value-bind (tree other) (%links-reaching node target link)
                 (let ((n (%lookup-send node (or tree other) (encode-lookup-request req))))
                   (list (list :lookup-forwarded target n)))))))))))))

(defun node-lookup-response (node link body now)
  "A LookupResponse: ours (verify, cache), or one to pass back along its request's path."
  (declare (ignore link))
  (let ((resp (handler-case (decode-lookup-response body) (error () nil))))
    (if (null resp)
        (list (list :lookup-dropped :malformed))
        (let* ((id (lookup-response-request-id resp))
               (target (lookup-response-target resp))
               (pending (gethash target (fips-node-lookup-pending node)))
               (recent (gethash id (fips-node-lookup-recent node))))
          (cond
            ((and pending (member id (lookup-pending-ids pending)))
             (if (verify-lookup-response resp (lookup-pending-key pending))
                 (progn
                   (remhash target (fips-node-lookup-pending node))
                   (setf (gethash target (fips-node-coord-cache node))
                         (list (lookup-response-target-coords resp) (lookup-response-path-mtu resp) now))
                   (list (list :lookup-ok target (lookup-response-target-coords resp)
                               (lookup-response-path-mtu resp))))
                 (list (list :lookup-dropped :bad-proof))))
            ((null recent) (list (list :lookup-dropped :unsolicited)))
            ((third recent) (list (list :lookup-dropped :already-forwarded)))
            ((not (member (first recent) (fips-node-links node)))
             (list (list :lookup-dropped :no-route)))
            (t
             (setf (third recent) t)
             (setf (lookup-response-path-mtu resp)
                   (min (lookup-response-path-mtu resp) (stream-link-mtu (first recent))))
             (%lookup-send node (list (first recent)) (encode-lookup-response resp))
             (list (list :lookup-response-forwarded target))))))))
