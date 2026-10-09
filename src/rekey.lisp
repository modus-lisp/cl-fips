;;;; rekey.lisp -- FMP link rekey and key epochs, as a pure state machine.
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510, the CODE, which disagrees with
;;;; the design doc in places (each noted where it matters):
;;;;
;;;;   proto/fmp/core.rs      Fmp::poll_rekey (the per-tick decision),
;;;;                          establish_inbound (classifying a msg1 from an
;;;;                          established peer), cross_connection_winner,
;;;;                          REKEY_MIN_LINK_AGE_SECS, REKEY_MIN_CUTOVER_AGE_SECS,
;;;;                          AnsweredMsg1s / ENDED_MSG1_RECORD
;;;;   node/handlers/rekey.rs check_rekey, initiate_rekey, DRAIN_WINDOW_SECS,
;;;;                          REKEY_DAMPENING_SECS, pending_hold
;;;;   node/handlers/handshake.rs  the RekeyRespond arm (msg2 answer) and the
;;;;                          rekey-msg2 arm (complete_rekey_msg2 + set_pending)
;;;;   peer/active.rs         cutover_to_new_session, handle_peer_kbit_flip,
;;;;                          adopt_pending, complete_drain, retire_pending,
;;;;                          abandon_rekey, set_rekey_state, complete_rekey_msg2
;;;;   node/dataplane/encrypted.rs  handle_encrypted_frame: pending trial,
;;;;                          then current, then previous
;;;;   node/mod.rs            the send path: K flag = current_k_bit, receiver
;;;;                          index = their_index, timestamp = session-relative
;;;;   proto/fmp/wire.rs      build_msg1 / build_msg2, Msg1Header / Msg2Header
;;;;
;;;; What the code does, in the order it happens:
;;;;
;;;;  * TRIGGER (poll_rekey).  Session age >= after_secs + jitter, or the
;;;;    current session's send counter >= after_messages.  Vetoed while a rekey
;;;;    is in flight, while dampened (a peer msg1 was answered < 30 s ago), and
;;;;    while any pending session is held.
;;;;  * MSG1/MSG2 ARE NOT ENCRYPTED FRAMES.  initiate_rekey sends
;;;;    build_msg1(new_index, noise_msg1) -- the ordinary phase-0x1 bootstrap
;;;;    packet, in the clear -- "on the existing link (same transport +
;;;;    address)"; the responder answers with a phase-0x2 build_msg2.  The design
;;;;    doc says they "travel over the existing link as ordinary encrypted FMP
;;;;    frames"; the code does not do that.
;;;;  * A msg1 from an established peer is a REKEY only if the link is >= 30 s
;;;;    old and the session >= 10 s old (and the epoch is unchanged).  Then:
;;;;    a held pending -> resend the same msg2 for the same msg1, else refuse;
;;;;    a msg1 of an ended cycle -> refuse; our own rekey in flight -> the
;;;;    smaller NodeAddr keeps the initiator role and refuses, the larger
;;;;    abandons its own and answers.  Answering completes any drain first,
;;;;    allocates a NEW index, holds the new session as PENDING (role responder)
;;;;    and stamps the dampener.
;;;;  * The initiator reads msg2 with the ROLLING-BACK read (a forged msg2 keeps
;;;;    the cycle), holds the session as pending (role initiator), and the NEXT
;;;;    TICK cuts over: current -> previous (drain starts), pending -> current,
;;;;    K = NOT K (a TOGGLE, not a mark: the second rekey's frames carry K=0),
;;;;    session age, frame-timestamp base and jitter reset.
;;;;  * The responder tries a frame on its pending session when the frame's K
;;;;    differs from its own OR the frame names the pending index; only a frame
;;;;    that AUTHENTICATES there promotes it, and the responder then takes the
;;;;    frame's K (not a toggle of its own).  The bit alone never promotes.
;;;;  * New sessions start their nonce counter at 0 and a fresh replay window:
;;;;    the counter restarts at every cutover.
;;;;  * DRAIN: the previous session decrypts (after current fails) until a tick
;;;;    finds 10 whole seconds since the cutover, which drops it and its index.
;;;;  * A responder pending the initiator never adopts is retired at the hold:
;;;;    max(drain ceiling 120 s, link silence 64 s) = 120 s at stock settings.
;;;;
;;;; Pure: no clock is read.  Every entry point takes NOW-MS; the send counter is
;;;; the session's own; indices come from the caller's ALLOCATE-INDEX; jitter
;;;; from JITTER-FN (upstream draws uniform [-15, 15] s at each cutover).
;;;;
;;;; Not modelled: msg1 retransmission and its abandon budget, the silent-session
;;;; backoff, multiple transports / off-link msg1s, restart re-promotion, and the
;;;; FSP (session-layer, XK) rekey, which follows a parallel design.

(in-package #:cl-fips)

(defconstant +drain-window-secs+ 10 "node/handlers/rekey.rs DRAIN_WINDOW_SECS.")
(defconstant +rekey-dampening-secs+ 30 "node/handlers/rekey.rs REKEY_DAMPENING_SECS.")
(defconstant +rekey-min-link-age-secs+ 30 "proto/fmp/core.rs REKEY_MIN_LINK_AGE_SECS.")
(defconstant +rekey-min-cutover-age-secs+ 10 "proto/fmp/core.rs REKEY_MIN_CUTOVER_AGE_SECS.")
(defconstant +rekey-jitter-secs+ 15 "node/mod.rs REKEY_JITTER_SECS.")
(defconstant +ended-msg1-record+ 256 "proto/fmp/core.rs ENDED_MSG1_RECORD.")
(defconstant +msg1-wire-size+ 114)
(defconstant +setup-resend-window-ms+ 30000
  "handshake_timeout_secs: how long a resend of the establishing msg1 is answered.")
(defconstant +msg2-wire-size+ 69)

(defstruct rekey-config
  "node.rekey.* and the derived responder hold.  PENDING-HOLD-MS is upstream's
   pending_hold at stock settings: max(drain ceiling = 12 * 10 s = 120 s, and
   the msg3 recovery budget 31 + 30 + 30 = 91 s; link silence = resend ladder
   31 s + 3 ticks + max(heartbeat 10, link-dead 30) = 64 s) = 120 s."
  (enabled t)
  (after-secs 120)
  (after-messages 65536)
  (pending-hold-ms 120000))

;;; --- wire.rs: msg1 / msg2 packets --------------------------------------------------

(defun build-msg1 (sender-idx noise-msg1)
  "[0x01][0x00][payload_len = 4 + |noise| LE][sender_idx LE][noise_msg1]."
  (let ((out (u8-vector (+ 8 (length noise-msg1)))))
    (replace out (encode-prefix 0 +phase-msg1+ 0 (+ 4 (length noise-msg1))))
    (replace out (encode-u32le sender-idx) :start1 4)
    (replace out noise-msg1 :start1 8)
    out))

(defun build-msg2 (sender-idx receiver-idx noise-msg2)
  "[0x02][0x00][payload_len LE][sender_idx LE][receiver_idx LE][noise_msg2]."
  (let ((out (u8-vector (+ 12 (length noise-msg2)))))
    (replace out (encode-prefix 0 +phase-msg2+ 0 (+ 8 (length noise-msg2))))
    (replace out (encode-u32le sender-idx) :start1 4)
    (replace out (encode-u32le receiver-idx) :start1 8)
    (replace out noise-msg2 :start1 12)
    out))

(defun parse-msg1 (wire)
  "Msg1Header::parse: exact size, version 0, phase 1, flags 0.
   Returns (values sender-idx noise-msg1) or NIL."
  (when (and (= (length wire) +msg1-wire-size+)
             (= (prefix-version wire) 0) (= (prefix-phase wire) +phase-msg1+)
             (zerop (aref wire 1)))
    (values (decode-u32le wire 4) (subseq wire 8))))

(defun parse-msg2 (wire)
  "Msg2Header::parse.  Returns (values sender-idx receiver-idx noise-msg2) or NIL."
  (when (and (= (length wire) +msg2-wire-size+)
             (= (prefix-version wire) 0) (= (prefix-phase wire) +phase-msg2+)
             (zerop (aref wire 1)))
    (values (decode-u32le wire 4) (decode-u32le wire 8) (subseq wire 12))))

;;; --- The tie-break (core.rs cross_connection_winner) --------------------------------

(defun node-addr< (a b)
  "NodeAddr's derived Ord: lexicographic over the 16 unsigned bytes."
  (loop for x across a for y across b
        when (< x y) return t
        when (> x y) return nil))

(defun rekey-tie-break-winner-p (our-addr their-addr this-is-outbound)
  "cross_connection_winner: the smaller node's outbound wins.  For a rekey race
   our own rekey is the outbound side, so a T answer means: keep ours, refuse
   theirs."
  (if (node-addr< our-addr their-addr) this-is-outbound (not this-is-outbound)))

;;; --- One peer's link state (peer/active.rs ActivePeer, the rekey half) --------------

(defstruct (fmp-link (:conc-name link-))
  (config (make-rekey-config))
  static peer-static-bytes local-epoch remote-epoch
  our-addr peer-addr
  allocate-index                 ; () -> fresh u32
  (jitter-fn (constantly 0))     ; () -> jitter secs, drawn at each cutover
  ;; current
  session our-index their-index (k-bit nil)
  session-established-at session-start link-established-at (jitter-secs 0)
  ;; previous (drain)
  previous-session previous-our-index drain-started
  ;; pending (a completed rekey not yet current)
  pending-session pending-our-index pending-their-index pending-role pending-since
  (pending-restart nil)
  ;; initiator cycle in flight
  rekey-handshake rekey-our-index rekey-msg1 (rekey-in-progress nil)
  ;; responder bookkeeping
  last-peer-rekey held-answer (ended-msg1s nil)
  ;; the responder's answer to the msg1 this link was established from, as
  ;; (digest . msg2-wire): a datagram transport can lose our msg2, and the
  ;; initiator then resends the same msg1 (handshake.rs ResendMsg2)
  (setup-answer nil))

(defun make-link (session our-index their-index &key static peer-static-bytes local-epoch
                                                    remote-epoch now-ms allocate-index
                                                    (config (make-rekey-config))
                                                    (jitter-fn (constantly 0)))
  "A link established at NOW-MS over SESSION (a natrium.noise session)."
  (make-fmp-link :config config :static static :peer-static-bytes peer-static-bytes
                 :local-epoch local-epoch :remote-epoch remote-epoch
                 :our-addr (node-addr (secp256k1-fast.ecdh:keypair-public-bytes static))
                 :peer-addr (node-addr peer-static-bytes)
                 :allocate-index allocate-index :jitter-fn jitter-fn
                 :session session :our-index our-index :their-index their-index
                 :session-established-at now-ms :session-start now-ms
                 :link-established-at now-ms :jitter-secs (funcall jitter-fn)))

(defun whole-secs (now-ms then-ms) (floor (- now-ms then-ms) 1000))

;;; --- The decision (core.rs poll_rekey), pure over a snapshot ------------------------

(defstruct rekey-snapshot
  has-pending pending-role pending-expired rekey-in-progress draining drain-expired
  dampened (elapsed-secs 0) (counter 0) (jitter-secs 0))

(defun %drain-expired-p (link now-ms)
  "active.rs drain_expired: whole seconds since the cutover >= DRAIN_WINDOW_SECS."
  (and (link-drain-started link)
       (>= (whole-secs now-ms (link-drain-started link)) +drain-window-secs+)))

(defun link-snapshot (link now-ms)
  "rekey_peer_snapshots for this link: every clock read resolved here."
  (make-rekey-snapshot
   :has-pending (and (link-pending-session link) t)
   :pending-role (link-pending-role link)
   :pending-expired (and (link-pending-since link)
                         (>= (- now-ms (link-pending-since link))
                             (rekey-config-pending-hold-ms (link-config link))))
   :rekey-in-progress (link-rekey-in-progress link)
   :draining (and (link-drain-started link) t)
   :drain-expired (%drain-expired-p link now-ms)
   :dampened (and (link-last-peer-rekey link)
                  (< (whole-secs now-ms (link-last-peer-rekey link)) +rekey-dampening-secs+))
   :elapsed-secs (whole-secs now-ms (link-session-established-at link))
   :counter (natrium.noise:session-current-send-counter (link-session link))
   :jitter-secs (link-jitter-secs link)))

(defun rekey-decide (snap config)
  "poll_rekey for one peer: a list of :CUTOVER / :DRAIN / :RETIRE / :INITIATE,
   in upstream's phase order.  Pure: reads only SNAP and CONFIG."
  (let ((initiated (eq (rekey-snapshot-pending-role snap) :initiator))
        (out '()))
    (unless (rekey-config-enabled config)          ; check_rekey returns at once
      (return-from rekey-decide nil))
    (when (and (rekey-snapshot-has-pending snap) (not (rekey-snapshot-rekey-in-progress snap))
               initiated)
      (return-from rekey-decide (list :cutover)))
    (when (and (rekey-snapshot-has-pending snap) (not initiated)
               (rekey-snapshot-pending-expired snap))
      (push :retire out))
    (when (and (rekey-snapshot-draining snap) (rekey-snapshot-drain-expired snap))
      (push :drain out))
    (unless (or (rekey-snapshot-rekey-in-progress snap) (rekey-snapshot-dampened snap)
                (rekey-snapshot-has-pending snap))
      (when (or (>= (rekey-snapshot-elapsed-secs snap)
                    (max 0 (+ (rekey-config-after-secs config) (rekey-snapshot-jitter-secs snap))))
                (>= (rekey-snapshot-counter snap) (rekey-config-after-messages config)))
        (push :initiate out)))
    ;; phase order: cutovers, drains, retirements, initiations
    (sort out #'< :key (lambda (a) (position a '(:cutover :drain :retire :initiate))))))

;;; --- The effects (active.rs) ---------------------------------------------------------

(defun %msg1-digest (wire) (natrium:sha256 (coerce wire '(simple-array (unsigned-byte 8) (*)))))

(defun %end-answer (link)
  "AnsweredMsg1s::end: the held answer's digest moves to the bounded ended list."
  (let ((held (link-held-answer link)))
    (when held
      (push (car held) (link-ended-msg1s link))
      (when (> (length (link-ended-msg1s link)) +ended-msg1-record+)
        (setf (link-ended-msg1s link) (subseq (link-ended-msg1s link) 0 +ended-msg1-record+)))
      (setf (link-held-answer link) nil))))

(defun %release-pending (link)
  ;; upstream also restarts the link age when the pending revealed a peer
  ;; restart; restart handling is not modelled
  (setf (link-pending-role link) nil (link-pending-since link) nil
        (link-pending-restart link) nil)
  (%end-answer link))

(defun %install-pending (link session our-index their-index role now-ms)
  (setf (link-pending-session link) session (link-pending-our-index link) our-index
        (link-pending-their-index link) their-index (link-pending-role link) role
        (link-pending-since link) now-ms (link-pending-restart link) nil
        (link-rekey-in-progress link) nil (link-rekey-our-index link) nil
        (link-rekey-handshake link) nil (link-rekey-msg1 link) nil))

(defun %promote-pending (link now-ms)
  "The body shared by cutover_to_new_session and handle_peer_kbit_flip: the
   current session becomes previous (the drain starts), pending becomes current."
  (let ((new (link-pending-session link))
        (new-our (link-pending-our-index link))
        (new-their (link-pending-their-index link)))
    (setf (link-pending-session link) nil (link-pending-our-index link) nil
          (link-pending-their-index link) nil)
    (%release-pending link)
    (setf (link-previous-session link) (link-session link)
          (link-previous-our-index link) (link-our-index link)
          (link-drain-started link) now-ms
          (link-session link) new (link-our-index link) new-our (link-their-index link) new-their
          (link-session-established-at link) now-ms (link-session-start link) now-ms
          (link-rekey-in-progress link) nil
          (link-jitter-secs link) (funcall (link-jitter-fn link)))
    (link-previous-our-index link)))

(defun %cutover-k-bit (old-k restarted)
  "cutover_to_new_session: flip, or 0 when the msg2 revealed a peer restart."
  (if restarted nil (not old-k)))

(defun link-cutover (link now-ms)
  "Initiator cutover (cutover_to_new_session).  Returns the old index, or NIL."
  (when (link-pending-session link)
    (let ((restarted (link-pending-restart link)))
      (prog1 (%promote-pending link now-ms)
        (setf (link-k-bit link) (%cutover-k-bit (link-k-bit link) restarted))))))

(defun link-adopt-pending (link frame-k now-ms)
  "Responder promotion (adopt_pending): take the K of the authenticated frame."
  (when (link-pending-session link)
    (prog1 (%promote-pending link now-ms)
      (setf (link-k-bit link) frame-k))))

(defun link-complete-drain (link)
  (setf (link-previous-session link) nil (link-drain-started link) nil)
  (shiftf (link-previous-our-index link) nil))

(defun link-retire-pending (link)
  "retire_pending: only a pending this node answered."
  (unless (or (eq (link-pending-role link) :initiator) (null (link-pending-session link)))
    (setf (link-pending-session link) nil (link-pending-their-index link) nil)
    (%release-pending link)
    (shiftf (link-pending-our-index link) nil)))

(defun link-abandon-rekey (link)
  "abandon_rekey: drop our cycle; returns the index it owned."
  (setf (link-rekey-handshake link) nil (link-rekey-msg1 link) nil
        (link-rekey-in-progress link) nil)
  (or (shiftf (link-rekey-our-index link) nil)
      (progn (setf (link-pending-session link) nil (link-pending-their-index link) nil)
             (%release-pending link)
             (shiftf (link-pending-our-index link) nil))))

(defun link-initiate-rekey (link &key ephemeral)
  "initiate_rekey: a fresh IK initiator toward the peer's static key, a NEW
   index, and the phase-0x1 msg1 packet to send on the link."
  (let* ((idx (funcall (link-allocate-index link)))
         (hs (fips-make-ik-initiator (link-static link) (link-peer-static-bytes link)
                                     (link-local-epoch link)))
         (wire (build-msg1 idx (natrium.noise:ik-write-message-1 hs :ephemeral ephemeral))))
    (setf (link-rekey-handshake link) hs (link-rekey-our-index link) idx
          (link-rekey-msg1 link) wire (link-rekey-in-progress link) t)
    wire))

(defun link-tick (link now-ms)
  "check_rekey for this link: decide, then perform in phase order.  Returns
   (values packets-to-send actions)."
  (let ((actions (rekey-decide (link-snapshot link now-ms) (link-config link)))
        (packets '()))
    (dolist (a actions)
      (ecase a
        (:cutover (link-cutover link now-ms))
        (:drain (link-complete-drain link))
        (:retire (link-retire-pending link))
        (:initiate (push (link-initiate-rekey link) packets))))
    (values (nreverse packets) actions)))

;;; --- Sending (node/mod.rs) ------------------------------------------------------------

(defun link-send (link link-message now-ms &key (flags 0))
  "An established frame on the CURRENT session, to their index, K = our K."
  (fmp-seal-frame (link-session link) (link-their-index link)
                  (ldb (byte 32 0) (- now-ms (link-session-start link)))
                  link-message
                  :flags (if (link-k-bit link) (logior flags +flag-key-epoch+) flags)))

;;; --- Receiving ------------------------------------------------------------------------

(defun %index-known-p (link idx)
  "peers_by_index: current, the draining previous, and the registered pending."
  (or (eql idx (link-our-index link))
      (and (link-previous-session link) (eql idx (link-previous-our-index link)))
      (and (link-pending-session link) (eql idx (link-pending-our-index link)))))

(defun %open-on (session counter ct header)
  (handler-case (natrium.noise:session-decrypt-with-replay-check session counter ct header)
    (natrium.noise:noise-error () nil)))

(defun %try-pending-p (link frame-k idx)
  "encrypted.rs: try pending when the K-bit differs OR the frame names it."
  (and (link-pending-session link)
       (or (not (eq frame-k (link-k-bit link)))
           (eql idx (link-pending-our-index link)))))

(defun %receive-frame (link wire now-ms)
  (unless (and (>= (length wire) (+ +fmp-established-header-size+ +aead-tag-size+))
               (= (prefix-version wire) 0) (= (prefix-phase wire) +phase-established+))
    (return-from %receive-frame (values :drop :malformed)))
  (multiple-value-bind (flags payload-len idx counter) (decode-fmp-established-header wire)
    (declare (ignore payload-len))
    (unless (%index-known-p link idx)
      (return-from %receive-frame (values :drop :unknown-index)))
    (let* ((header (subseq wire 0 +fmp-established-header-size+))
           (ct (subseq wire +fmp-established-header-size+))
           (frame-k (logbitp 0 flags))
           (slot nil) (pt nil))
      (when (%try-pending-p link frame-k idx)
        (setf pt (%open-on (link-pending-session link) counter ct header))
        (when pt
          (link-adopt-pending link frame-k now-ms)
          (setf slot :adopted)))
      (unless pt
        (setf pt (%open-on (link-session link) counter ct header) slot :current))
      (unless (or pt (null (link-previous-session link)))
        (setf pt (%open-on (link-previous-session link) counter ct header) slot :previous))
      (cond ((null pt) (values :drop :decrypt-failed))
            ((< (length pt) +inner-header-size+) (values :drop :inner-header-too-short))
            (t (values :frame (subseq pt 4) slot flags (decode-u32le pt 0) counter))))))

(defun %remote-identity-ok-p (link hs)
  (equalp (node-addr (secp256k1-fast.ecdh:encode-pubkey (natrium.noise:hs-remote-static hs)))
          (link-peer-addr link)))

(defun %receive-msg1 (link wire now-ms)
  "A msg1 from the established peer: the Noise step, then establish_inbound's
   same-identity arm, then the RekeyRespond effects."
  (multiple-value-bind (sender-idx noise) (parse-msg1 wire)
    (unless sender-idx (return-from %receive-msg1 (values :drop :malformed)))
    ;; a resend of the msg1 this link came from: our msg2 was lost, so answer it
    ;; again (no crypto, no state).  After the handshake window it is only a replay.
    (let ((setup (link-setup-answer link)))
      (when (and setup (equalp (car setup) (%msg1-digest wire)))
        (return-from %receive-msg1
          (if (< (- now-ms (link-link-established-at link)) +setup-resend-window-ms+)
              (values :msg2 (cdr setup))
              (values :drop :answered-before)))))
    (let ((hs (fips-make-ik-responder (link-static link) (link-local-epoch link)))
          (digest (%msg1-digest wire)))
      (unless (ignore-errors (natrium.noise:ik-read-message-1 hs noise) t)
        (return-from %receive-msg1 (values :drop :bad-msg1)))
      (unless (%remote-identity-ok-p link hs)
        (return-from %receive-msg1 (values :drop :not-this-peer)))
      (let ((msg2 (natrium.noise:ik-write-message-2 hs)))
        (cond
          ((and (link-remote-epoch link)
                (not (equalp (link-remote-epoch link) (natrium.noise:hs-remote-epoch hs))))
           (values :drop :peer-restart))
          ((not (and (rekey-config-enabled (link-config link))
                     (>= (whole-secs now-ms (link-link-established-at link))
                         +rekey-min-link-age-secs+)
                     (>= (whole-secs now-ms (link-session-established-at link))
                         +rekey-min-cutover-age-secs+)))
           (values :drop :not-a-rekey))  ; upstream: duplicate / re-establish paths
          ((link-pending-session link)
           (let ((held (link-held-answer link)))
             (if (and held (equalp (car held) digest))
                 (values :msg2 (cdr held))
                 (values :drop :pending-session))))
          ((member digest (link-ended-msg1s link) :test #'equalp)
           (values :drop :answered-before))
          ((and (link-rekey-in-progress link)
                (rekey-tie-break-winner-p (link-our-addr link) (link-peer-addr link) t))
           (values :drop :dual-rekey-won))
          (t
           (when (link-rekey-in-progress link) (link-abandon-rekey link))
           (when (link-drain-started link) (link-complete-drain link))
           (let* ((idx (funcall (link-allocate-index link)))
                  (wire2 (build-msg2 idx sender-idx msg2)))
             (%install-pending link (natrium.noise:handshake-into-session hs) idx sender-idx
                               :responder now-ms)
             (%end-answer link)
             (setf (link-held-answer link) (cons digest wire2)
                   (link-last-peer-rekey link) now-ms)
             (values :msg2 wire2))))))))

(defun %receive-msg2 (link wire now-ms)
  (multiple-value-bind (sender-idx receiver-idx noise) (parse-msg2 wire)
    (unless sender-idx (return-from %receive-msg2 (values :drop :malformed)))
    (unless (and (link-rekey-in-progress link) (eql receiver-idx (link-rekey-our-index link)))
      (return-from %receive-msg2 (values :drop :unknown-index)))
    (let ((hs (link-rekey-handshake link)))
      ;; complete_rekey_msg2: a msg2 that fails keeps the cycle (try_read_message_2)
      (unless (ignore-errors (natrium.noise:ik-try-read-message-2 hs noise) t)
        (return-from %receive-msg2 (values :drop :msg2-not-authentic)))
      (let ((epoch (natrium.noise:hs-remote-epoch hs))
            (restarted nil))
        (when (and (link-remote-epoch link) (not (equalp epoch (link-remote-epoch link))))
          (setf restarted t))
        (setf (link-remote-epoch link) epoch)
        (%install-pending link (natrium.noise:handshake-into-session hs)
                          (link-rekey-our-index link) sender-idx :initiator now-ms)
        (%end-answer link)                 ; set_pending_session: answered.end()
        (setf (link-pending-restart link) restarted)
        (values :rekey-complete nil)))))

(defun link-receive (link wire now-ms)
  "Dispatch one packet from the peer by phase.  Returns one of
     (values :frame link-message slot flags timestamp counter)
                                  slot = :current, :previous or :adopted (pending
                                  promoted); counter = the frame's AEAD counter
     (values :msg2 wire)          send this answer to the peer
     (values :rekey-complete nil) msg2 read; the next tick cuts over
     (values :drop reason)        upstream drops it (silently, or with a log line)"
  (if (< (length wire) 4)
      (values :drop :malformed)
      (case (prefix-phase wire)
        (#.+phase-established+ (%receive-frame link wire now-ms))
        (#.+phase-msg1+ (%receive-msg1 link wire now-ms))
        (#.+phase-msg2+ (%receive-msg2 link wire now-ms))
        (t (values :drop :unknown-phase)))))
