;;;; tree.lisp -- our spanning-tree declaration, from the peers' TreeAnnounces.
;;;;
;;;; A small, pure model of the part of upstream's stp/state.rs a node with its
;;;; peers needs in order to announce itself:
;;;;   * record each peer's latest verified declaration and ancestry, keeping only
;;;;     strictly fresher sequences (update_peer);
;;;;   * if no peer's root is smaller than our node_addr, declare ourselves a root;
;;;;     otherwise adopt the peer with the smallest visible root as parent
;;;;     (should_be_root, set_parent);
;;;;   * never adopt a peer whose ancestry already contains us (a loop);
;;;;   * our ancestry is [self] ++ parent's ancestry (recompute_coords);
;;;;   * a change of parent or role bumps the declaration sequence and stamps the
;;;;     time; a change only in the ancestry does not (the sequence names the
;;;;     declaration, not the coordinates).
;;;;
;;;; Not modelled: parent hysteresis, flap dampening, hold-down, cost-based parent
;;;; choice, and the resend budget.  Time is passed in; nothing reads a clock.

(in-package #:cl-fips)

(defstruct (tree-state (:constructor %make-tree-state (node xonly privkey)))
  node            ; our 16-byte node_addr
  xonly           ; our 32-byte x-only public key
  privkey         ; our secp256k1 secret, an integer
  (seq 0)         ; the sequence of our current declaration
  declaration     ; our current PARENT-DECLARATION (signed), or NIL before first use
  entries         ; our current ancestry (a list of COORD-ENTRY)
  (peers (make-hash-table :test 'equalp))   ; node -> (declaration . entries)
  (keys (make-hash-table :test 'equalp)))   ; node -> x-only key, from the handshake

(defun make-tree-state (privkey-int)
  (let* ((xonly (secp256k1-fast.schnorr:pubkey-xonly privkey-int))
         (node (subseq (natrium:sha256 xonly) 0 16)))
    (%make-tree-state node xonly privkey-int)))

(defun tree-root-of (entries)
  (coord-entry-node (car (last entries))))

(defun tree-observe-announce (state declaration entries)
  "Record a peer's TreeAnnounce if it verifies, is semantically valid, and is
   strictly fresher than what we hold.  Returns T when it was recorded."
  (let* ((peer (parent-declaration-node declaration))
         (xonly (gethash peer (tree-state-keys state))))
    (when (and xonly
               (not (equalp peer (tree-state-node state)))
               (verify-declaration declaration xonly)
               (validate-tree-semantics declaration entries))
      (let* ((held (gethash peer (tree-state-peers state)))
             (fresher (or (null held)
                          (> (parent-declaration-seq declaration)
                             (parent-declaration-seq (car held))))))
        (when fresher
          (setf (gethash peer (tree-state-peers state)) (cons declaration entries))
          t)))))

(defun tree-register-peer-key (state node xonly)
  "Record the x-only key of NODE, learned from the handshake.  A node_addr is
   SHA-256(key)[0..16], so the key is checked against it before it is trusted."
  (unless (equalp (subseq (natrium:sha256 xonly) 0 16) node)
    (error "key does not hash to node_addr"))
  (setf (gethash node (tree-state-keys state)) xonly))

(defun tree-peers-without-us (state)
  "Peers whose ancestry does not contain us: adopting one of them cannot loop."
  (let ((out '()))
    (maphash (lambda (peer held)
               (declare (ignore peer))
               (unless (find (tree-state-node state) (cdr held)
                             :key #'coord-entry-node :test #'equalp)
                 (push held out)))
             (tree-state-peers state))
    out))

(defun tree-recompute (state now-seconds)
  "Decide our declaration and ancestry from the peers we hold.  Re-signs and
   returns (values declaration entries changed-p) where CHANGED-P means the
   declaration (parent or role) changed and its sequence moved on."
  (let* ((me (tree-state-node state))
         (candidates (tree-peers-without-us state))
         (best (let ((b nil))
                 (dolist (c candidates b)
                   (when (or (null b)
                             (bytes< (tree-root-of (cdr c)) (tree-root-of (cdr b))))
                     (setf b c)))))
         (want-root (or (null best) (not (bytes< (tree-root-of (cdr best)) me)))))
    ;; our node_addr <= every visible root => root; ties go to the lower address
    (when (and best (equalp me (tree-root-of (cdr best))))
      (setf want-root t))
    (let* ((parent (if want-root me (parent-declaration-node (car best))))
           (current (tree-state-declaration state))
           (same (and current
                      (equalp (parent-declaration-parent current) parent)))
           (changed (not same))
           (seq (if changed (1+ (tree-state-seq state)) (tree-state-seq state)))
           (ts (if changed now-seconds (parent-declaration-ts current)))
           (decl (make-parent-declaration me parent seq ts)))
      (sign-declaration decl (tree-state-privkey state))
      (let ((entries (cons (make-coord-entry me seq ts)
                           (if want-root '() (cdr best)))))
        (setf (tree-state-seq state) seq
              (tree-state-declaration state) decl
              (tree-state-entries state) entries)
        (values decl entries changed)))))

(defun tree-current-announce (state)
  "The encoded TreeAnnounce for our current declaration, or NIL before the first
   recompute."
  (let ((decl (tree-state-declaration state)))
    (when decl
      (encode-tree-announce decl (tree-state-entries state)))))
