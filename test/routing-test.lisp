;;;; routing-test.lisp -- the spanning-tree TreeAnnounce (stp.lisp), the bloom
;;;; FilterAnnounce (bloom.lisp) and our declaration (tree.lisp).  Pure, in memory.
;;;;
;;;;   R1  bloom: bit positions match an independent SHA-256 computation (Python),
;;;;       insert/contains, union, encode/decode, and rejects of bad size_class
;;;;       and wrong lengths
;;;;   R2  TreeAnnounce: sign, encode, decode, verify, semantics -- byte layout
;;;;       offsets, and negative controls for each rule in wire.rs
;;;;   R3  two nodes: the one with the larger node_addr adopts the smaller as
;;;;       parent; the smaller stays root; a bad signature is refused; a stale
;;;;       sequence is refused

(in-package #:cl-fips.test)

(defun octets (&rest xs)
  (make-array (length xs) :element-type '(unsigned-byte 8) :initial-contents xs))

(defun ascii-octets (s)
  (map '(vector (unsigned-byte 8)) #'char-code s))

(defun octet-range (from count)
  (apply #'octets (loop for i from from below (+ from count) collect i)))

(defun test-bloom ()
  ;; SHA-256 of bytes 1..16, h1/h2 little-endian, k = 0..4, mod 8192 (computed
  ;; independently in Python: [7005, 1177, 3541, 5905, 77])
  (check "bloom bit positions match the independent computation"
         (equal (bloom-bit-indices (octet-range 1 16)) '(7005 1177 3541 5905 77)))
  (let ((f (make-bloom)) (a (octet-range 1 16)) (b (octet-range 17 16)))
    (bloom-insert f a)
    (check "bloom contains an inserted item" (bloom-contains-p f a))
    (check "bloom does not contain an uninserted item" (not (bloom-contains-p f b)))
    (let* ((msg (encode-filter-announce 7 f)))
      (check "FilterAnnounce length 1035" (= (length msg) 1035))
      (check "FilterAnnounce msg_type 0x20" (= (aref msg 0) #x20))
      (multiple-value-bind (seq filter k) (decode-filter-announce (subseq msg 1))
        (check "FilterAnnounce round trip: sequence" (= seq 7))
        (check "FilterAnnounce round trip: hash count" (= k 5))
        (check "FilterAnnounce round trip: filter" (equalp filter f)))
      ;; negative controls
      (check "size_class 2 rejected"
             (handler-case (progn (let ((b (copy-seq (subseq msg 1))))
                                    (setf (aref b 9) 2)
                                    (decode-filter-announce b))
                                  nil)
               (error () t)))
      (check "truncated FilterAnnounce rejected"
             (handler-case (progn (decode-filter-announce (subseq msg 1 1000)) nil)
               (error () t)))))
  (let ((u (bloom-union (let ((x (make-bloom))) (bloom-insert x (octet-range 1 16)) x)
                        (let ((x (make-bloom))) (bloom-insert x (octet-range 17 16)) x))))
    (check "union contains both"
           (and (bloom-contains-p u (octet-range 1 16))
                (bloom-contains-p u (octet-range 17 16))))))

(defun make-test-node (privkey)
  "Returns (values node-addr xonly) for a secp256k1 secret key."
  (let* ((xonly (secp256k1-fast.schnorr:pubkey-xonly privkey))
         (node (subseq (natrium:sha256 xonly) 0 16)))
    (values node (coerce xonly '(vector (unsigned-byte 8))))))

(defun signed-root-announce (privkey seq ts)
  (multiple-value-bind (node) (make-test-node privkey)
    (let ((d (make-parent-declaration node node seq ts)))
      (sign-declaration d privkey)
      (values d (list (make-coord-entry node seq ts))))))

(defun test-tree-announce ()
  (multiple-value-bind (decl entries) (signed-root-announce 3 1 1000)
    (let* ((msg (encode-tree-announce decl entries))
           (xonly (secp256k1-fast.schnorr:pubkey-xonly 3)))
      (check "TreeAnnounce layout: msg_type 0x10, version 1"
             (and (= (aref msg 0) #x10) (= (aref msg 1) 1)))
      (check "TreeAnnounce size: 1 + 99 + 32 entries" (= (length msg) (+ 1 99 32)))
      (check "TreeAnnounce sequence is little-endian at offset 2"
             (= (decode-u64le msg 2) 1))
      (check "TreeAnnounce count at offset 34" (= (decode-u16le msg 34) 1))
      (multiple-value-bind (d2 e2) (decode-tree-announce (subseq msg 1))
        (check "TreeAnnounce round trip: declaration"
               (and (equalp (parent-declaration-node d2) (parent-declaration-node decl))
                    (equalp (parent-declaration-parent d2) (parent-declaration-parent decl))
                    (= (parent-declaration-seq d2) 1)
                    (= (parent-declaration-ts d2) 1000)))
        (check "TreeAnnounce round trip: entries"
               (and (= (length e2) 1) (equalp (coord-entry-node (first e2))
                                              (coord-entry-node (first entries)))))
        (check "decoded TreeAnnounce verifies under the signer's key"
               (verify-declaration d2 xonly))
        (check "decoded TreeAnnounce passes semantic validation"
               (validate-tree-semantics d2 e2))
        ;; negative controls
        (check "a flipped signature byte fails verification"
               (let ((bad (copy-seq (subseq msg 1))))
                 (setf (aref bad (- (length bad) 1)) (logxor 1 (aref bad (- (length bad) 1))))
                 (multiple-value-bind (d3) (decode-tree-announce bad)
                   (not (verify-declaration d3 xonly)))))
        (check "a wrong key fails verification"
               (not (verify-declaration d2 (secp256k1-fast.schnorr:pubkey-xonly 5))))
        (check "truncated body rejected"
               (handler-case (progn (decode-tree-announce (subseq msg 1 60)) nil)
                 (error () t)))
        (check "version 2 rejected"
               (handler-case (let ((b (copy-seq (subseq msg 1))))
                               (setf (aref b 0) 2)
                               (decode-tree-announce b) nil)
                 (error () t)))
        (check "zero ancestry entries rejected"
               (handler-case (let ((b (copy-seq (subseq msg 1))))
                               (setf (aref b 33) 0 (aref b 34) 0)
                               (decode-tree-announce b) nil)
                 (error () t)))))
    (check "unsigned declaration is not encoded"
           (handler-case (progn (encode-tree-announce
                                 (make-parent-declaration (octet-range 1 16) (octet-range 1 16) 1 1)
                                 (list (make-coord-entry (octet-range 1 16) 1 1)))
                                nil)
             (error () t))))
  ;; semantics: the wire.rs rules, each violated on purpose.  The advertised root
  ;; is the LAST entry and must be the smallest NodeAddr on the path.
  (let* ((a (octet-range 200 16))               ; the declaring node, large
         (b (octet-range 1 16))                 ; its parent, small: the root
         (c (octet-range 100 16))               ; a middle entry
         (decl-ab (make-parent-declaration a b 1 1))   ; a declares parent b
         (decl-aa (make-parent-declaration a a 1 1)))  ; a declares itself root
    (check "semantics: parent-first, root-minimum path accepted"
           (validate-tree-semantics decl-ab (list (make-coord-entry a 1 1)
                                                  (make-coord-entry b 1 1))))
    (check "semantics: advertised root not minimum rejected"
           (not (validate-tree-semantics decl-ab (list (make-coord-entry a 1 1)
                                                       (make-coord-entry b 1 1)
                                                       (make-coord-entry c 1 1)))))
    (check "semantics: first entry must be the declaring node"
           (not (validate-tree-semantics decl-ab (list (make-coord-entry b 1 1)
                                                       (make-coord-entry a 1 1)))))
    (check "semantics: second entry must match the declared parent"
           (not (validate-tree-semantics decl-ab (list (make-coord-entry a 1 1)
                                                       (make-coord-entry c 1 1)
                                                       (make-coord-entry b 1 1)))))
    (check "semantics: a root declaration with two entries rejected"
           (not (validate-tree-semantics decl-aa (list (make-coord-entry a 1 1)
                                                       (make-coord-entry b 1 1)))))
    (check "semantics: a non-root declaration with one entry rejected"
           (not (validate-tree-semantics decl-ab (list (make-coord-entry a 1 1)))))))

(defun test-tree-two-nodes ()
  (let* ((sa (make-tree-state 3))
         (sb (make-tree-state 5))
         (small-first (u8-less-p (tree-state-node sa) (tree-state-node sb)))
         (small (if small-first sa sb))
         (large (if small-first sb sa)))
    (tree-register-peer-key sa (tree-state-node sb) (secp256k1-fast.schnorr:pubkey-xonly 5))
    (tree-register-peer-key sb (tree-state-node sa) (secp256k1-fast.schnorr:pubkey-xonly 3))
    (tree-recompute sa 1000)
    (tree-recompute sb 1000)
    (let* ((ann-a (tree-current-announce sa))
           (ann-b (tree-current-announce sb)))
      (check "each node's first declaration is a signed root announcement"
             (and ann-a ann-b))
      (multiple-value-bind (d e) (decode-tree-announce (subseq ann-b 1))
        (check "B's announce reaches A and verifies" (tree-observe-announce sa d e))
        (check "a repeat of the same sequence is refused as stale"
               (not (tree-observe-announce sa d e))))
      (multiple-value-bind (d e) (decode-tree-announce (subseq ann-a 1))
        (check "A's announce reaches B and verifies" (tree-observe-announce sb d e))))
    (multiple-value-bind (decl entries changed) (tree-recompute large 2000)
      (declare (ignore entries))
      (check "the larger node adopts the smaller as parent"
             (and changed
                  (equalp (parent-declaration-parent decl) (tree-state-node small)))))
    (multiple-value-bind (decl entries changed) (tree-recompute small 2000)
      (declare (ignore changed))
      (check "the smaller node stays a root"
             (and (parent-declaration-root-p decl) (= (length entries) 1))))
    (let ((ann (tree-current-announce large)))
      (check "the larger node's announce carries its ancestry [self, root]"
             (multiple-value-bind (d e) (decode-tree-announce (subseq ann 1))
               (declare (ignore d))
               (and (= (length e) 2)
                    (equalp (coord-entry-node (second e)) (tree-state-node small))))))
    ;; a forged announce: claims the larger node's identity, signed with the other
    ;; key.  Sign directly (SIGN-DECLARATION refuses a mismatched node on purpose).
    (let ((forged (make-parent-declaration (tree-state-node large) (tree-state-node large) 9 9)))
      (setf (parent-declaration-sig forged)
            (secp256k1-fast.schnorr:schnorr-sign
             (if (eq large sa) 5 3) (declaration-signing-hash forged)))
      (check "a forged announce is refused"
             (not (tree-observe-announce (if (eq large sa) sb sa) forged
                                         (list (make-coord-entry (tree-state-node large) 9 9))))))))

(defun u8-less-p (a b)
  (loop for x across a for y across b
        do (cond ((< x y) (return t)) ((> x y) (return nil)))
        finally (return nil)))

(defun test-routing ()
  (test-bloom)
  (test-tree-announce)
  (test-tree-two-nodes))
