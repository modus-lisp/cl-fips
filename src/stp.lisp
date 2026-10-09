;;;; stp.lisp -- the spanning-tree TreeAnnounce (msg_type 0x10): codec, signing
;;;; and the semantic checks a receiver makes.  Pure, apart from the Schnorr
;;;; signature, which comes from secp256k1-fast.
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510.
;;;;   src/proto/stp/wire.rs      TreeAnnounce layout and validate_semantics
;;;;   src/proto/stp/declaration.rs  signing_bytes: node(16) parent(16) seq(8) ts(8)
;;;;   src/node/tree.rs           sign: BIP-340 over SHA-256(signing_bytes);
;;;;                              verify: the same, against the peer's x-only key
;;;;   src/proto/stp/state.rs     recompute_coords: a node at or below the parent's
;;;;                              root demotes itself to a self-root
;;;;
;;;; Encoded (msg_type included):
;;;;   [0x10][version 0x01][seq u64][ts u64][parent 16][count u16]
;;;;   [entries: node 16 | seq u64 | ts u64, count times][signature 64]
;;;; The entry list runs from the declaring node to the root; the root is last.

(in-package #:cl-fips)

(defconstant +tree-announce-msg-type+ #x10)
(defconstant +tree-announce-version+ 1)
(defconstant +tree-entry-size+ 32)
;; After msg_type: version(1) + seq(8) + ts(8) + parent(16) + count(2) + sig(64).
(defconstant +tree-announce-min-body+ 99)

(defstruct (coord-entry (:constructor make-coord-entry (node seq ts)))
  node seq ts)

(defstruct (parent-declaration
            (:constructor make-parent-declaration (node parent seq ts &optional sig)))
  node parent seq ts sig)

(defun parent-declaration-root-p (decl)
  "A declaration is a root candidate when the node names itself as parent."
  (equalp (parent-declaration-node decl) (parent-declaration-parent decl)))

(defun declaration-signing-bytes (decl)
  "node(16) || parent(16) || seq(8, LE) || ts(8, LE): declaration.rs signing_bytes."
  (bytes-cat (parent-declaration-node decl)
          (parent-declaration-parent decl)
          (encode-u64le (parent-declaration-seq decl))
          (encode-u64le (parent-declaration-ts decl))))

(defun declaration-signing-hash (decl)
  "SHA-256 over the signing bytes: the message BIP-340 signs (node/tree.rs)."
  (natrium:sha256 (declaration-signing-bytes decl)))

(defun sign-declaration (decl privkey-int)
  "Sign DECL in place with PRIVKEY-INT.  Its node_addr must be the key's node_addr
   (node/tree.rs sign_declaration refuses otherwise)."
  (let* ((xonly (secp256k1-fast.schnorr:pubkey-xonly privkey-int))
         (own (natrium:sha256 xonly)))
    (unless (equalp (parent-declaration-node decl) (subseq own 0 16))
      (error "declaration node ~a is not this key's node_addr"
             (parent-declaration-node decl)))
    (setf (parent-declaration-sig decl)
          (secp256k1-fast.schnorr:schnorr-sign privkey-int (declaration-signing-hash decl)))
    decl))

(defun verify-declaration (decl xonly-pubkey)
  "T iff DECL carries a valid signature by XONLY-PUBKEY (32 bytes) over its hash."
  (let ((sig (parent-declaration-sig decl)))
    (and sig
         (= (length xonly-pubkey) 32)
         (secp256k1-fast.schnorr:schnorr-verify
          xonly-pubkey (declaration-signing-hash decl) sig)
         t)))

(defun encode-tree-announce (decl entries)
  "The full link plaintext, msg_type first.  DECL must be signed."
  (unless (parent-declaration-sig decl) (error "declaration is not signed"))
  (when (null entries) (error "a TreeAnnounce needs at least one ancestry entry"))
  (apply #'bytes-cat
         (bytes-of +tree-announce-msg-type+)
         (bytes-of +tree-announce-version+)
         (encode-u64le (parent-declaration-seq decl))
         (encode-u64le (parent-declaration-ts decl))
         (parent-declaration-parent decl)
         (encode-u16le (length entries))
         (append
          (loop for e in entries
                collect (bytes-cat (coord-entry-node e)
                                (encode-u64le (coord-entry-seq e))
                                (encode-u64le (coord-entry-ts e))))
          (list (parent-declaration-sig decl)))))

(defun decode-tree-announce (body)
  "Parse the body after msg_type.  Returns (values declaration entries), or
   signals an error for a malformed body.  The signature is parsed, not verified:
   use VERIFY-DECLARATION with the sender's key.  Length must match exactly."
  (let ((n (length body)))
    (when (< n +tree-announce-min-body+) (error "TreeAnnounce body too short: ~d" n))
    (unless (= (aref body 0) +tree-announce-version+)
      (error "TreeAnnounce version ~d not supported" (aref body 0)))
    (let* ((seq (decode-u64le body 1))
           (ts (decode-u64le body 9))
           (parent (bytes-slice body 17 33))
           (count (decode-u16le body 33))
           (expected (+ 35 (* count +tree-entry-size+) 64)))
      (when (zerop count) (error "TreeAnnounce with no ancestry entries"))
      (unless (= n expected)
        (error "TreeAnnounce body is ~d bytes, expected ~d for ~d entries" n expected count))
      (let ((entries
              (loop for off from 35 below (+ 35 (* count +tree-entry-size+)) by +tree-entry-size+
                    collect (make-coord-entry (bytes-slice body off (+ off 16))
                                              (decode-u64le body (+ off 16))
                                              (decode-u64le body (+ off 24)))))
            (sig (bytes-slice body (- n 64) n)))
        (values (make-parent-declaration (coord-entry-node (first entries))
                                         parent seq ts sig)
                entries)))))

(defun validate-tree-semantics (decl entries)
  "wire.rs validate_semantics.  Returns T, or NIL with the first violated rule as
   a second value."
  (let ((head (first entries))
        (next (second entries))
        (root (car (last entries))))
    (cond
      ((not (equalp (coord-entry-node head) (parent-declaration-node decl)))
       (values nil :ancestry-node-mismatch))
      ((parent-declaration-root-p decl)
       (if (= (length entries) 1)
           (validate-tree-minimum entries root)
           (values nil :root-declaration-mismatch)))
      ((null next)
       (values nil :ancestry-too-short))
      ((not (equalp (coord-entry-node next) (parent-declaration-parent decl)))
       (values nil :ancestry-parent-mismatch))
      (t (validate-tree-minimum entries root)))))

(defun validate-tree-minimum (entries root)
  "The advertised root must be the smallest NodeAddr on the path."
  (let ((minimum (reduce (lambda (a b) (if (bytes< a b) a b))
                         entries :key #'coord-entry-node)))
    (if (equalp (coord-entry-node root) minimum)
        t
        (values nil :ancestry-root-not-minimum))))

(defun bytes< (a b)
  "Lexicographic order on byte vectors of equal length: NodeAddr's Ord."
  (loop for x across a for y across b
        do (cond ((< x y) (return t)) ((> x y) (return nil)))
        finally (return nil)))

;;; small byte helpers used only here

(defun bytes-of (&rest bytes)
  (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes))

(defun bytes-cat (&rest vs)
  (let* ((out (make-array (reduce #'+ vs :key #'length) :element-type '(unsigned-byte 8)))
         (pos 0))
    (dolist (v vs out)
      (replace out v :start1 pos)
      (incf pos (length v)))))

(defun bytes-slice (v start &optional end)
  (let ((out (make-array (- (or end (length v)) start) :element-type '(unsigned-byte 8))))
    (replace out v :start2 start :end2 end)
    out))
