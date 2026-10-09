;;;; lookup.lisp -- coordinate discovery: LookupRequest (0x30), LookupResponse (0x31).
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510.
;;;;   src/proto/lookup/wire.rs   the two messages, and proof_bytes
;;;;   src/proto/lookup/core.rs   forward (TTL), plan_forward / plan_initiate (tree
;;;;                              peers whose filter may reach the target; a
;;;;                              forward falls back to non-tree peers), the
;;;;                              dedup of request ids, the reverse-path response
;;;;   src/node/handlers/lookup.rs  the target answers with its coordinates and a
;;;;                              Schnorr proof; each hop on the way back folds its
;;;;                              outgoing link MTU into path_mtu; the originator
;;;;                              verifies the proof with the target's key
;;;;   src/identity/local.rs      sign: BIP-340 over SHA-256(data)
;;;;   src/config/node.rs         ttl 64; attempts at 1, 2, 4, 8 s (fresh ids);
;;;;                              recent-request expiry 10 s; forward at most once
;;;;                              per target per 2 s
;;;;
;;;; Both travel as LINK messages, hop by hop, not inside a SessionDatagram:
;;;;   request  [0x30][request_id u64][target 16][origin 16][ttl u8][min_mtu u16]
;;;;            [origin coords: count u16, then 16-byte addresses, root last]
;;;;   response [0x31][request_id u64][target 16][path_mtu u16]
;;;;            [target coords][proof 64]
;;;; The proof signs request_id || target || coords (path_mtu is not covered: it
;;;; is rewritten on the way).

(in-package #:cl-fips)

(defconstant +lookup-request-msg-type+ #x30)
(defconstant +lookup-response-msg-type+ #x31)
(defconstant +lookup-default-ttl+ 64)
(defparameter *lookup-attempt-ms* '(1000 2000 4000 8000)
  "attempt_timeouts_secs: how long each attempt waits before the next (fresh id).")
(defconstant +lookup-recent-expiry-ms+ 10000)
(defconstant +lookup-forward-interval-ms+ 2000)

(defstruct (lookup-request (:constructor make-lookup-request
                               (request-id target origin origin-coords &key (ttl +lookup-default-ttl+)
                                                                          (min-mtu 0))))
  request-id target origin origin-coords ttl min-mtu)

(defstruct (lookup-response (:constructor make-lookup-response
                                (request-id target target-coords proof &key (path-mtu #xffff))))
  request-id target path-mtu target-coords proof)

(defun encode-lookup-request (r)
  (bytes-cat (bytes-of +lookup-request-msg-type+)
             (encode-u64le (lookup-request-request-id r))
             (lookup-request-target r) (lookup-request-origin r)
             (bytes-of (lookup-request-ttl r))
             (encode-u16le (lookup-request-min-mtu r))
             (encode-coords (lookup-request-origin-coords r))))

(defun decode-lookup-request (body)
  "BODY is the message after msg_type.  Signals an error for a malformed one."
  (when (< (length body) 45) (error "LookupRequest body is ~d bytes" (length body)))
  (multiple-value-bind (coords next) (decode-coords body 43)
    (unless (= next (length body))
      (error "LookupRequest has ~d bytes after its coordinates" (- (length body) next)))
    (make-lookup-request (decode-u64le body 0) (bytes-slice body 8 24) (bytes-slice body 24 40)
                         coords :ttl (aref body 40) :min-mtu (decode-u16le body 41))))

(defun lookup-proof-bytes (request-id target coords)
  (bytes-cat (encode-u64le request-id) target (encode-coords coords)))

(defun sign-lookup-proof (privkey-int request-id target coords)
  (secp256k1-fast.schnorr:schnorr-sign
   privkey-int (natrium:sha256 (lookup-proof-bytes request-id target coords))))

(defun verify-lookup-response (r xonly)
  "T iff R's proof is the target's signature (XONLY, 32 bytes) over its id,
   target and coordinates, and XONLY is the key the target address names."
  (and (= (length xonly) 32)
       (equalp (node-addr xonly) (lookup-response-target r))
       (secp256k1-fast.schnorr:schnorr-verify
        xonly
        (natrium:sha256 (lookup-proof-bytes (lookup-response-request-id r)
                                            (lookup-response-target r)
                                            (lookup-response-target-coords r)))
        (lookup-response-proof r))
       t))

(defun encode-lookup-response (r)
  (bytes-cat (bytes-of +lookup-response-msg-type+)
             (encode-u64le (lookup-response-request-id r))
             (lookup-response-target r)
             (encode-u16le (lookup-response-path-mtu r))
             (encode-coords (lookup-response-target-coords r))
             (lookup-response-proof r)))

(defun decode-lookup-response (body)
  (when (< (length body) 92) (error "LookupResponse body is ~d bytes" (length body)))
  (multiple-value-bind (coords next) (decode-coords body 26)
    (when (< (length body) (+ next 64))
      (error "LookupResponse is ~d bytes; its coordinates and proof need ~d"
             (length body) (+ next 64)))
    (make-lookup-response (decode-u64le body 0) (bytes-slice body 8 24) coords
                          (bytes-slice body next (+ next 64))
                          :path-mtu (decode-u16le body 24))))
