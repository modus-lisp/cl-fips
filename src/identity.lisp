;;;; identity.lisp -- node_addr and the FIPS IPv6 address.
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510.
;;;;   src/identity/node_addr.rs  NodeAddr::from_pubkey: SHA-256 over the 32-byte
;;;;                              x-only key, first 16 bytes.
;;;;   src/identity/address.rs    FipsAddress::from_node_addr: 0xfd (ULA,
;;;;                              FIPS_ADDRESS_PREFIX) then node_addr[0..15].
;;;; The x-only key is the compressed SEC1 key without its parity byte, so both
;;;; parities of a point give the same node_addr.

(in-package #:cl-fips)

(defconstant +fips-address-prefix+ #xfd)

(defun node-addr (pubkey-bytes)
  "16-byte node_addr of a 33-byte compressed (or 32-byte x-only) public key."
  (let ((x (ecase (length pubkey-bytes)
             (33 (subseq pubkey-bytes 1))
             (32 pubkey-bytes))))
    (subseq (natrium:sha256 (coerce x '(simple-array (unsigned-byte 8) (*)))) 0 16)))

(defun fips-address (node-addr)
  "16-byte FIPS IPv6 address: 0xfd || node_addr[0..15]."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
    (setf (aref out 0) +fips-address-prefix+)
    (replace out node-addr :start1 1 :end2 15)
    out))

(defun fips-address-string (address)
  "Uncompressed textual IPv6 form, eight colon-separated groups."
  (format nil "~(~{~4,'0x~^:~}~)"
          (loop for i below 16 by 2
                collect (+ (ash (aref address i) 8) (aref address (1+ i))))))

;;; --- npub / nsec (NIP-19 bech32) -------------------------------------------------
;;;
;;; Upstream names a node by its npub (bech32, hrp "npub", of the 32-byte x-only key)
;;; and keeps its secret as an nsec (hrp "nsec", of the 32-byte secret).  BIP-173
;;; bech32: the checksum constant is 1 (not bech32m).

(defparameter +bech32-alphabet+ "qpzry9x8gf2tvdw0s3jn54khce6mua7l")

(defun %bech32-polymod (values)
  (let ((gen #(#x3b6a57b2 #x26508e6d #x1ea119fa #x3d4233dd #x2a1462b3)) (chk 1))
    (dolist (v values chk)
      (let ((b (ash chk -25)))
        (setf chk (logxor (ash (logand chk #x1ffffff) 5) v))
        (dotimes (i 5) (when (logbitp i b) (setf chk (logxor chk (aref gen i)))))))))

(defun %bech32-hrp-expand (hrp)
  (append (map 'list (lambda (c) (ash (char-code c) -5)) hrp) '(0)
          (map 'list (lambda (c) (logand (char-code c) 31)) hrp)))

(defun %convert-bits (values from to pad)
  "Regroup VALUES of FROM bits into TO bits.  Returns NIL if a value is out of range,
   or (without PAD) if the leftover bits are not a zero padding shorter than FROM."
  (let ((acc 0) (bits 0) (out '()) (maxv (1- (ash 1 to))))
    (dolist (v values)
      (when (or (minusp v) (>= v (ash 1 from))) (return-from %convert-bits nil))
      (setf acc (logior (ash acc from) v)) (incf bits from)
      (loop while (>= bits to)
            do (decf bits to) (push (logand (ash acc (- bits)) maxv) out))
      (setf acc (logand acc (1- (ash 1 bits)))))
    (cond (pad (when (plusp bits) (push (logand (ash acc (- to bits)) maxv) out)))
          ((or (>= bits from) (plusp acc)) (return-from %convert-bits nil)))
    (nreverse out)))

(defun bech32-encode (hrp octets)
  (let* ((data (%convert-bits (coerce octets 'list) 8 5 t))
         (pm (logxor 1 (%bech32-polymod (append (%bech32-hrp-expand hrp) data '(0 0 0 0 0 0)))))
         (chk (loop for i below 6 collect (ldb (byte 5 (* 5 (- 5 i))) pm))))
    (format nil "~a1~{~c~}" hrp (mapcar (lambda (d) (char +bech32-alphabet+ d)) (append data chk)))))

(defun bech32-decode (string)
  "Returns (values hrp octets), or NIL for anything that is not valid bech32."
  (let* ((s (string-downcase string))
         (sep (position #\1 s :from-end t)))
    (when (and sep (plusp sep) (>= (- (length s) sep 1) 6)
               (or (string= s string) (string= (string-upcase string) string))
               (every (lambda (c) (<= 33 (char-code c) 126)) s))
      (let* ((hrp (subseq s 0 sep))
             (data (loop for c across (subseq s (1+ sep))
                         for d = (position c +bech32-alphabet+)
                         unless d do (return-from bech32-decode nil)
                         collect d)))
        (when (= 1 (%bech32-polymod (append (%bech32-hrp-expand hrp) data)))
          (let ((bytes (%convert-bits (butlast data 6) 5 8 nil)))
            (when bytes
              (values hrp (coerce bytes '(vector (unsigned-byte 8)))))))))))

(defun %bech32-32 (string hrp)
  (multiple-value-bind (h octets) (bech32-decode string)
    (unless (and h (string= h hrp) (= (length octets) 32))
      (error "not a valid ~a: ~s" hrp string))
    octets))

(defun npub-encode (pubkey)
  "npub of a 33-byte compressed or 32-byte x-only public key."
  (bech32-encode "npub" (if (= (length pubkey) 33) (subseq pubkey 1) pubkey)))

(defun npub-decode (npub)
  "The peer key an npub names, as the 33-byte compressed key the handshake takes.
   The npub carries no parity; FIPS's handshake uses the x coordinate only, and the
   pre-message forces 0x02, so 0x02 is the right prefix."
  (let ((x (%bech32-32 npub "npub"))
        (out (make-array 33 :element-type '(unsigned-byte 8))))
    (setf (aref out 0) 2)
    (replace out x :start1 1)
    out))

(defun nsec-encode (secret-bytes) (bech32-encode "nsec" secret-bytes))
(defun nsec-decode (nsec) (%bech32-32 nsec "nsec"))
