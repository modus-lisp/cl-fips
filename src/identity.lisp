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
