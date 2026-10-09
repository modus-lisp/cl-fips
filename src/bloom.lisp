;;;; bloom.lisp -- the reachability filter and the FilterAnnounce (msg_type 0x20).
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510.
;;;;   src/proto/bloom/core.rs    insert / contains: SHA-256(data); h1 and h2 are the
;;;;                              first and second 8-byte little-endian halves;
;;;;                              bit k is (h1 + k*h2) mod 2^64, then mod num_bits
;;;;   src/proto/bloom/limits.rs  8192 bits, 5 hash functions, size_class 1 (1 KiB)
;;;;   src/proto/bloom/wire.rs    FilterAnnounce layout; decode requires size_class 1
;;;;                              and an exact length
;;;;
;;;; Encoded (msg_type included):
;;;;   [0x20][seq u64][hash_count u8][size_class u8][filter 1024 bytes]

(in-package #:cl-fips)

(defconstant +bloom-bits+ 8192)
(defconstant +bloom-bytes+ 1024)
(defconstant +bloom-hash-count+ 5)
(defconstant +bloom-size-class+ 1)
(defconstant +filter-announce-msg-type+ #x20)

(defun make-bloom ()
  (make-array +bloom-bytes+ :element-type '(unsigned-byte 8) :initial-element 0))

(defun bloom-base-hashes (data)
  "h1, h2 from SHA-256(data), each an unsigned 64-bit little-endian integer."
  (let ((h (natrium:sha256 data)))
    (values (decode-u64le h 0) (decode-u64le h 8))))

(defun bloom-bit-indices (data)
  "The k bit positions for DATA, as bloom/core.rs bit_index computes them."
  (multiple-value-bind (h1 h2) (bloom-base-hashes data)
    (loop for k from 0 below +bloom-hash-count+
          collect (mod (ldb (byte 64 0) (+ h1 (* k h2))) +bloom-bits+))))

(defun bloom-insert (filter data)
  "Set the bits for DATA (a byte vector, typically a 16-byte NodeAddr)."
  (dolist (i (bloom-bit-indices data) filter)
    (multiple-value-bind (byte bit) (floor i 8)
      (setf (aref filter byte) (logior (aref filter byte) (ash 1 bit))))))

(defun bloom-contains-p (filter data)
  (every (lambda (i)
           (multiple-value-bind (byte bit) (floor i 8)
             (logbitp bit (aref filter byte))))
         (bloom-bit-indices data)))

(defun bloom-union (a b)
  "Bitwise OR of two filters of the same size: core.rs merge."
  (let ((out (make-bloom)))
    (dotimes (i +bloom-bytes+ out)
      (setf (aref out i) (logior (aref a i) (aref b i))))))

(defun encode-filter-announce (seq filter)
  (unless (= (length filter) +bloom-bytes+) (error "filter is not 1024 bytes"))
  (bytes-cat (bytes-of +filter-announce-msg-type+)
          (encode-u64le seq)
          (bytes-of +bloom-hash-count+ +bloom-size-class+)
          filter))

(defun decode-filter-announce (body)
  "Parse the body after msg_type.  Returns (values seq filter hash-count)."
  (unless (= (length body) (+ 10 +bloom-bytes+))
    (error "FilterAnnounce body is ~d bytes, expected ~d" (length body) (+ 10 +bloom-bytes+)))
  (let ((size-class (aref body 9)))
    (unless (= size-class +bloom-size-class+)
      (error "FilterAnnounce size_class ~d; v1 requires ~d" size-class +bloom-size-class+))
    (values (decode-u64le body 0)
            (bytes-slice body 10)
            (aref body 8))))
