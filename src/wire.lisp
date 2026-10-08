;;;; wire.lisp -- byte-exact FIPS codecs.
;;;;
;;;; Every layout here is quoted from the FIPS reference wire-format and transport
;;;; documents (docs/reference/wire-formats.md, docs/design/fips-transport-layer.md).
;;;; All multi-byte integers are little-endian.

(in-package #:cl-fips)

(defconstant +phase-established+ #x0)
(defconstant +phase-msg1+ #x1)
(defconstant +phase-msg2+ #x2)
(defconstant +aead-tag-size+ 16)
;; FMP established outer header: prefix(4) + receiver_idx(4) + counter(8), AEAD AAD.
(defconstant +fmp-established-header-size+ 16)
;; FSP header: ver/phase(1) + flags(1) + payload_len(2) + counter(8), AEAD AAD.
(defconstant +fsp-header-size+ 12)

(defun encode-uint-le (value nbytes)
  (let ((out (make-array nbytes :element-type '(unsigned-byte 8))))
    (dotimes (i nbytes out)
      (setf (aref out i) (ldb (byte 8 (* 8 i)) value)))))

(defun decode-uint-le (bytes offset nbytes)
  (let ((v 0))
    (dotimes (i nbytes v)
      (setf v (logior v (ash (aref bytes (+ offset i)) (* 8 i)))))))

(defun encode-u16le (v) (encode-uint-le v 2))
(defun decode-u16le (bytes &optional (offset 0)) (decode-uint-le bytes offset 2))
(defun encode-u32le (v) (encode-uint-le v 4))
(defun decode-u32le (bytes &optional (offset 0)) (decode-uint-le bytes offset 4))
(defun encode-u64le (v) (encode-uint-le v 8))
(defun decode-u64le (bytes &optional (offset 0)) (decode-uint-le bytes offset 8))

;;; Common prefix: [ver<<4 | phase : 1][flags : 1][payload_len : 2 LE]

(defun encode-prefix (version phase flags payload-len)
  (let ((out (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref out 0) (logior (ash version 4) phase)
          (aref out 1) flags)
    (replace out (encode-u16le payload-len) :start1 2)
    out))

(defun prefix-version (bytes) (ash (aref bytes 0) -4))
(defun prefix-phase (bytes) (logand (aref bytes 0) #x0f))

(defun decode-prefix (bytes)
  "Return (values version phase flags payload-len) from the first four bytes."
  (values (prefix-version bytes)
          (prefix-phase bytes)
          (aref bytes 1)
          (decode-u16le bytes 2)))

(defun stream-frame-length (prefix-bytes)
  "Bytes that follow the 4-byte prefix on a stream transport (TCP, Tor, Nym).
   Returns NIL for an unknown phase: the spec says to close the connection."
  (multiple-value-bind (version phase flags payload-len) (decode-prefix prefix-bytes)
    (declare (ignore version flags))
    (case phase
      (#.+phase-established+ (+ +fmp-established-header-size+ -4 payload-len +aead-tag-size+))
      (#.+phase-msg1+ payload-len)            ; fixed at 110 -> 114 total
      (#.+phase-msg2+ payload-len)            ; fixed at 65  -> 69 total
      (t nil))))

;;; FMP established header, 16 bytes:
;;;   0 prefix(4)  4 receiver_idx u32 LE  8 counter u64 LE

(defun encode-fmp-established-header (flags payload-len receiver-idx counter)
  (let ((out (make-array +fmp-established-header-size+ :element-type '(unsigned-byte 8))))
    (replace out (encode-prefix 0 +phase-established+ flags payload-len))
    (replace out (encode-u32le receiver-idx) :start1 4)
    (replace out (encode-u64le counter) :start1 8)
    out))

(defun decode-fmp-established-header (bytes)
  "Return (values flags payload-len receiver-idx counter)."
  (values (aref bytes 1)
          (decode-u16le bytes 2)
          (decode-u32le bytes 4)
          (decode-u64le bytes 8)))

;;; FSP header, 12 bytes:
;;;   0 ver/phase(1)  1 flags(1)  2 payload_len u16 LE  4 counter u64 LE

(defun encode-fsp-header (flags payload-len counter)
  (let ((out (make-array +fsp-header-size+ :element-type '(unsigned-byte 8))))
    (replace out (encode-prefix 0 +phase-established+ flags payload-len))
    (replace out (encode-u64le counter) :start1 4)
    out))

(defun decode-fsp-header (bytes)
  "Return (values flags payload-len counter)."
  (values (aref bytes 1)
          (decode-u16le bytes 2)
          (decode-u64le bytes 4)))
