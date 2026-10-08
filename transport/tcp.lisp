;;;; tcp.lisp -- a TCP BYTE-PORT for cl-fips stream links, on usocket.
;;;;
;;;; DEVELOPMENT ADAPTER.  It is written against usocket and has only been run on
;;;; SBCL; it is not part of the pure system and nothing in src/ names it.  All
;;;; it does is supply the two closures of a CL-FIPS:BYTE-PORT (read-exactly with
;;;; an absolute deadline, write-all) plus connect / listen / accept.  A modus
;;;; port of the transport replaces this file and nothing else.
;;;;
;;;; READ-EXACTLY honours its DEADLINE across the whole request, not per byte,
;;;; so a peer that dribbles a packet slower than the link's deadline is dropped
;;;; (upstream transport/tcp/mod.rs InboundDeadline: "Each deadline covers one
;;;; complete frame, not a byte").  Buffered bytes are drained with LISTEN before
;;;; waiting, so data already inside the Lisp stream is never waited for twice.

(defpackage #:cl-fips.transport
  (:use #:common-lisp)
  (:export #:tcp-connect #:tcp-listen #:tcp-listener-port #:tcp-accept #:tcp-listener-close
           #:socket-byte-port))

(in-package #:cl-fips.transport)

(defun %seconds-until (deadline)
  (and deadline
       (/ (float (- deadline (get-internal-real-time)) 1d0) internal-time-units-per-second)))

(defun socket-byte-port (socket)
  (let ((stream (usocket:socket-stream socket)))
    (flet ((read-exactly (n deadline)
             (let ((buf (make-array n :element-type '(unsigned-byte 8))) (got 0))
               (flet ((done (status) (return-from read-exactly
                                       (values (if (= got n) buf (subseq buf 0 got)) status)))
                      (take () (let ((b (read-byte stream nil nil)))
                                 (unless b (return-from read-exactly
                                             (values (subseq buf 0 got) :eof)))
                                 (setf (aref buf got) b) (incf got))))
                 (handler-case
                     (loop
                       (when (= got n) (done :ok))
                       (if (listen stream)
                           (take)
                           (let ((wait (%seconds-until deadline)))
                             (when (and wait (<= wait 0)) (done :timeout))
                             (if (usocket:wait-for-input socket :timeout wait :ready-only t)
                                 (take)          ; readable: a byte, or EOF -- never blocks
                                 (done :timeout)))))
                   (error () (done :eof))))))
           (write-all (octets)
             (handler-case (progn (write-sequence octets stream) (finish-output stream) :ok)
               (error () :closed)))
           (close-it () (ignore-errors (usocket:socket-close socket))))
      (cl-fips:make-byte-port #'read-exactly #'write-all #'close-it))))

(defun tcp-connect (host port &key (timeout-secs 10))
  (socket-byte-port (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                                      :timeout timeout-secs :nodelay t)))

(defun tcp-listen (&key (host "127.0.0.1") (port 0))
  "Listen on HOST (loopback by default) and PORT (0 = ephemeral)."
  (usocket:socket-listen host port :reuse-address t :element-type '(unsigned-byte 8)))

(defun tcp-listener-port (listener) (usocket:get-local-port listener))

(defun tcp-accept (listener &key timeout-ms)
  "Accept one connection as a BYTE-PORT, or NIL if TIMEOUT-MS passes first."
  (when (usocket:wait-for-input listener :timeout (and timeout-ms (/ timeout-ms 1000d0))
                                         :ready-only t)
    (socket-byte-port (usocket:socket-accept listener :element-type '(unsigned-byte 8)))))

(defun tcp-listener-close (listener) (ignore-errors (usocket:socket-close listener)))
