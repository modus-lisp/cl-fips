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

(in-package #:cl-fips.transport)


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
                             (if (usocket:wait-for-input (list socket) :timeout wait :ready-only t)
                                 (take)          ; readable: a byte, or EOF -- never blocks
                                 (done :timeout)))))
                   (error () (done :eof))))))
           (write-all (octets)
             (handler-case (progn (write-sequence octets stream) (finish-output stream) :ok)
               (error () :closed)))
           (close-it () (ignore-errors (usocket:socket-close socket))))
      (cl-fips:make-byte-port #'read-exactly #'write-all #'close-it))))

(defun tcp-connect (host port &key (timeout-secs 10))
  "A BYTE-PORT on a new connection to HOST:PORT.  The second value is the socket."
  (let ((socket (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                                  :timeout timeout-secs :nodelay t)))
    (values (socket-byte-port socket) socket)))

(defun tcp-read-available (socket)
  "Whatever bytes SOCKET has now, without waiting.  Returns (values octets eof-p);
   call it only after WAIT-FOR-INPUT said SOCKET is readable, so that no bytes and
   no LISTEN means the peer closed."
  (let ((stream (usocket:socket-stream socket)) (out '()))
    (handler-case
        (progn
          (loop while (listen stream) do (push (read-byte stream) out))
          (if out
              (values (coerce (nreverse out) '(vector (unsigned-byte 8))) nil)
              (let ((b (read-byte stream nil nil)))
                (if b
                    (values (coerce (list b) '(vector (unsigned-byte 8))) nil)
                    (values (make-array 0 :element-type '(unsigned-byte 8)) t)))))
      (error () (values (coerce (nreverse out) '(vector (unsigned-byte 8))) t)))))

(defun prefixed-byte-port (prefix port)
  "PORT, with the octets PREFIX (already read off it) served first."
  (let ((pos 0))
    (cl-fips:make-byte-port
     (lambda (n deadline)
       (let* ((take (min n (- (length prefix) pos)))
              (head (subseq prefix pos (+ pos take))))
         (incf pos take)
         (if (= take n)
             (values head :ok)
             (multiple-value-bind (rest status)
                 (funcall (cl-fips::byte-port-read-exactly port) (- n take) deadline)
               (values (concatenate '(vector (unsigned-byte 8)) head rest) status)))))
     (cl-fips::byte-port-write-all port)
     (lambda () (cl-fips:byte-port-close port)))))

(defun tcp-socket-buffered-p (socket)
  "True if bytes are already inside SOCKET's Lisp stream.  WAIT-FOR-INPUT watches the
   descriptor, so it cannot see these: an event loop must drain them first."
  (ignore-errors (listen (usocket:socket-stream socket))))

(defun tcp-listen (&key (host "127.0.0.1") (port 0))
  "Listen on HOST (loopback by default) and PORT (0 = ephemeral)."
  (usocket:socket-listen host port :reuse-address t :element-type '(unsigned-byte 8)))

(defun tcp-listener-port (listener) (usocket:get-local-port listener))

(defun tcp-accept (listener &key timeout-ms)
  "Accept one connection as a BYTE-PORT, or NIL if TIMEOUT-MS passes first.  The
   second value is the socket."
  (when (usocket:wait-for-input (list listener) :timeout (and timeout-ms (/ timeout-ms 1000d0))
                                         :ready-only t)
    (let ((socket (handler-case (usocket:socket-accept listener :element-type '(unsigned-byte 8))
                    ;; out of descriptors, or the connection went away first
                    (error () nil))))
      (when socket (values (socket-byte-port socket) socket)))))

(defun tcp-listener-close (listener) (ignore-errors (usocket:socket-close listener)))

(defun tcp-wait (sockets timeout-ms)
  "The members of SOCKETS (usocket sockets, listeners included) that are readable
   within TIMEOUT-MS.  A fresh list each call: usocket's single-socket form reuses
   a stale wait-list after a list wait."
  (and sockets
       (handler-case (usocket:wait-for-input sockets :timeout (/ timeout-ms 1000d0) :ready-only t)
         (error () nil))))
