;;;; tcp.lisp -- TCP for cl-fips stream links.
;;;;
;;;; The socket work is cl-transport/sockets' (sb-bsd-sockets: SBCL and hosted
;;;; modus): a TCP-SOCKET with its own receive buffer and deadline reads.  Here it
;;;; becomes a CL-FIPS:BYTE-PORT.  READ-EXACTLY's deadline covers a whole packet,
;;;; not a byte, so a peer that dribbles a packet slower than the link's deadline is
;;;; dropped (upstream transport/tcp/mod.rs InboundDeadline).

(in-package #:cl-fips.transport)

(defun socket-byte-port (ts)
  "A CL-FIPS:BYTE-PORT over the TCP-SOCKET TS."
  (cl-fips:make-byte-port (lambda (n deadline) (sk:tcp-read-exactly ts n deadline))
                          (lambda (octets) (sk:tcp-write ts octets))
                          (lambda () (sk:tcp-close ts))))

(defun tcp-connect (host port &key (timeout-secs 10))
  "A BYTE-PORT on a new connection to HOST:PORT.  The second value is the socket."
  (let ((ts (sk:tcp-connect host port :timeout-secs timeout-secs)))
    (values (socket-byte-port ts) ts)))

(defun tcp-accept (listener &key timeout-ms)
  "Accept one connection as a BYTE-PORT, or NIL if TIMEOUT-MS passes first.  The
   second value is the socket."
  (let ((ts (sk:tcp-accept listener :timeout-ms timeout-ms)))
    (when ts (values (socket-byte-port ts) ts))))

(defun tcp-listen (&key (host "127.0.0.1") (port 0)) (sk:tcp-listen :host host :port port))
(defun tcp-listener-port (listener) (sk:tcp-listener-port listener))
(defun tcp-listener-close (listener) (sk:tcp-listener-close listener))
(defun tcp-read-available (ts) (sk:tcp-read-available ts))
(defun tcp-socket-buffered-p (ts) (sk:tcp-buffered-p ts))
(defun tcp-write (ts octets) (sk:tcp-write ts octets))
(defun tcp-close (ts) (sk:tcp-close ts))
(defun tcp-shutdown-output (ts) (sk:tcp-shutdown-output ts))
(defun tcp-wait (sockets timeout-ms &key udp) (sk:wait-readable sockets timeout-ms :udp udp))

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
