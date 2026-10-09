;;;; tcp.lisp -- TCP for cl-fips stream links, on sb-bsd-sockets.
;;;;
;;;; HOST ADAPTER, nothing in src/ names it.  Written against SBCL's own
;;;; sb-bsd-sockets and SB-SYS:WAIT-UNTIL-FD-USABLE, which modus provides too, so
;;;; the same file carries TCP links on SBCL and on hosted modus.  It supplies the
;;;; closures of a CL-FIPS:BYTE-PORT (read-exactly with an absolute deadline,
;;;; write-all, close) plus connect / listen / accept / wait.
;;;;
;;;; A TCP-SOCKET keeps its OWN receive buffer rather than a Lisp stream's, so "is
;;;; there input?" has one answer -- bytes in the buffer, or the descriptor
;;;; readable -- and an event loop can never wait on a descriptor while bytes sit
;;;; unseen in a stream buffer above it.
;;;;
;;;; READ-EXACTLY honours its DEADLINE across the whole request, not per byte, so
;;;; a peer that dribbles a packet slower than the link's deadline is dropped
;;;; (upstream transport/tcp/mod.rs InboundDeadline: "Each deadline covers one
;;;; complete frame, not a byte").

(in-package #:cl-fips.transport)

(defconstant +tcp-recv-chunk+ 65536)

(defstruct (tcp-socket (:constructor %make-tcp-socket (sock)))
  sock
  (buf (make-array 0 :element-type '(unsigned-byte 8)))
  (pos 0) (eof nil) (closed nil))

(defun %fd (s)
  (sb-bsd-sockets:socket-file-descriptor (if (tcp-socket-p s) (tcp-socket-sock s) s)))

(defun %fd-readable-p (s seconds)
  (ignore-errors (sb-sys:wait-until-fd-usable (%fd s) :input (max 0 seconds))))

(defun %buffered (ts) (- (length (tcp-socket-buf ts)) (tcp-socket-pos ts)))

(defun %fill (ts seconds)
  "Wait up to SECONDS for input and read what is there.  NIL if nothing came;
   end of stream sets EOF."
  (when (and (not (tcp-socket-eof ts)) (%fd-readable-p ts seconds))
    (multiple-value-bind (buf n)
        ;; an explicit octet buffer: given NIL, SBCL allocates a CHARACTER one
        (handler-case (sb-bsd-sockets:socket-receive
                       (tcp-socket-sock ts)
                       (make-array +tcp-recv-chunk+ :element-type '(unsigned-byte 8)) +tcp-recv-chunk+)
          (error () (values nil 0)))
      (if (or (null n) (zerop n))
          (setf (tcp-socket-eof ts) t)
          (setf (tcp-socket-buf ts)
                (concatenate '(vector (unsigned-byte 8))
                             (subseq (tcp-socket-buf ts) (tcp-socket-pos ts)) (subseq buf 0 n))
                (tcp-socket-pos ts) 0))
      t)))

(defun %take (ts n)
  (let ((out (subseq (tcp-socket-buf ts) (tcp-socket-pos ts) (+ (tcp-socket-pos ts) n))))
    (incf (tcp-socket-pos ts) n)
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun tcp-write (ts octets)
  "Write all of OCTETS.  :OK or :CLOSED."
  (handler-case
      (let ((v (coerce octets '(simple-array (unsigned-byte 8) (*)))) (sent 0))
        (loop while (< sent (length v))
              do (let ((n (sb-bsd-sockets:socket-send (tcp-socket-sock ts) (subseq v sent) (- (length v) sent))))
                   (when (or (null n) (<= n 0)) (return-from tcp-write :closed))
                   (incf sent n)))
        :ok)
    (error () :closed)))

(defun tcp-close (ts)
  (unless (tcp-socket-closed ts)
    (setf (tcp-socket-closed ts) t)
    (ignore-errors (sb-bsd-sockets:socket-close (tcp-socket-sock ts)))))

(defun tcp-shutdown-output (ts)
  "Half-close: the peer reads end of stream; we can still read."
  (ignore-errors (sb-bsd-sockets:socket-shutdown (tcp-socket-sock ts) :direction :output)))

(defun socket-byte-port (ts)
  "A CL-FIPS:BYTE-PORT over the TCP-SOCKET TS."
  (flet ((read-exactly (n deadline)
           (loop
             (when (>= (%buffered ts) n) (return (values (%take ts n) :ok)))
             (when (tcp-socket-eof ts) (return (values (%take ts (%buffered ts)) :eof)))
             (let ((wait (%seconds-until deadline)))
               (when (and wait (<= wait 0)) (return (values (%take ts (%buffered ts)) :timeout)))
               (unless (%fill ts (or wait 3600))
                 (when wait (return (values (%take ts (%buffered ts)) :timeout)))))))
         (write-all (octets) (tcp-write ts octets))
         (close-it () (tcp-close ts)))
    (cl-fips:make-byte-port #'read-exactly #'write-all #'close-it)))

(defun %resolve (host)
  (if (and (vectorp host) (not (stringp host)))
      host
      (or (%dotted-quad host)
          (sb-bsd-sockets:host-ent-address (sb-bsd-sockets:get-host-by-name host)))))

(defun tcp-connect (host port &key (timeout-secs 10))
  "A BYTE-PORT on a new connection to HOST:PORT.  The second value is the socket.
   TIMEOUT-SECS bounds the connect on SBCL (a non-blocking connect); modus's
   sb-bsd-sockets has no non-blocking connect, so there it is the kernel's."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
        (addr (%resolve host)))
    (handler-case
        (progn
          #+sbcl
          (progn
            (setf (sb-bsd-sockets:non-blocking-mode s) t)
            (handler-case (sb-bsd-sockets:socket-connect s addr port)
              (sb-bsd-sockets:operation-in-progress () nil))
            (unless (sb-sys:wait-until-fd-usable (sb-bsd-sockets:socket-file-descriptor s) :output timeout-secs)
              (error "connect to ~a:~d timed out" host port))
            ;; the connect's outcome: a refused one shows as an error on the peer name
            (sb-bsd-sockets:socket-peername s)
            (setf (sb-bsd-sockets:non-blocking-mode s) nil))
          #-sbcl
          (progn timeout-secs (sb-bsd-sockets:socket-connect s addr port))
          (ignore-errors (setf (sb-bsd-sockets:sockopt-tcp-nodelay s) t))
          (let ((ts (%make-tcp-socket s)))
            (values (socket-byte-port ts) ts)))
      (error (e) (ignore-errors (sb-bsd-sockets:socket-close s)) (error e)))))

(defun tcp-read-available (ts)
  "Whatever bytes TS has now, without waiting.  Returns (values octets eof-p)."
  (when (zerop (%buffered ts)) (%fill ts 0))
  (values (%take ts (%buffered ts)) (and (tcp-socket-eof ts) (zerop (%buffered ts)))))

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

(defun tcp-socket-buffered-p (ts)
  "True if bytes already received sit in TS's buffer: an event loop must take
   them before waiting on the descriptor."
  (and (tcp-socket-p ts) (plusp (%buffered ts))))

(defun tcp-listen (&key (host "127.0.0.1") (port 0))
  "Listen on HOST (loopback by default) and PORT (0 = ephemeral)."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (handler-case
        (progn
          (setf (sb-bsd-sockets:sockopt-reuse-address s) t)
          (sb-bsd-sockets:socket-bind s (%resolve host) port)
          (sb-bsd-sockets:socket-listen s 16)
          s)
      (error (e) (ignore-errors (sb-bsd-sockets:socket-close s)) (error e)))))

(defun tcp-listener-port (listener) (nth-value 1 (sb-bsd-sockets:socket-name listener)))

(defun tcp-accept (listener &key timeout-ms)
  "Accept one connection as a BYTE-PORT, or NIL if TIMEOUT-MS passes first.  The
   second value is the socket."
  (when (%fd-readable-p listener (if timeout-ms (/ timeout-ms 1000) 3600))
    (let ((s (handler-case (sb-bsd-sockets:socket-accept listener)
               ;; out of descriptors, or the connection went away first
               (error () nil))))
      (when s
        (ignore-errors (setf (sb-bsd-sockets:sockopt-tcp-nodelay s) t))
        (let ((ts (%make-tcp-socket s)))
          (values (socket-byte-port ts) ts))))))

(defun tcp-listener-close (listener) (ignore-errors (sb-bsd-sockets:socket-close listener)))

(defun tcp-wait (sockets timeout-ms &key udp)
  "The members of SOCKETS (TCP-SOCKETs and listeners) that are readable within
   TIMEOUT-MS -- bytes already buffered count.  UDP, an endpoint, ends the wait
   too when it has input (it is pumped).  There is no portable multi-descriptor
   wait, so this checks every descriptor and sleeps on one in slices of 10 ms:
   a TCP readiness is seen at most that late."
  (let ((deadline (+ (get-internal-real-time)
                     (round (* timeout-ms internal-time-units-per-second) 1000))))
    (loop
      (let ((ready (remove-if-not (lambda (s) (or (tcp-socket-buffered-p s) (%fd-readable-p s 0))) sockets)))
        (when (and udp (plusp (udp-pump udp :timeout-ms 0)))
          (return ready))
        (when ready (return ready))
        (let ((left (- deadline (get-internal-real-time))))
          (when (<= left 0) (return nil))
          (let ((slice (min 0.01 (/ left internal-time-units-per-second))))
            (if udp
                (udp-pump udp :timeout-ms (round (* slice 1000)))
                (%fd-readable-p (first sockets) slice))))))))
