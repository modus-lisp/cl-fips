;;;; udp.lisp -- UDP datagram ports for cl-fips links, on usocket.
;;;;
;;;; DEVELOPMENT ADAPTER, like tcp.lisp: usocket, run on SBCL, nothing in src/
;;;; names it.  UDP is FIPS's default transport (upstream transport/udp: one
;;;; socket serves every peer, each datagram is one whole FMP packet, MTU 1280).
;;;;
;;;; One socket, many links: a UDP-ENDPOINT owns the socket and sorts arriving
;;;; datagrams by source address into per-peer queues.  Each peer's link gets a
;;;; DATAGRAM PORT (cl-fips:make-datagram-port) reading from its queue; a read
;;;; that finds its queue empty pumps the socket, queueing what arrives for other
;;;; peers.  A datagram from an address with no port is kept only if it is a
;;;; phase-0x1 msg1 -- someone dialling us -- and UDP-ACCEPT hands it out.  All of
;;;; this is single-threaded: the program drives it, as it drives everything else.

(in-package #:cl-fips.transport)

(defconstant +udp-mtu+ 1280 "transport/udp: DEFAULT_UDP_MTU (the IPv6 minimum).")
(defconstant +udp-max-fresh+ 64 "Unanswered inbound msg1s kept; older ones are dropped.")
(defconstant +udp-max-queue+ 256 "Datagrams queued for one peer; older ones are dropped.")

(defstruct (udp-endpoint (:constructor %make-udp-endpoint (socket)))
  socket
  (peers (make-hash-table :test 'equal))   ; (host-octets port) -> UDP-PEER
  (fresh '())                              ; ((key . msg1) ...), newest first
  (received 0) (dropped 0) (closed nil))

(defstruct (udp-peer (:conc-name upeer-)) key host port (queue '()) (tail '()) port-object)

(defun %host-octets (host)
  (coerce (usocket::host-to-vector-quad host) 'list))

(defun udp-open (&key (host "127.0.0.1") (port 0))
  "A UDP endpoint bound to HOST:PORT (loopback, ephemeral by default)."
  (%make-udp-endpoint
   (usocket:socket-connect nil nil :protocol :datagram :element-type '(unsigned-byte 8)
                                   :local-host host :local-port port)))

(defun udp-endpoint-local-port (ep) (usocket:get-local-port (udp-endpoint-socket ep)))

(defun udp-close (ep)
  (unless (udp-endpoint-closed ep)
    (setf (udp-endpoint-closed ep) t)
    (ignore-errors (usocket:socket-close (udp-endpoint-socket ep)))))

(defun %enqueue (peer packet)
  (let ((cell (list packet)))
    (if (upeer-queue peer)
        (setf (cdr (upeer-tail peer)) cell)
        (setf (upeer-queue peer) cell))
    (setf (upeer-tail peer) cell)
    (when (> (length (upeer-queue peer)) +udp-max-queue+)
      (pop (upeer-queue peer)))))

(defun %dequeue (peer)
  (let ((p (pop (upeer-queue peer))))
    (unless (upeer-queue peer) (setf (upeer-tail peer) nil))
    p))

(defun %receive-one (ep)
  "Read one datagram that is already waiting and file it.  Returns T if one was read."
  (let ((buf (make-array 65536 :element-type '(unsigned-byte 8))))
    (multiple-value-bind (b size host port)
        (handler-case (usocket:socket-receive (udp-endpoint-socket ep) buf (length buf))
          (error () (values nil nil nil nil)))
      (declare (ignore b))
      (when (and size host)
        (incf (udp-endpoint-received ep))
        (let* ((packet (subseq buf 0 size))
               (key (list (coerce host 'list) port))
               (peer (gethash key (udp-endpoint-peers ep))))
          (cond
            (peer (%enqueue peer packet))
            ;; a stranger: keep it only if it opens a handshake
            ;; exactly a msg1: version 0, phase 1, the msg1 size -- anything else
            ;; would register an address for a handshake that cannot happen
            ((and (= size 114) (= (aref packet 0) cl-fips:+phase-msg1+)
                  (not (assoc key (udp-endpoint-fresh ep) :test #'equal)))
             (push (cons key packet) (udp-endpoint-fresh ep))
             (when (> (length (udp-endpoint-fresh ep)) +udp-max-fresh+)
               (setf (udp-endpoint-fresh ep) (subseq (udp-endpoint-fresh ep) 0 +udp-max-fresh+))))
            (t (incf (udp-endpoint-dropped ep)))))
        t))))

(defun udp-pump (ep &key (timeout-ms 0))
  "Wait up to TIMEOUT-MS for the socket to be readable, then read every datagram
   already waiting.  Returns the number read."
  (if (udp-endpoint-closed ep)
      0
      (let ((n 0))
        (when (usocket:wait-for-input (list (udp-endpoint-socket ep))
                                      :timeout (/ (max 0 timeout-ms) 1000d0) :ready-only t)
          (loop while (and (%receive-one ep)
                           (progn (incf n) t)
                           (usocket:wait-for-input (list (udp-endpoint-socket ep))
                                                   :timeout 0 :ready-only t))))
        n)))

(defun %peer-port (ep peer)
  (let ((socket (udp-endpoint-socket ep)))
    (flet ((read-packet (deadline)
             (loop
               (cond
                 ((udp-endpoint-closed ep) (return (values (cl-fips::u8-vector 0) :eof)))
                 ((upeer-queue peer) (return (values (%dequeue peer) :ok))))
               (let ((wait (%seconds-until deadline)))
                 (when (and wait (<= wait 0))
                   (return (values (cl-fips::u8-vector 0) :timeout)))
                 (udp-pump ep :timeout-ms (if wait (ceiling (* 1000 wait)) 1000)))))
           (write-all (octets)
             (handler-case
                 (progn (usocket:socket-send socket octets (length octets)
                                             :host (coerce (upeer-host peer) 'vector)
                                             :port (upeer-port peer))
                        :ok)
               (error () :closed)))
           (close-it () (remhash (upeer-key peer) (udp-endpoint-peers ep))))
      (setf (upeer-port-object peer)
            (cl-fips:make-datagram-port #'read-packet #'write-all #'close-it)))))

(defun udp-peer-port (ep host port)
  "A datagram port to HOST:PORT through EP.  Closing it forgets the peer (the socket
   stays open for the others)."
  (let* ((octets (%host-octets host))
         (key (list octets port)))
    (when (gethash key (udp-endpoint-peers ep))
      (error "a port to ~a:~d is already open" host port))
    (let ((peer (make-udp-peer :key key :host octets :port port)))
      (setf (gethash key (udp-endpoint-peers ep)) peer)
      ;; a msg1 this address sent before we opened the port is not ours to keep
      (setf (udp-endpoint-fresh ep) (remove key (udp-endpoint-fresh ep) :key #'car :test #'equal))
      (%peer-port ep peer))))

(defun udp-accept (ep &key (timeout-ms 0))
  "The oldest unanswered inbound msg1, as a datagram port to its sender with that
   msg1 queued (pass the port to STREAM-LINK-ACCEPT).  Returns (values port host
   port), or NIL if none arrives within TIMEOUT-MS."
  (when (null (udp-endpoint-fresh ep)) (udp-pump ep :timeout-ms timeout-ms))
  (let ((entry (car (last (udp-endpoint-fresh ep)))))
    (when entry
      (setf (udp-endpoint-fresh ep) (butlast (udp-endpoint-fresh ep)))
      (destructuring-bind ((host port) . msg1) entry
        (let* ((peer (make-udp-peer :key (car entry) :host host :port port))
               (p (%peer-port ep peer)))
          (setf (gethash (car entry) (udp-endpoint-peers ep)) peer)
          (%enqueue peer msg1)
          (values p (format nil "~{~d~^.~}" host) port))))))

(defun udp-port-ready-p (ep port)
  "True if PORT (from UDP-PEER-PORT / UDP-ACCEPT on EP) has a datagram queued."
  (loop for peer being the hash-values of (udp-endpoint-peers ep)
        thereis (and (eq (upeer-port-object peer) port) (upeer-queue peer) t)))

(defun udp-accept-pending-p (ep) (and (udp-endpoint-fresh ep) t))

(defun udp-offer (ep host port packet)
  "Put PACKET (a msg1 from HOST:PORT) where UDP-ACCEPT will find it, as if it had
   just arrived from a stranger.  For a dial that yields to the peer's own dial."
  (let ((key (list (%host-octets host) port)))
    (unless (or (gethash key (udp-endpoint-peers ep))
                (assoc key (udp-endpoint-fresh ep) :test #'equal))
      (push (cons key packet) (udp-endpoint-fresh ep)))))
