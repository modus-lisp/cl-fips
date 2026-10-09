;;;; udp.lisp -- UDP datagram ports for cl-fips links.
;;;;
;;;; The socket work is cl-transport/sockets' (sb-bsd-sockets: SBCL and hosted
;;;; modus): one socket per endpoint, datagrams sorted into per-peer queues by
;;;; source address.  What is FIPS here is only how a peer becomes a link port
;;;; (CL-FIPS:MAKE-DATAGRAM-PORT), which strangers are worth keeping -- exactly a
;;;; msg1, someone dialling us -- and the MTU.  UDP is FIPS's default transport
;;;; (upstream transport/udp: each datagram is one whole FMP packet, MTU 1280).

(in-package #:cl-fips.transport)

(defconstant +udp-mtu+ 1280 "transport/udp: DEFAULT_UDP_MTU (the IPv6 minimum).")

(defun %fips-msg1-p (datagram)
  "Exactly a msg1: version 0, phase 1, the msg1 size -- anything else from a
   stranger would register an address for a handshake that cannot happen."
  (and (= (length datagram) 114) (= (aref datagram 0) cl-fips:+phase-msg1+)))

(defun udp-open (&key (host "127.0.0.1") (port 0))
  "A UDP endpoint bound to HOST:PORT (loopback, ephemeral by default) that keeps a
   stranger's datagram only if it is a msg1."
  (sk:udp-open :host host :port port :admit #'%fips-msg1-p))

(defun udp-close (ep) (sk:udp-close ep))
(defun udp-endpoint-local-port (ep) (sk:udp-local-port ep))
(defun udp-endpoint-received (ep) (sk:udp-endpoint-received ep))
(defun udp-endpoint-dropped (ep) (sk:udp-endpoint-dropped ep))
(defun udp-endpoint-peers (ep) (sk::udp-endpoint-peers ep))
(defun udp-endpoint-fresh (ep) (sk:udp-endpoint-strangers ep))
(defun udp-pump (ep &key (timeout-ms 0)) (sk:udp-pump ep :timeout-ms timeout-ms))
(defun udp-wait (ep timeout-ms) (sk:udp-pump ep :timeout-ms timeout-ms))
(defun udp-accept-pending-p (ep) (sk:udp-accept-pending-p ep))
(defun udp-offer (ep host port packet) (sk:udp-offer ep host port packet))

(defun %datagram-port (peer)
  (setf (sk::udp-peer-handle-port peer)
        (cl-fips:make-datagram-port (lambda (deadline) (sk:udp-peer-read peer deadline))
                                    (lambda (octets) (sk:udp-peer-write peer octets))
                                    (lambda () (sk:udp-peer-close peer)))))

(defun udp-peer-port (ep host port)
  "A datagram port to HOST:PORT through EP.  Closing it forgets the peer (the socket
   stays open for the others)."
  (%datagram-port (sk:udp-peer-handle ep host port)))

(defun udp-accept (ep &key (timeout-ms 0))
  "The oldest unanswered inbound msg1, as a datagram port to its sender with that
   msg1 queued (pass the port to STREAM-LINK-ACCEPT).  Returns (values port host
   port), or NIL if none arrives within TIMEOUT-MS."
  (multiple-value-bind (peer host port) (sk:udp-accept ep :timeout-ms timeout-ms)
    (when peer (values (%datagram-port peer) host port))))

(defun udp-port-ready-p (ep port)
  "True if PORT (from UDP-PEER-PORT / UDP-ACCEPT on EP) has a datagram queued."
  (loop for peer being the hash-values of (sk::udp-endpoint-peers ep)
        thereis (and (eq (sk::udp-peer-handle-port peer) port) (sk:udp-peer-ready-p peer))))
