;;;; package.lisp -- CL-FIPS.TRANSPORT, shared by the UDP adapter (portable: SBCL
;;;; and modus, on sb-bsd-sockets) and the TCP adapter (SBCL, on usocket).
;;;; The TCP names are exported here even where tcp.lisp is not loaded, so code
;;;; that mentions them (the daemon) reads everywhere and fails only if it is
;;;; asked for TCP where there is none.

(defpackage #:cl-fips.transport
  (:use #:common-lisp)
  (:export #:tcp-connect #:tcp-listen #:tcp-listener-port #:tcp-accept #:tcp-listener-close
           #:socket-byte-port #:tcp-socket-buffered-p #:tcp-read-available #:prefixed-byte-port
           #:tcp-wait #:tcp-available-p
           #:udp-endpoint-socket
           #:+udp-mtu+ #:udp-open #:udp-close #:udp-endpoint-local-port #:udp-pump #:udp-wait
           #:udp-peer-port #:udp-accept #:udp-port-ready-p #:udp-accept-pending-p
           #:udp-endpoint-received #:udp-endpoint-dropped #:udp-offer
           #:%seconds-until))

(in-package #:cl-fips.transport)

(defun %seconds-until (deadline)
  "Seconds from now until DEADLINE (an absolute GET-INTERNAL-REAL-TIME value), or NIL."
  (and deadline
       (/ (float (- deadline (get-internal-real-time)) 1d0) internal-time-units-per-second)))

(defun tcp-available-p ()
  "True when the TCP adapter is loaded (cl-fips/transport, SBCL)."
  (and (fboundp 'tcp-connect) t))
