;;;; package.lisp -- CL-FIPS.TRANSPORT: the UDP and TCP adapters.  The sockets are
;;;; cl-transport/sockets' (sb-bsd-sockets: SBCL and hosted modus); what is here is
;;;; FIPS's use of them.
;;;; The TCP names are exported here even where tcp.lisp is not loaded, so code
;;;; that mentions them (the daemon) reads everywhere and fails only if it is
;;;; asked for TCP where there is none.

(defpackage #:cl-fips.transport
  (:use #:common-lisp)
  (:local-nicknames (#:sk #:cl-transport.sockets))
  (:export #:tcp-connect #:tcp-listen #:tcp-listener-port #:tcp-accept #:tcp-listener-close
           #:socket-byte-port #:tcp-socket-buffered-p #:tcp-read-available #:prefixed-byte-port
           #:tcp-wait #:tcp-available-p #:tcp-write #:tcp-close #:tcp-shutdown-output

           #:+udp-mtu+ #:udp-open #:udp-close #:udp-endpoint-local-port #:udp-pump #:udp-wait
           #:udp-peer-port #:udp-accept #:udp-port-ready-p #:udp-accept-pending-p
           #:udp-endpoint-received #:udp-endpoint-dropped #:udp-offer
           #:%seconds-until))

(in-package #:cl-fips.transport)

(defun %seconds-until (deadline) (sk:seconds-until deadline))

(defun tcp-available-p ()
  "True when the TCP adapter is loaded (cl-fips/transport, SBCL)."
  (and (fboundp 'tcp-connect) t))
