;;;; ipv6-shim.lisp -- the IPv6 shim: IPv6 packets carried in DataPackets on port 256.
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510, src/ipv6tun/ipv6_shim.rs
;;;; (compress_ipv6 / decompress_ipv6) and src/proto/fsp/wire.rs
;;;; (FSP_PORT_IPV6_SHIM = 256, used as both source and destination port).
;;;;
;;;;   [format 0x00][IPv6 bytes 0-3: version, traffic class, flow label]
;;;;   [next header][hop limit][upper-layer payload]
;;;;
;;;; The addresses and the payload length are not carried: the addresses are the two
;;;; nodes' FIPS addresses, known from the session, and the length is what remains.
;;;; Upstream rebuilds the header and hands the packet to its TUN, so a TCP segment
;;;; sent this way reaches the far host's ordinary TCP stack.

(in-package #:cl-fips)

(defconstant +fsp-port-ipv6-shim+ 256)
(defconstant +ipv6-next-header-tcp+ 6)

(defun ipv6-shim-wrap (payload &key (next-header +ipv6-next-header-tcp+) (hop-limit 64))
  "PAYLOAD (a TCP segment, by default) as the shim carries it: format 0, version 6,
   traffic class and flow label 0."
  (bytes-cat (bytes-of 0 #x60 0 0 0 next-header hop-limit) payload))

(defun ipv6-shim-unwrap (shim)
  "(values payload next-header) of a format-0 shim packet, or NIL."
  (when (and (>= (length shim) 7) (zerop (aref shim 0)) (= (ash (aref shim 1) -4) 6))
    (values (bytes-slice shim 7) (aref shim 5))))
