;;;; route.lisp -- transit forwarding of SessionDatagrams (pure).
;;;;
;;;; A node that is not the destination of a SessionDatagram forwards it.  The
;;;; choice of next hop and the header rules are upstream's; the sources are:
;;;;   src/proto/link.rs        SessionDatagram: [0x00][ttl u8][path_mtu u16 LE]
;;;;                            [src 16][dest 16][payload]; TTL is decremented at
;;;;                            each hop, and a datagram that arrives with TTL 0 or
;;;;                            would leave with 0 is dropped (transit_ttl)
;;;;   src/proto/coord ..       path_mtu: each hop applies min(path_mtu, the outgoing
;;;;                            link's MTU)
;;;;   src/node/mod.rs          find_next_hop: a direct peer is used directly
;;;;   src/proto/routing/core.rs  select_best_candidate: among peers whose bloom
;;;;                            filter may reach the destination, the cheapest
;;;;                            strictly closer one
;;;;
;;;; We keep the bloom rule and leave the coordinate tie-break out: a leaf or a
;;;; relay with few peers has one candidate in practice, and the choice affects
;;;; only our own path, not correctness.  A datagram no peer's filter reaches is
;;;; dropped.  Split horizon: a filter we send to a peer is the union of our own
;;;; address and the filters of every other peer, so a datagram is never sent back
;;;; the way it came.

(in-package #:cl-fips)

;; Offsets in a SessionDatagram as the link carries it, msg_type first.  The body
;; the link hands us has msg_type stripped, so accessors subtract one.
(defconstant +sd-ttl-offset+ 1 "ttl, at 1 with msg_type (0 in the body).")
(defconstant +sd-mtu-offset+ 2 "path_mtu, u16 LE, at 2 with msg_type (1 in the body).")
(defconstant +sd-src-offset+ 4 "src_addr, at 4 with msg_type (3 in the body).")
(defconstant +sd-dest-offset+ 20 "dest_addr, at 20 with msg_type (19 in the body).")
(defconstant +sd-payload-offset+ 36 "payload, at 36 with msg_type (35 in the body).")

(defun sd-body-valid-p (body)
  (>= (length body) (- +sd-payload-offset+ 1)))

(defun sd-ttl (body) (aref body (- +sd-ttl-offset+ 1)))
(defun sd-path-mtu (body) (decode-u16le body (- +sd-mtu-offset+ 1)))
(defun sd-src (body) (bytes-slice body (- +sd-src-offset+ 1) (- +sd-dest-offset+ 1)))
(defun sd-dest (body) (bytes-slice body (- +sd-dest-offset+ 1) (- +sd-payload-offset+ 1)))

(defun sd-forward-header (body out-mtu)
  "The body to forward: TTL decremented, path_mtu lowered to OUT-MTU if that is
   smaller.  Returns NIL if the datagram may not be forwarded (TTL 0 on arrival, or
   1, which would leave with 0)."
  (let ((ttl (sd-ttl body)))
    (when (> ttl 1)
      (let ((out (copy-seq body)))
        (setf (aref out (- +sd-ttl-offset+ 1)) (1- ttl))
        (replace out (encode-u16le (min (sd-path-mtu body) out-mtu)) :start1 1)
        out))))

(defun route-next-hop (filters-by-link from-link dest)
  "Among the links other than FROM-LINK, the first (in order) whose peer filter may
   reach DEST, or NIL.  FILTERS-BY-LINK is a list of (link . filter-or-nil)."
  (loop for (link . filter) in filters-by-link
        when (and filter (not (eq link from-link)) (bloom-contains-p filter dest))
          return link))

(defun route-filter-for (own-addr filters-by-link to-link)
  "The reachability filter we send TO-LINK: our own address, plus every other
   link's peer filter (split horizon)."
  (let ((f (make-bloom)))
    (bloom-insert f own-addr)
    (loop for (link . filter) in filters-by-link
          when (and filter (not (eq link to-link)))
            do (setf f (bloom-union f filter)))
    f))
