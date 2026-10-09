;;;; transit-test.lisp -- transit forwarding of SessionDatagrams (src/route.lisp).
;;;; Pure: the next hop is chosen from bloom filters, and the header is rewritten.
;;;;
;;;;   T1  the forwarded header: TTL down by one, path_mtu lowered to the outgoing
;;;;       link's MTU when that is smaller, the rest of the datagram unchanged
;;;;   T2  datagrams that may not leave: TTL 0 on arrival, and TTL 1 (it would leave
;;;;       with 0)
;;;;   T3  the next hop is a peer whose filter may reach the destination; never the
;;;;       link the datagram came from; no candidate means no route
;;;;   T4  split horizon: the filter we send a link is our own address and every
;;;;       other link's filter, never the filter of the link we send it to

(in-package #:cl-fips.test)

(defun sd-msg (src dest ttl mtu payload)
  "A SessionDatagram as the link carries it: msg_type first."
  (encode-session-datagram src dest payload :ttl ttl :path-mtu mtu))

(defun test-transit ()
  (let* ((src (fsp-addr 1)) (dest (fsp-addr 9))
         (msg (sd-msg src dest 40 1400 (ascii-octets "payload")))
         (body (subseq msg 1)))
    (check "T1: the datagram's fields read back from the body"
           (and (= (sd-ttl body) 40) (= (sd-path-mtu body) 1400)
                (equalp (sd-src body) src) (equalp (sd-dest body) dest)))
    (let ((out (sd-forward-header body 1280)))
      (check "T1: TTL goes down by one"
             (= (sd-ttl out) 39))
      (check "T1: path_mtu is lowered to the outgoing link's MTU"
             (= (sd-path-mtu out) 1280))
      (check "T1: the addresses and payload are unchanged"
             (and (equalp (sd-src out) src) (equalp (sd-dest out) dest)
                  (equalp (subseq out 35) (ascii-octets "payload")))))
    (check "T1: path_mtu is not raised above what arrived"
           (= (sd-path-mtu (sd-forward-header (subseq (sd-msg src dest 40 1000 (octets 1)) 1) 1400))
              1000))
    (check "T2: a datagram arriving with TTL 0 is not forwarded"
           (null (sd-forward-header (subseq (sd-msg src dest 0 1400 (octets 1)) 1) 1400)))
    (check "T2: a datagram with TTL 1 would leave with 0 and is not forwarded"
           (null (sd-forward-header (subseq (sd-msg src dest 1 1400 (octets 1)) 1) 1400))))
  ;; T3: next hop from filters, with the link names as stand-ins
  (let* ((dest (fsp-addr 9)) (other (fsp-addr 5))
         (fa (make-bloom)) (fb (make-bloom)) (fc (make-bloom)))
    (bloom-insert fa other)
    (bloom-insert fb dest)                     ; B's side reaches the destination
    (bloom-insert fc (fsp-addr 7))
    (let ((links (list (cons 'a fa) (cons 'b fb) (cons 'c fc))))
      (check "T3: the datagram goes to the link whose filter reaches the destination"
             (eq (route-next-hop links 'a dest) 'b))
      (check "T3: never back out the link it came in on"
             (null (route-next-hop (list (cons 'a fb)) 'a dest)))
      (check "T3: no candidate, no route"
             (null (route-next-hop links 'a (fsp-addr 200))))
      (check "T3: a link with no filter is not a candidate"
             (null (route-next-hop (list (cons 'a nil) (cons 'b nil)) 'a dest)))))
  ;; T4: split horizon
  (let* ((own (fsp-addr 1)) (x (fsp-addr 2)) (y (fsp-addr 3))
         (fx (make-bloom)) (fy (make-bloom)))
    (bloom-insert fx x) (bloom-insert fy y)
    (let* ((links (list (cons 'a fx) (cons 'b fy)))
           (to-a (route-filter-for own links 'a))
           (to-b (route-filter-for own links 'b)))
      (check "T4: the filter for link a carries our address and link b's reachability"
             (and (bloom-contains-p to-a own) (bloom-contains-p to-a y)))
      (check "T4: the filter for link a does not carry link a's own reachability"
             (not (bloom-contains-p to-a x)))
      (check "T4: the filter for link b does not carry link b's own reachability"
             (not (bloom-contains-p to-b y)))
      (check "T4: the filter for link b carries link a's reachability"
             (bloom-contains-p to-b x)))))
