;;;; fetch-fips-url.lisp -- fetch an http://<npub>.fips/ URL over the PUBLIC test mesh.
;;;;
;;;;   sbcl --script test/fetch-fips-url.lisp [URL] [log]
;;;;
;;;; Peers with test-us01.fips.network (UDP 2121, admits any npub), then seal GETs URL
;;;; through cl-transport :fips -- cl-transport/tcp over the IPv6 shim to the node itself.

(require :asdf)
(dolist (d '("/home/claude/cl-fips/" "/home/claude/natrium/" "/home/claude/secp256k1-fast/" "/home/claude/seal/" "/home/claude/cl-transport/"))
  (push (pathname d) asdf:*central-registry*))
(load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname)))
(let ((*standard-output* (make-broadcast-stream)))
  (ql:quickload '("usocket" "bordeaux-threads") :silent t)
  (asdf:load-system "cl-fips/stream") (asdf:load-system "seal/http"))
(defvar *url* (or (second sb-ext:*posix-argv*) "http://npub1crpldvy49ef8z34wlacwujnfudy4nd7k96aqdx5wgn6ckztz7z8q9t59ud.fips/"))
(let* ((ep (cl-fips.stream:start-fips-client
            (list :udp '(:bind "0.0.0.0:0")
                  :peers `((:npub "npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98"
                            :transport :udp :addr ,(or (sb-ext:posix-getenv "MESH_PEER_ADDR") "test-us01.fips.network:2121")
                            :alias "test-us01")))
            :log (and (third sb-ext:*posix-argv*) *standard-output*)))
       (d (cl-fips.stream:endpoint-daemon ep)))
  (loop repeat 300 until (cl-fips:fips-node-links (cl-fips.daemon:daemon-node d)) do (sleep 0.1))
  (sleep 3)
  (format t "linked; fetching ~a~%" *url*) (finish-output)
  (let* ((t0 (get-internal-real-time))
         (seal.http:*dial* (lambda (h p tm) (cl-transport:dial h p :transport :fips :timeout tm)))
         (r (handler-case (seal.http:http-get *url*) (error (e) (format t "FAILED: ~a~%" e) nil))))
    (when r
      (format t "HTTP ~d, ~d bytes in ~d ms~%" (seal.http:response-status r) (length (seal.http:response-body r))
              (round (* 1000 (- (get-internal-real-time) t0)) internal-time-units-per-second))
      (let ((o (coerce (seal.http:response-body r) '(simple-array (unsigned-byte 8) (*)))))
        (format t "LEN ~d SHA256 ~(~{~2,'0x~}~)~%" (length o) (coerce (natrium:sha256 o) 'list))))
    (cl-fips.stream:stop-fips-endpoint ep)))
