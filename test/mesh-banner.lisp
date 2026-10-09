;;;; mesh-banner.lisp -- TCP over the IPv6 shim to public-mesh nodes: their SSH banners.
;;;;
;;;;   sbcl --script test/mesh-banner.lisp [HOST.fips ...]
;;;;
;;;; Peers with test-us01 (MESH_PEER_ADDR overrides its address, e.g. an impairment
;;;; proxy), then reads the first line from port 22 of each host through
;;;; cl-transport :fips -- cl-transport/tcp at our end, the node's own sshd at the
;;;; other.  Prints PASS when every banner starts with SSH-.

(require :asdf)
(dolist (d '("/home/claude/cl-fips/" "/home/claude/natrium/" "/home/claude/secp256k1-fast/" "/home/claude/cl-transport/"))
  (push (pathname d) asdf:*central-registry*))
(load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname)))
(let ((*standard-output* (make-broadcast-stream)))
  (ql:quickload '("usocket" "bordeaux-threads") :silent t) (asdf:load-system "cl-fips/stream"))
(let* ((ep (cl-fips.stream:start-fips-client
            (list :udp '(:bind "0.0.0.0:0")
                  :peers `((:npub "npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98"
                            :transport :udp :addr ,(or (sb-ext:posix-getenv "MESH_PEER_ADDR") "test-us01.fips.network:2121"))))
            :log (and (sb-ext:posix-getenv "LOG") *standard-output*))))
  (loop repeat 300 until (cl-fips:fips-node-links (cl-fips.daemon:daemon-node (cl-fips.stream:endpoint-daemon ep))) do (sleep 0.1))
  (sleep 2)
  (defparameter *ok* 0)
  (defparameter *hosts* (or (rest sb-ext:*posix-argv*)
                            (list "npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98.fips")))
  (dolist (host *hosts*)
    (let ((t0 (get-internal-real-time)))
      (handler-case
          (multiple-value-bind (s closer) (cl-transport:dial host 22 :transport :fips :timeout 60)
            (let ((line (with-output-to-string (o)
                          (loop for b = (read-byte s nil nil) while (and b (/= b 10)) do (write-char (code-char b) o)))))
              (when (and (> (length line) 4) (string= "SSH-" line :end2 4)) (incf *ok*))
              (format t "~a:22 -> ~s (~d ms)~%" (subseq host 0 12) (string-trim '(#\Return) line)
                      (round (* 1000 (- (get-internal-real-time) t0)) internal-time-units-per-second)))
            (funcall closer))
        (error (e) (format t "~a:22 -> FAILED ~a~%" (subseq host 0 12) e)))
      (finish-output)))
  (cl-fips.stream:stop-fips-endpoint ep)
  (format t "~:[FAIL~;PASS~]: ~d of ~d banners~%" (= *ok* (length *hosts*)) *ok* (length *hosts*))
  (sb-ext:exit :code (if (= *ok* (length *hosts*)) 0 1)))
