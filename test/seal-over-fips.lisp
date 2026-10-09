;;;; seal-over-fips.lisp -- seal fetches an https URL whose bytes travel over FIPS.
;;;;
;;;;   sbcl --script test/seal-over-fips.lisp gateway CONFIG ALLOW-NPUB
;;;;   sbcl --script test/seal-over-fips.lisp client  CONFIG GATEWAY-NPUB URL [EXPECT]
;;;;
;;;; gateway: a cl-fips node that opens TCP connections for ALLOW-NPUB.
;;;; client:  a cl-fips node in a thread, registered as cl-transport's :fips backend;
;;;;          seal.http:*dial* is cl-transport:dial with :transport :fips, and the
;;;;          script GETs URL.  TLS runs end to end, from seal to the web server:
;;;;          the gateway and every FIPS node on the way see only ciphertext.
;;;; Driven by scripts/run-seal-over-fips.sh.

(require :asdf)
(let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
  (push (merge-pathnames "../" here) asdf:*central-registry*))
(dolist (dep '(("NATRIUM_DIR" . "natrium") ("SECP256K1_DIR" . "secp256k1-fast")
               ("SEAL_DIR" . "seal") ("CL_TRANSPORT_DIR" . "cl-transport")))
  (push (pathname (format nil "~a/" (or (sb-ext:posix-getenv (car dep))
                                        (namestring (merge-pathnames (cdr dep) (user-homedir-pathname))))))
        asdf:*central-registry*))
(let ((ql (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (when (probe-file ql) (load ql)))
(let ((*standard-output* (make-broadcast-stream)))
  (funcall (find-symbol "QUICKLOAD" "QL") '("usocket" "bordeaux-threads") :silent t)
  (asdf:load-system "cl-fips/stream")
  (asdf:load-system "seal/http"))

(defpackage #:cl-fips.seal-test (:use #:common-lisp))
(in-package #:cl-fips.seal-test)

(defun out (fmt &rest args) (apply #'format t fmt args) (terpri) (finish-output))

(let ((args (rest sb-ext:*posix-argv*)))
  (cond
    ((string= (first args) "gateway")
     (cl-fips.stream:run-gateway-main (second args) (list (third args))))
    ((string= (first args) "client")
     (destructuring-bind (config gateway url &optional expect) (rest args)
       (let* ((ep (cl-fips.stream:start-fips-client (cl-fips.daemon:load-config config)
                                                    :gateway gateway))
              (d (cl-fips.stream:endpoint-daemon ep)))
         (out "CLIENT npub=~a" (cl-fips.daemon:daemon-npub d))
         ;; wait for the relay link, then give the tree a moment
         (loop repeat 300 until (cl-fips:fips-node-links (cl-fips.daemon:daemon-node d)) do (sleep 0.1))
         (sleep 3)
         (let* ((t0 (get-internal-real-time))
                (seal.http:*dial* (lambda (h p tm) (cl-transport:dial h p :transport :fips :timeout tm)))
                (r (handler-case (seal.http:http-get url)
                     (error (e) (out "FETCH FAILED: ~a" e) nil)))
                (ms (round (* 1000 (- (get-internal-real-time) t0)) internal-time-units-per-second)))
           (cl-fips.stream:stop-fips-endpoint ep)
           (if (null r)
               (progn (out "FAIL: seal over FIPS") (sb-ext:exit :code 1))
               (let* ((octets (coerce (seal.http:response-body r) '(simple-array (unsigned-byte 8) (*))))
                      (body (map 'string #'code-char octets))
                      (sha (format nil "~(~{~2,'0x~}~)" (coerce (natrium:sha256 octets) 'list)))
                      ;; EXPECT is text the body must contain, or sha256:<hex> of the whole body
                      (ok (and (= (seal.http:response-status r) 200)
                               (cond ((null expect) t)
                                     ((and (> (length expect) 7) (string= "sha256:" expect :end2 7))
                                      (string-equal sha (subseq expect 7)))
                                     (t (search expect body))))))
                 (out "SHA256 ~a" sha)
                 (out "HTTP ~d, ~d bytes in ~d ms, over FIPS" (seal.http:response-status r) (length body) ms)
                 (out "~a" (subseq body 0 (min 300 (length body))))
                 (out "~:[FAIL~;PASS~]: seal fetched ~a over FIPS~@[ (body contains ~s)~]" ok url expect)
                 (sb-ext:exit :code (if ok 0 1)))))))))))
