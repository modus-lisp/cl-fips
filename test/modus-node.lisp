;;;; modus-node.lisp -- a cl-fips node running INSIDE MODUS, against a real FIPS node.
;;;;
;;;;   MODUS_FIPS_CONFIG=node.conf MODUS_FIPS_TARGET=npub1... MODUS_FIPS_SECS=60 \
;;;;     modus --script test/modus-node.lisp
;;;;
;;;; The same daemon as on SBCL (cl-fips/daemon, UDP only: the UDP adapter is written
;;;; against sb-bsd-sockets, which modus provides).  Once the link is up it sends a
;;;; probe to the target's port 4600 (native-echo) every 3 s and checks each echo.
;;;; Settings come from the environment because a modus --script has no argv
;;;; convention to rely on.  Driven by scripts/run-modus-node.sh.

(require :asdf)
(let ((home (or (sb-ext:posix-getenv "HOME") "/home/claude")))
  (dolist (d (list (or (sb-ext:posix-getenv "NATRIUM_DIR") (concatenate 'string home "/natrium"))
                   (or (sb-ext:posix-getenv "SECP256K1_DIR") (concatenate 'string home "/secp256k1-fast"))
                   (or (sb-ext:posix-getenv "CL_FIPS_DIR") (concatenate 'string home "/cl-fips"))))
    (push (pathname (concatenate 'string d "/")) asdf:*central-registry*)))

(defun out (fmt &rest args) (apply #'format t fmt args) (terpri) (finish-output))

(handler-case (asdf:load-system "cl-fips/daemon")
  (error (e) (out "LOAD FAILED: ~a" e) (sb-ext:exit :code 2)))
(out "LOADED cl-fips/daemon on ~a" (lisp-implementation-type))

(let* ((config (sb-ext:posix-getenv "MODUS_FIPS_CONFIG"))
       (target (sb-ext:posix-getenv "MODUS_FIPS_TARGET"))
       (secs (parse-integer (or (sb-ext:posix-getenv "MODUS_FIPS_SECS") "60")))
       (target-addr (cl-fips:node-addr (cl-fips:npub-decode target)))
       (sent (make-hash-table :test 'equal))
       (up nil) (ok 0) (bad 0) (n 0) (next 0)
       (d (cl-fips.daemon:make-daemon
           (cl-fips.daemon:load-config config)
           :on-event (lambda (d ev)
                       (declare (ignore d))
                       (case (first ev)
                         (:peer-up (setf up t))
                         (:data
                          (let ((peer (second ev)) (sp (third ev)) (dp (fourth ev))
                                (text (map 'string #'code-char (fifth ev))))
                            (when (and (equalp peer target-addr) (= sp 4600) (= dp 4601))
                              (if (gethash text sent)
                                  (progn (incf ok) (remhash text sent) (out "ECHO OK ~s" text))
                                  (progn (incf bad) (out "ECHO MISMATCH ~s" text))))))))))
       (t0 (get-universal-time)))
  (cl-fips.daemon:daemon-start d)
  (out "LISTENING npub=~a udp=~a" (cl-fips.daemon:daemon-npub d) (cl-fips.daemon:daemon-udp-port d))
  (cl-fips.daemon:daemon-run
   d :until (lambda ()
              (when (and up (>= (cl-fips.daemon::daemon-now d) next))
                (let ((probe (format nil "modus probe ~d" (incf n))))
                  (setf (gethash probe sent) t)
                  (handler-case
                      (cl-fips.daemon:daemon-send d target (map '(vector (unsigned-byte 8)) #'char-code probe)
                                                  :src-port 4601 :dst-port 4600)
                    (error (e) (out "SEND FAILED ~a" e)))
                  (setf next (+ (cl-fips.daemon::daemon-now d) 3000))))
              (>= (- (get-universal-time) t0) secs)))
  (cl-fips.daemon:daemon-stop d)
  (out "probes sent ~d, echoed ~d, mismatched ~d" n ok bad)
  (let ((pass (and up (>= ok 2) (zerop bad))))
    (out "~:[FAIL~;PASS~]: a cl-fips node on modus against the real node" pass)
    (sb-ext:exit :code (if pass 0 1))))
