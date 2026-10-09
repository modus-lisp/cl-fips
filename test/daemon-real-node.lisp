;;;; daemon-real-node.lisp -- the cl-fips daemon against a REAL upstream node.
;;;;
;;;; Driven by scripts/run-real-node-udp.sh, which writes both configs, starts the
;;;; upstream node and its native-echo, and greps the node's log.  The Lisp half:
;;;;
;;;;   sbcl --script test/daemon-real-node.lisp CONFIG NODE-NPUB SECS
;;;;
;;;; Runs the daemon CONFIG describes.  Once a link is up it sends a probe to the
;;;; node's port 4600 (native-echo) every 2 s, from our port 4601, each probe
;;;; different, and checks every echo against what was sent.  It also logs any
;;;; DataPacket the node sends us (port 4700: the runner's native-send).
;;;; Exit 0 when a link came up and at least 3 probes came back byte for byte,
;;;; with no mismatch.

(require :asdf)
(let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
  (push (merge-pathnames "../" here) asdf:*central-registry*))
(push (pathname (format nil "~a/" (or (sb-ext:posix-getenv "NATRIUM_DIR")
                                      (namestring (merge-pathnames "natrium" (user-homedir-pathname))))))
      asdf:*central-registry*)
(push (pathname (format nil "~a/" (or (sb-ext:posix-getenv "SECP256K1_DIR")
                                      (namestring (merge-pathnames "secp256k1-fast" (user-homedir-pathname))))))
      asdf:*central-registry*)
(let ((ql (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (when (probe-file ql) (load ql)))
(let ((*standard-output* (make-broadcast-stream)))   ; quiet, but load ERRORS still print
  (if (find-package "QL")
      (funcall (find-symbol "QUICKLOAD" "QL") "usocket" :silent t)
      (asdf:load-system "usocket"))
  (asdf:load-system "cl-fips/daemon"))

(defpackage #:cl-fips.daemon-real-node (:use #:common-lisp))
(in-package #:cl-fips.daemon-real-node)

(defun ascii (s) (map '(vector (unsigned-byte 8)) #'char-code s))
(defun text (v) (map 'string #'code-char v))

(destructuring-bind (config-path node-npub secs) (rest sb-ext:*posix-argv*)
  (let* ((secs (parse-integer secs))
         (node-addr (cl-fips:node-addr (cl-fips:npub-decode node-npub)))
         (sent (make-hash-table :test 'equal))
         (ok 0) (bad 0) (up nil) (next-probe 0) (n 0)
         (d (cl-fips.daemon:make-daemon
             (cl-fips.daemon:load-config config-path)
             :on-event (lambda (d ev)
                         (declare (ignore d))
                         (case (first ev)
                           (:peer-up (setf up t))
                           (:data
                            (destructuring-bind (peer sp dp data ts) (rest ev)
                              (declare (ignore ts))
                              (cond
                                ((and (equalp peer node-addr) (= sp 4600) (= dp 4601))
                                 (if (gethash (text data) sent)
                                     (progn (incf ok) (remhash (text data) sent)
                                            (format t "ECHO OK ~s~%" (text data)))
                                     (progn (incf bad) (format t "ECHO MISMATCH ~s~%" (text data)))))
                                (t
                                 (format t "DATA from ~:[~(~{~2,'0x~}~)~;the node~*~] src_port=~d dst_port=~d data=~s~%"
                                         (equalp peer node-addr) (coerce (subseq peer 0 4) 'list)
                                         sp dp (text data)))))))
                         (finish-output)))))
    (cl-fips.daemon:daemon-start d)
    (format t "LISTENING udp=~a tcp=~a npub=~a~%"
            (cl-fips.daemon:daemon-udp-port d) (cl-fips.daemon:daemon-tcp-port d)
            (cl-fips.daemon:daemon-npub d))
    (finish-output)
    (let ((end (+ (get-universal-time) secs)))
      (cl-fips.daemon:daemon-run
       d :until (lambda ()
                  (when (and up (>= (cl-fips.daemon::daemon-now d) next-probe))
                    (let ((probe (format nil "cl-fips probe ~d over the daemon" (incf n))))
                      (setf (gethash probe sent) t)
                      (handler-case (cl-fips.daemon:daemon-send d node-npub (ascii probe)
                                                                :src-port 4601 :dst-port 4600)
                        (error (e) (format t "SEND FAILED ~a~%" e)))
                      (setf next-probe (+ (cl-fips.daemon::daemon-now d) 2000))))
                  (>= (get-universal-time) end))))
    (cl-fips.daemon:daemon-stop d)
    (format t "probes sent ~d, echoed ~d, mismatched ~d~%" n ok bad)
    (let ((pass (and up (>= ok 3) (zerop bad))))
      (format t "~:[FAIL~;PASS~]: daemon against the real node~%" pass)
      (finish-output)
      (sb-ext:exit :code (if pass 0 1)))))
