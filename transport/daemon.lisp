;;;; daemon.lisp -- a runnable FIPS node on SBCL: config, identity, listeners, peers.
;;;;
;;;; DEVELOPMENT/HOST ADAPTER, like tcp.lisp and udp.lisp: SBCL and usocket.  It
;;;; is the event loop around a CL-FIPS:FIPS-NODE that src/ deliberately does not
;;;; contain -- which socket has input, when to dial, when to give up on a peer --
;;;; and the one place that reads a clock.
;;;;
;;;; Configuration is a Lisp plist, read with *READ-EVAL* off:
;;;;
;;;;   (:identity (:key-file "fips.key")      ; nsec, one line, mode 0600; created
;;;;                                          ; if absent.  Relative to the config.
;;;;    :udp (:bind "0.0.0.0:2121")           ; omit to run without UDP
;;;;    :tcp (:bind "127.0.0.1:8443")         ; omit to run without a TCP listener
;;;;    :peers ((:npub "npub1..." :transport :udp :addr "198.51.100.7:2121"
;;;;             :alias "relay"))
;;;;    :echo-ports (4600))                   ; answer DataPackets on these ports
;;;;
;;;; Upstream's defaults are kept where they exist: UDP on 2121 with MTU 1280,
;;;; TCP MTU 1400, the 30 s handshake and dead-link timeouts.  A configured peer
;;;; is redialled after it drops, with a doubling backoff (1 s .. 60 s, jittered).
;;;;
;;;; A program uses it as a library (MAKE-DAEMON, DAEMON-STEP or DAEMON-RUN,
;;;; DAEMON-SEND, an event hook), or runs it as a process with
;;;; scripts/cl-fips-node.

(defpackage #:cl-fips.daemon
  (:use #:common-lisp)
  (:export #:make-daemon #:daemon-start #:daemon-step #:daemon-run #:daemon-stop
           #:daemon-node #:daemon-npub #:daemon-udp-port #:daemon-tcp-port
           #:daemon-send #:daemon-peer-up-p #:daemon-on-event #:daemon-stopping
           #:load-config #:load-or-create-identity #:write-identity
           #:format-event #:main))

(in-package #:cl-fips.daemon)

(defconstant +backoff-min-ms+ 1000)
(defconstant +backoff-max-ms+ 60000)
(defconstant +accept-timeout-ms+ 3000
  "How long an accepted TCP connection may take to deliver its whole msg1 once it
   has become readable.")
(defconstant +max-pending-sends+ 64 "DataPackets queued per peer while its session opens.")

(defun clock-ms () (floor (* 1000 (get-internal-real-time)) internal-time-units-per-second))

;;; --- configuration and identity ------------------------------------------------------

(defun load-config (path)
  "Read the config plist at PATH.  Relative file names in it are resolved against
   PATH's directory."
  (let ((*read-eval* nil) (*package* (find-package '#:cl-fips.daemon)))
    (with-open-file (in path)
      (let ((form (read in)))
        (unless (and (listp form) (evenp (length form)))
          (error "~a: the config must be a property list" path))
        (list* :config-dir (make-pathname :name nil :type nil :defaults (truename path)) form)))))

(defun parse-host-port (string)
  "\"host:port\" -> (values host port)."
  (let ((colon (position #\: string :from-end t)))
    (unless colon (error "~s is not host:port" string))
    (values (string-trim "[]" (subseq string 0 colon))
            (parse-integer string :start (1+ colon)))))

(defun write-identity (path keypair)
  "Write KEYPAIR's nsec to PATH (mode 0600, as upstream's write_key_file) and its
   npub to PATH with type pub."
  (let ((nsec (cl-fips:nsec-encode (secp256k1-fast:int-to-bytes32
                                    (secp256k1-fast.ecdh::keypair-secret keypair)))))
    (with-open-file (o path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (sb-posix:chmod (namestring path) #o600)
      (write-line nsec o))
    (with-open-file (o (make-pathname :type "pub" :defaults path)
                       :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line (cl-fips:npub-encode (secp256k1-fast.ecdh:keypair-public-bytes keypair)) o))
    path))

(defun load-or-create-identity (path)
  "The key pair in PATH (an nsec or 64 hex digits on its first line), or a new one
   written there.  Returns (values keypair created-p)."
  (if (probe-file path)
      (let ((line (string-trim '(#\Space #\Tab #\Return #\Newline)
                               (with-open-file (in path) (or (read-line in nil) "")))))
        (values (secp256k1-fast.ecdh:keypair-from-secret
                 (if (and (> (length line) 5) (string-equal "nsec1" line :end2 5))
                     (cl-fips:nsec-decode line)
                     (let ((v (make-array 32 :element-type '(unsigned-byte 8))))
                       (unless (= (length line) 64) (error "~a: not an nsec or 64 hex digits" path))
                       (dotimes (i 32 v)
                         (setf (aref v i) (parse-integer line :start (* 2 i) :end (+ 2 (* 2 i))
                                                              :radix 16))))))
                nil))
      (let ((kp (cl-fips:generate-keypair)))
        (write-identity path kp)
        (values kp t))))

;;; --- the daemon ------------------------------------------------------------------

(defstruct peer
  npub key addr alias transport host port
  (state :idle)                         ; :idle, :dialing, :up
  (next-attempt 0) (backoff +backoff-min-ms+)
  link dial dial-socket)

(defstruct (daemon (:constructor %make-daemon))
  config node static epoch
  udp tcp-listener
  (links (make-hash-table :test 'eq))   ; link -> plist (:transport :socket :peer)
  (accepting '())                       ; ((socket . port) ...) TCP, msg1 not yet read
  (peers '())
  (pending (make-hash-table :test 'equalp)) ; node_addr -> list of (data src dst)
  (echo-ports '())
  (on-event nil)                        ; (lambda (daemon event)) or NIL
  (log *standard-output*)
  (started 0) (stopping nil))

(defun daemon-npub (d) (cl-fips:npub-encode (secp256k1-fast.ecdh:keypair-public-bytes (daemon-static d))))
(defun daemon-udp-port (d) (and (daemon-udp d) (cl-fips.transport:udp-endpoint-local-port (daemon-udp d))))
(defun daemon-tcp-port (d) (and (daemon-tcp-listener d)
                                (cl-fips.transport:tcp-listener-port (daemon-tcp-listener d))))
(defun daemon-now (d) (- (clock-ms) (daemon-started d)))

(defun %resolve (config path)
  (merge-pathnames path (or (getf config :config-dir) *default-pathname-defaults*)))

(defun make-daemon (config &key keypair on-event (log *standard-output*))
  "A daemon for CONFIG (a plist, as LOAD-CONFIG returns).  KEYPAIR overrides the
   identity in the config.  ON-EVENT is called with (daemon event) for every node
   event and the daemon's own (:peer-up ...), (:peer-down ...), (:dial-failed ...)."
  (let* ((id (getf config :identity))
         (kp (or keypair
                 (if (getf id :key-file)
                     (load-or-create-identity (%resolve config (getf id :key-file)))
                     (cl-fips:generate-keypair)))))
    (%make-daemon
     :config config :static kp :epoch (natrium:random-bytes 8)
     :node (cl-fips:make-fips-node kp)
     :echo-ports (getf config :echo-ports)
     :on-event on-event :log log
     :peers (mapcar (lambda (p)
                      (multiple-value-bind (host port) (parse-host-port (getf p :addr))
                        (let ((key (cl-fips:npub-decode (getf p :npub))))
                          (make-peer :npub (getf p :npub) :key key :addr (cl-fips:node-addr key)
                                     :alias (getf p :alias)
                                     :transport (or (getf p :transport) :udp)
                                     :host host :port port))))
                    (getf config :peers)))))

(defun daemon-start (d)
  "Open the configured listeners.  Returns D."
  (let ((config (daemon-config d)))
    (setf (daemon-started d) (clock-ms))
    (let ((udp (getf config :udp)))
      (when udp
        (multiple-value-bind (host port) (parse-host-port (or (getf udp :bind) "0.0.0.0:2121"))
          (setf (daemon-udp d) (cl-fips.transport:udp-open :host host :port port)))))
    (let ((tcp (getf config :tcp)))
      (when tcp
        (multiple-value-bind (host port) (parse-host-port (or (getf tcp :bind) "127.0.0.1:8443"))
          (setf (daemon-tcp-listener d) (cl-fips.transport:tcp-listen :host host :port port)))))
    (%emit d (list :started (daemon-npub d) (daemon-udp-port d) (daemon-tcp-port d)))
    d))

(defun daemon-stop (d)
  "Close every link, dial and listener."
  (setf (daemon-stopping d) t)
  (dolist (l (copy-list (cl-fips:fips-node-links (daemon-node d))))
    (cl-fips:node-remove-link (daemon-node d) l))
  (dolist (p (daemon-peers d))
    (when (peer-dial p) (ignore-errors (cl-fips:byte-port-close (cl-fips:link-dial-port (peer-dial p)))))
    (setf (peer-dial p) nil (peer-state p) :idle))
  (dolist (a (daemon-accepting d)) (ignore-errors (cl-fips:byte-port-close (cdr a))))
  (setf (daemon-accepting d) nil)
  (when (daemon-udp d) (cl-fips.transport:udp-close (daemon-udp d)))
  (when (daemon-tcp-listener d) (cl-fips.transport:tcp-listener-close (daemon-tcp-listener d)))
  d)

;;; --- events ----------------------------------------------------------------------

(defun %short (bytes) (format nil "~(~{~2,'0x~}~)" (coerce (subseq bytes 0 (min 4 (length bytes))) 'list)))

(defun format-event (event)
  "A one-line description of EVENT; links and addresses shortened."
  (format nil "~(~a~)~{ ~a~}" (first event)
          (mapcar (lambda (x)
                    (cond ((typep x '(vector (unsigned-byte 8)))
                           (if (= (length x) 16) (%short x) (format nil "<~d bytes>" (length x))))
                          ((cl-fips::stream-link-p x)
                           (format nil "link:~a" (%short (cl-fips:node-link-peer x))))
                          (t (princ-to-string x))))
                  (rest event))))

(defun %emit (d event)
  (when (daemon-log d)
    (format (daemon-log d) "~&~8,3f ~a~%" (/ (daemon-now d) 1000) (format-event event))
    (force-output (daemon-log d)))
  (when (daemon-on-event d) (funcall (daemon-on-event d) d event)))

;;; --- links -----------------------------------------------------------------------

(defun %peer-for-addr (d addr) (find addr (daemon-peers d) :key #'peer-addr :test #'equalp))

(defun %schedule-redial (d p now &optional reason)
  (let ((b (peer-backoff p)))
    (setf (peer-state p) :idle (peer-link p) nil (peer-dial p) nil (peer-dial-socket p) nil
          (peer-next-attempt p) (+ now b (random (max 1 (floor b 4))))
          (peer-backoff p) (min +backoff-max-ms+ (* 2 b)))
    (when reason (%emit d (list :peer-down (or (peer-alias p) (peer-npub p)) reason)))))

(defun %add-link (d link transport socket)
  (let* ((node (daemon-node d))
         (peer (%peer-for-addr d (cl-fips:node-link-peer link))))
    ;; a peer that dials us again (it restarted) replaces the link we held
    (when peer
      (when (and (peer-link peer) (member (peer-link peer) (cl-fips:fips-node-links node)))
        (%drop-link d (peer-link peer)))
      (when (peer-dial peer)
        (ignore-errors (cl-fips:byte-port-close (cl-fips:link-dial-port (peer-dial peer))))
        (setf (peer-dial peer) nil))
      (setf (peer-state peer) :up (peer-link peer) link (peer-backoff peer) +backoff-min-ms+))
    (cl-fips:node-add-link node link)
    (setf (gethash link (daemon-links d)) (list :transport transport :socket socket :peer peer))
    (%emit d (list :peer-up (if peer (or (peer-alias peer) (peer-npub peer)) (cl-fips:node-link-peer link))
                   transport))))

(defun %drop-link (d link)
  (cl-fips:node-remove-link (daemon-node d) link)
  (%forget-link d link))

(defun %forget-link (d link)
  "LINK is gone from the node; drop our record of it and schedule a redial."
  (let ((info (gethash link (daemon-links d))))
    (remhash link (daemon-links d))
    (let ((p (getf info :peer)))
      (when (and p (eq (peer-link p) link))
        (%schedule-redial d p (daemon-now d) :link-closed)))))

(defun %link-opts (d transport)
  (list :mtu (if (eq transport :udp) cl-fips.transport:+udp-mtu+ cl-fips:+default-stream-mtu+)
        :routing (cl-fips:fips-node-tree (daemon-node d))))

;;; --- dialling --------------------------------------------------------------------

(defun %start-dial (d p now)
  (handler-case
      (multiple-value-bind (port socket)
          (ecase (peer-transport p)
            (:udp (unless (daemon-udp d) (error "no UDP endpoint is configured"))
             (cl-fips.transport:udp-peer-port (daemon-udp d) (peer-host p) (peer-port p)))
            (:tcp (cl-fips.transport:tcp-connect (peer-host p) (peer-port p) :timeout-secs 5)))
        (setf (peer-dial p)
              (apply #'cl-fips:stream-link-dial port (daemon-static d) (peer-key p) (daemon-epoch d)
                     :now-ms now (%link-opts d (peer-transport p)))
              (peer-dial-socket p) socket
              (peer-state p) :dialing))
    (error (e)
      (%emit d (list :dial-failed (or (peer-alias p) (peer-npub p)) (princ-to-string e)))
      (%schedule-redial d p now))))

(defun %dial-input (d p)
  "Input for P's dial: one packet."
  (handler-case
      (let ((link (cl-fips:link-dial-receive (peer-dial p)
                                             :timeout-ms (%transport-wait (peer-transport p)))))
        (when link
          (setf (peer-dial p) nil)
          (%add-link d link (peer-transport p) (peer-dial-socket p))))
    (cl-fips:link-error (e)
      (when (cl-fips:link-error-fatal-p e)
        (%emit d (list :dial-failed (or (peer-alias p) (peer-npub p)) (cl-fips:link-error-reason e)))
        (%schedule-redial d p (daemon-now d))))))

;;; --- the step --------------------------------------------------------------------

(defun %handle-node-events (d events)
  (dolist (ev events)
    (%emit d ev)
    (case (first ev)
      (:link-closed (%forget-link d (third ev)))
      ((:established :accepted) (%flush-pending d (second ev)))
      (:data
       (destructuring-bind (peer sp dp data ts) (rest ev)
         (declare (ignore ts))
         (when (member dp (daemon-echo-ports d))
           (ignore-errors (daemon-send d peer data :src-port dp :dst-port sp))))))))

(defconstant +tcp-packet-ms+ 2000
  "Once a TCP socket is readable, how long the rest of a packet may take to arrive
   (a packet can span segments).  A datagram is whole or absent, so UDP waits 0.")

(defun %transport-wait (transport) (if (eq transport :tcp) +tcp-packet-ms+ 0))

(defun %receive (d link)
  (%handle-node-events d (cl-fips:node-receive
                          (daemon-node d) link
                          :timeout-ms (%transport-wait (getf (gethash link (daemon-links d)) :transport))
                          :now (daemon-now d))))

(defun %tcp-ready (socket ready)
  (or (member socket ready) (cl-fips.transport:tcp-socket-buffered-p socket)))

(defun %wait-sockets (d)
  (let ((s '()))
    (when (daemon-udp d) (push (cl-fips.transport:udp-endpoint-socket (daemon-udp d)) s))
    (when (daemon-tcp-listener d) (push (daemon-tcp-listener d) s))
    (maphash (lambda (l info)
               (when (and (eq (getf info :transport) :tcp)
                          (not (cl-fips:byte-port-closed (cl-fips::stream-link-port l))))
                 (push (getf info :socket) s)))
             (daemon-links d))
    (dolist (p (daemon-peers d))
      (when (and (peer-dial p) (eq (peer-transport p) :tcp)) (push (peer-dial-socket p) s)))
    (dolist (a (daemon-accepting d)) (push (car a) s))
    s))

(defun %buffered-anywhere-p (d)
  (or (loop for info being the hash-values of (daemon-links d)
            thereis (and (eq (getf info :transport) :tcp)
                         (cl-fips.transport:tcp-socket-buffered-p (getf info :socket))))
      (and (daemon-udp d)
           (or (cl-fips.transport:udp-accept-pending-p (daemon-udp d))
               (loop for l being the hash-keys of (daemon-links d)
                     thereis (cl-fips.transport:udp-port-ready-p (daemon-udp d) (cl-fips::stream-link-port l)))))))

(defun daemon-step (d &key (max-wait-ms 200))
  "One turn of the loop: start due dials, wait up to MAX-WAIT-MS for input, read
   everything that arrived, then tick the node and the dials."
  (let ((now (daemon-now d)))
    ;; dials that are due
    (dolist (p (daemon-peers d))
      (when (and (eq (peer-state p) :idle) (>= now (peer-next-attempt p)))
        (%start-dial d p now)))
    ;; wait
    (let* ((sockets (%wait-sockets d))
           (wait (if (%buffered-anywhere-p d) 0 max-wait-ms))
           (ready (and sockets
                       (handler-case
                           (usocket:wait-for-input sockets :timeout (/ wait 1000d0) :ready-only t)
                         (error () nil)))))
      (when (and (null sockets) (plusp wait)) (sleep (/ wait 1000d0)))
      ;; UDP: drain the socket, then every queue
      (let ((udp (daemon-udp d)))
        (when udp
          (cl-fips.transport:udp-pump udp :timeout-ms 0)
          (dolist (p (daemon-peers d))
            (when (and (peer-dial p) (eq (peer-transport p) :udp))
              (loop while (and (peer-dial p)
                               (cl-fips.transport:udp-port-ready-p udp (cl-fips:link-dial-port (peer-dial p))))
                    do (%dial-input d p))))
          (loop for (port host) = (multiple-value-list (cl-fips.transport:udp-accept udp))
                while port
                do (handler-case
                       (%add-link d (apply #'cl-fips:stream-link-accept port (daemon-static d) (daemon-epoch d)
                                           :timeout-ms 0 (%link-opts d :udp))
                                  :udp nil)
                     (cl-fips:link-error (e)
                       (%emit d (list :accept-failed host (cl-fips:link-error-reason e))))))
          (loop for l in (copy-list (cl-fips:fips-node-links (daemon-node d)))
                when (eq (getf (gethash l (daemon-links d)) :transport) :udp)
                  do (loop while (and (member l (cl-fips:fips-node-links (daemon-node d)))
                                      (cl-fips.transport:udp-port-ready-p udp (cl-fips::stream-link-port l)))
                           do (%receive d l)))))
      ;; TCP: new connections, handshakes, links, dials
      (let ((listener (daemon-tcp-listener d)))
        (when (and listener (member listener ready))
          (multiple-value-bind (port socket) (cl-fips.transport:tcp-accept listener :timeout-ms 0)
            (when port (push (cons socket port) (daemon-accepting d))))))
      (dolist (a (copy-list (daemon-accepting d)))
        (when (%tcp-ready (car a) ready)
          (setf (daemon-accepting d) (remove a (daemon-accepting d)))
          (handler-case
              (%add-link d (apply #'cl-fips:stream-link-accept (cdr a) (daemon-static d) (daemon-epoch d)
                                  :timeout-ms +accept-timeout-ms+ (%link-opts d :tcp))
                         :tcp (car a))
            (cl-fips:link-error (e) (%emit d (list :accept-failed :tcp (cl-fips:link-error-reason e)))))))
      (dolist (p (daemon-peers d))
        (when (and (peer-dial p) (eq (peer-transport p) :tcp) (%tcp-ready (peer-dial-socket p) ready))
          (%dial-input d p)))
      (loop for l in (copy-list (cl-fips:fips-node-links (daemon-node d)))
            for info = (gethash l (daemon-links d))
            when (eq (getf info :transport) :tcp)
              do (loop while (and (member l (cl-fips:fips-node-links (daemon-node d)))
                                  (%tcp-ready (getf info :socket) ready))
                       do (%receive d l)
                          (setf ready (remove (getf info :socket) ready)))))
    ;; tick
    (let ((now (daemon-now d)))
      (dolist (p (daemon-peers d))
        (when (peer-dial p)
          (handler-case (cl-fips:link-dial-tick (peer-dial p) now)
            (cl-fips:link-error (e)
              (%emit d (list :dial-failed (or (peer-alias p) (peer-npub p)) (cl-fips:link-error-reason e)))
              (%schedule-redial d p now)))))
      (%handle-node-events d (cl-fips:node-tick (daemon-node d) now))
      ;; a link the node dropped without an event (a send that found it dead)
      (let ((gone '()))
        (maphash (lambda (l info) (declare (ignore info))
                   (unless (member l (cl-fips:fips-node-links (daemon-node d))) (push l gone)))
                 (daemon-links d))
        (dolist (l gone) (%forget-link d l)))))
  d)

(defun daemon-run (d &key until (max-wait-ms 200))
  "Step until DAEMON-STOPPING is set, or UNTIL (a function of no arguments) is true."
  (loop until (or (daemon-stopping d) (and until (funcall until)))
        do (daemon-step d :max-wait-ms max-wait-ms))
  d)

;;; --- sending ---------------------------------------------------------------------

(defun %peer-key (d peer)
  "PEER as (values node-addr key-or-nil): an npub string, a 33-byte key, or a 16-byte
   node_addr (whose key we cannot know)."
  (declare (ignore d))
  (etypecase peer
    (string (let ((k (cl-fips:npub-decode peer))) (values (cl-fips:node-addr k) k)))
    ((vector (unsigned-byte 8))
     (ecase (length peer)
       (33 (values (cl-fips:node-addr peer) peer))
       (16 (values peer nil))))))

(defun daemon-peer-up-p (d peer)
  "True if the session with PEER is established."
  (let ((fi (cl-fips:node-session (daemon-node d) (nth-value 0 (%peer-key d peer)))))
    (and fi (eq (cl-fips::fsp-initiator-phase fi) :established))))

(defun %flush-pending (d addr)
  (let ((queued (reverse (gethash addr (daemon-pending d)))))
    (remhash addr (daemon-pending d))
    (dolist (q queued)
      (destructuring-bind (data sp dp) q
        (handler-case (cl-fips:node-send-data (daemon-node d) addr data :src-port sp :dst-port dp
                                                                        :now (daemon-now d))
          (error (e) (%emit d (list :send-failed addr (princ-to-string e)))))))))

(defun daemon-send (d peer data &key (src-port 0) (dst-port 0))
  "Send DATA to PEER (an npub, a 33-byte key, or the node_addr of a peer that has
   a session with us).  With no session yet, one is opened and DATA waits for it.
   Returns :sent or :queued.  Signals CL-FIPS:NODE-ERROR :too-big for DATA that
   cannot fit the outgoing link."
  (multiple-value-bind (addr key) (%peer-key d peer)
    (let* ((node (daemon-node d))
           (fi (cl-fips:node-session node addr))
           (now (daemon-now d)))
      (cond
        ((and fi (eq (cl-fips::fsp-initiator-phase fi) :established))
         (cl-fips:node-send-data node addr data :src-port src-port :dst-port dst-port :now now)
         :sent)
        (t
         (unless (or fi key) (error 'cl-fips:node-error :reason :no-session
                                                        :detail "an unknown node_addr needs its key"))
         (when (>= (length (gethash addr (daemon-pending d))) +max-pending-sends+)
           (error 'cl-fips:node-error :reason :queue-full))
         (push (list data src-port dst-port) (gethash addr (daemon-pending d)))
         (unless fi (cl-fips:node-open-session node key :now now))
         :queued)))))

;;; --- the command line ------------------------------------------------------------

(defun main (args)
  "scripts/cl-fips-node: run CONFIG | keygen FILE | npub FILE."
  (flet ((usage () (format *error-output* "usage: cl-fips-node run CONFIG | keygen FILE | npub FILE~%")
           (sb-ext:exit :code 2)))
    (cond
      ((and (= (length args) 2) (string= (first args) "keygen"))
       (if (probe-file (second args))
           (progn (format *error-output* "~a exists; not overwriting it~%" (second args))
                  (sb-ext:exit :code 1))
           (let ((kp (cl-fips:generate-keypair)))
             (write-identity (second args) kp)
             (format t "~a~%" (cl-fips:npub-encode (secp256k1-fast.ecdh:keypair-public-bytes kp))))))
      ((and (= (length args) 2) (string= (first args) "npub"))
       (let ((kp (load-or-create-identity (second args))))
         (format t "~a~%" (cl-fips:npub-encode (secp256k1-fast.ecdh:keypair-public-bytes kp)))))
      ((and (= (length args) 2) (string= (first args) "run"))
       (let ((d (make-daemon (load-config (second args)))))
         (daemon-start d)
         (handler-case (daemon-run d)
           (sb-sys:interactive-interrupt () nil))
         (daemon-stop d)))
      (t (usage)))))
