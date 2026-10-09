;;;; cl-fips.asd
;;;;
;;;; A pure-Common-Lisp FIPS (Free Internetworking Peering System) client.  The
;;;; first layer is the wire format: byte-exact codecs for the FMP and FSP headers
;;;; and the stream framing rule.  No dependencies, no I/O, no crypto yet -- the
;;;; codecs are plain octet arithmetic so the same file can later run on modus.

(defsystem "cl-fips"
  :description "A FIPS (Free Internetworking Peering System) node in portable Common Lisp."
  :version "0.9.0"
  :author "ynniv"
  :license "MIT"
  ;; Both are pure CL with no FFI: natrium (SHA-256, HKDF, ChaCha20-Poly1305,
  ;; CSPRNG) and secp256k1-fast (point arithmetic).
  :depends-on ("natrium" "secp256k1-fast")
  :serial t
  :components ((:module "src" :serial t
                :components ((:file "packages")
                             (:file "wire")
                             (:file "fips-noise")
                             (:file "fmp")
                             (:file "identity")
                             (:file "rekey")
                             (:file "mmp")
                             (:file "stp")
                             (:file "bloom")
                             (:file "tree")
                             (:file "fsp")
                             (:file "route")
                             (:file "lookup")
                             (:file "ipv6-shim")
                             (:file "link")
                             (:file "node"))))
  :in-order-to ((test-op (test-op "cl-fips/test"))))

(defsystem "cl-fips/test"
  :description "Wire-codec tests, and Noise IK interop tests against the upstream Rust oracle."
  :depends-on ("cl-fips")
  :serial t
  :components ((:module "test" :serial t
                :components ((:file "test") (:file "noise-test") (:file "frame-test")
                             (:file "try-read-test")
                             (:file "rekey-test")
                             (:file "mmp-test")
                             (:file "routing-test")
                             (:file "fsp-test")
                             (:file "transit-test")
                             (:file "node-test")
                             (:file "lookup-test")
                             (:file "review-test")
                             (:file "link-test"))))
  :perform (test-op (o c) (uiop:symbol-call '#:cl-fips.test '#:run-all)))

;;; The socket adapter.  Development-only: usocket on SBCL.  Nothing in src/
;;; depends on it; it only supplies the two closures of a BYTE-PORT.
;;; The host adapters: UDP and TCP links over cl-transport/sockets (sb-bsd-sockets:
;;; SBCL and hosted modus alike).  Nothing in src/ depends on them.
(defsystem "cl-fips/transport"
  :description "UDP and TCP adapters for cl-fips links (sb-bsd-sockets: SBCL and modus)."
  :depends-on ("cl-fips" "cl-transport/sockets")
  :components ((:module "transport" :serial t
                :components ((:file "package") (:file "udp") (:file "tcp")))))

;;; The old name of the UDP-only part, kept so a config that names it still loads.
(defsystem "cl-fips/udp" :depends-on ("cl-fips/transport"))

(defsystem "cl-fips/daemon"
  :description "A runnable FIPS node on SBCL: config, identity file, UDP and TCP listeners, peers."
  :depends-on ("cl-fips/transport" (:feature :sbcl (:require "sb-posix")))
  :components ((:module "transport" :components ((:file "daemon")))))

(defsystem "cl-fips/stream"
  :description "Byte streams over FIPS between cl-fips nodes, a TCP gateway, and
                cl-transport's :fips backend (SBCL)."
  :depends-on ("cl-fips/daemon" "cl-fips/transport" "cl-transport" "cl-transport/tcp" "bordeaux-threads")
  :components ((:module "transport" :components ((:file "fips-stream")))))

(defsystem "cl-fips/transport-test"
  :description "FMP over real TCP against the upstream Rust oracle."
  :depends-on ("cl-fips/test" "cl-fips/transport" "cl-fips/daemon" "usocket")
  :components ((:module "test" :serial t :components ((:file "tcp-test") (:file "udp-test") (:file "daemon-test")))))
