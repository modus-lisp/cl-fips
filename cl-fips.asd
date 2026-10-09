;;;; cl-fips.asd
;;;;
;;;; A pure-Common-Lisp FIPS (Free Internetworking Peering System) client.  The
;;;; first layer is the wire format: byte-exact codecs for the FMP and FSP headers
;;;; and the stream framing rule.  No dependencies, no I/O, no crypto yet -- the
;;;; codecs are plain octet arithmetic so the same file can later run on modus.

(defsystem "cl-fips"
  :description "FIPS wire codecs and the Noise IK handshake (FMP link layer) in pure CL."
  :version "0.1.0"
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
                             (:file "link"))))
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
                             (:file "link-test"))))
  :perform (test-op (o c) (uiop:symbol-call '#:cl-fips.test '#:run-all)))

;;; The socket adapter.  Development-only: usocket on SBCL.  Nothing in src/
;;; depends on it; it only supplies the two closures of a BYTE-PORT.
(defsystem "cl-fips/transport"
  :description "TCP adapter for cl-fips stream links (usocket; SBCL development use)."
  :depends-on ("cl-fips" "usocket")
  :components ((:module "transport" :components ((:file "tcp")))))

(defsystem "cl-fips/transport-test"
  :description "FMP over real TCP against the upstream Rust oracle."
  :depends-on ("cl-fips/test" "cl-fips/transport")
  :components ((:module "test" :components ((:file "tcp-test")))))
