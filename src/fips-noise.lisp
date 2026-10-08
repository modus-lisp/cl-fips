;;;; fips-noise.lisp -- binds the FIPS suite (secp256k1) to natrium's Noise IK and XK.
;;;;
;;;; The handshake and transport are natrium.noise's, generic over the DH group.
;;;; This file supplies the group FIPS uses: secp256k1 keys (secp256k1-fast.ecdh),
;;;; the FIPS ECDH, and the normalisation of the responder's key in the pre-message.
;;;; Authority: upstream jmcorgan/fips @ 57bc510, src/noise/handshake.rs
;;;;   * PUBKEY_SIZE = 33: compressed SEC1 on the wire.
;;;;   * normalize_for_premessage: byte 0 forced to 0x02 before mix_hash.
;;;;   * new_initiator / new_responder: IK protocol name Noise_IK_secp256k1_…
;;;;   * new_xk_initiator / new_xk_responder: XK protocol name (mod.rs
;;;;     PROTOCOL_NAME_XK) Noise_XK_secp256k1_…, same pre-message normalisation.
;;;;   * generate_ephemeral: a fresh random scalar in [1, n).

(in-package #:cl-fips)

(defun generate-keypair ()
  "Fresh random secp256k1 key pair from natrium's CSPRNG."
  (secp256k1-fast:secp-init)
  (loop
    (let* ((b (natrium:random-bytes 32))
           (k (secp256k1-fast:bytes-to-int b)))
      (when (< 0 k secp256k1-fast:*secp256k1-n*)
        (return (secp256k1-fast.ecdh:keypair-from-secret b))))))

(defun normalize-for-premessage (pubkey-bytes)
  "handshake.rs normalize_for_premessage: the compressed key with byte 0 = 0x02."
  (let ((v (copy-seq pubkey-bytes))) (setf (aref v 0) 2) v))

(defparameter *fips-suite*
  (natrium.noise:make-noise-suite
   :name "secp256k1"
   :ik-name "Noise_IK_secp256k1_ChaChaPoly_SHA256"
   :xk-name "Noise_XK_secp256k1_ChaChaPoly_SHA256"
   :pubkey-size secp256k1-fast.ecdh:+pubkey-size+
   :generate #'generate-keypair
   :public-bytes #'secp256k1-fast.ecdh:keypair-public-bytes
   :decode #'secp256k1-fast.ecdh:decode-pubkey
   :dh #'secp256k1-fast.ecdh:noise-dh
   :premessage #'normalize-for-premessage)
  "The FIPS Noise suite.  natrium.noise knows nothing of secp256k1.")

(defun fips-make-ik-initiator (static remote-static-bytes local-epoch)
  (natrium.noise:make-ik-initiator *fips-suite* static remote-static-bytes local-epoch))

(defun fips-make-ik-responder (static local-epoch)
  (natrium.noise:make-ik-responder *fips-suite* static local-epoch))

(defun fips-make-xk-initiator (static remote-static-bytes local-epoch)
  "FSP (session layer) initiator: knows the responder's static key."
  (natrium.noise:make-xk-initiator *fips-suite* static remote-static-bytes local-epoch))

(defun fips-make-xk-responder (static local-epoch)
  "FSP responder: learns the initiator's static key from msg3."
  (natrium.noise:make-xk-responder *fips-suite* static local-epoch))
