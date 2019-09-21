(ns cryptopals.bytestring-utils)

;;; ############################################################################
;;;  BYTE STRING OPERATIONS
;;; ############################################################################

(defn xor
  [bs1 bs2]
  (map bit-xor bs1 bs2))

(defn- byte-count-ones
  [b]
  (reduce + (map #(-> (bit-shift-right b %) 
                      (bit-and 0x01)) (range 8))))

(defn count-ones
  [bs]
  (transduce (map byte-count-ones) + 0 bs))

(defn hamming-dist
  [bs1 bs2]
  (-> (xor bs1 bs2)
      (count-ones)))

