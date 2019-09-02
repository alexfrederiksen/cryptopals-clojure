(ns cryptopals.codecs)

;;; ############################################################################
;;;  UTILS
;;; ############################################################################

(def index-map
  "Given a seq, creates a mapping element to index"
  (-> (fn [v]
        (reduce #(apply assoc %1 %2) {} 
                (map list v (range))))
      (memoize)))

(defn encode-digit
  [x base]
  (base x))

(defn decode-digit
  [x base]
  ((index-map base) x))

;;; ############################################################################
;;;  BASE64
;;; ############################################################################

(defn decode-base64
  [b64]
  (-> (java.util.Base64/getDecoder) 
      (.decode b64)
      (vec)))

; 4 base64 digits => 24 bits => 3 bytes
(defn encode-base64
  [bs]
  (-> (java.util.Base64/getEncoder) 
      (.encodeToString (into-array Byte/TYPE bs))))

;;; ############################################################################
;;;  HEX
;;; ############################################################################

(def hex (vec "0123456789abcdef"))

; unchecked to allow signed overflow (numbers above 127)
(defn decode-hex-pair
  [hex-pair]
  (unchecked-byte (+ 
    (-> (first hex-pair) (decode-digit hex) (* 16))
    (-> (second hex-pair) (decode-digit hex)))))

(defn decode-hex
  ([hex]
  (if (even? (count hex))
    (transduce (map decode-hex-pair) conj [] (partition 2 hex))
    (decode-hex (str "0" hex)))))

(defn encode-hex
  [bs]
  (-> (fn [b]
        (list (-> (bit-shift-right b 4) (encode-digit hex))
              (-> (bit-and b 0x0F) (encode-digit hex)))) 
      (map bs) (flatten) (#(apply str %))))

;;; ############################################################################
;;;  ASCII
;;; ############################################################################

(defn decode-ascii
  [cs]
  (mapv byte cs))

(defn encode-ascii
  [bs]
  (as-> (map #(char (bit-and % 0xff)) bs) cs
    (apply str cs)))


