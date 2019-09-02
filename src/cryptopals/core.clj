(ns cryptopals.core
  (:require [cryptopals.codecs :refer :all]
            [cryptopals.bytestring-utils :as b]
            [clojure.java.io :as io]
            [clojure.string :as string])
  (:gen-class))

;;; ############################################################################
;;;  TESTING
;;; ############################################################################

;;; CHALLENGE 1 ################################################################

(def test-hex (str "49276d206b696c6c696e6720796f" 
                   "757220627261696e206c696b6520" 
                   "6120706f69736f6e6f7573206d75" 
                   "7368726f6f6d"))


(-> (decode-hex test-hex) (encode-base64))

;;; CHALLENGE 2 ################################################################

(def test-xor1 (decode-hex "1c0111001f010100061a024b53535009181c"))
(def test-xor2 (decode-hex "686974207468652062756c6c277320657965"))

(-> (b/test-xor1 test-xor2) (b/test-xor1) (encode-hex))

(-> (encode-base64 test-xor1) (decode-base64) (encode-hex))

;;; CHALLENGE 3 ################################################################

(def test-single-cipher (-> (str "1b37373331363f78151b7f2" 
                                 "b783431333d78397828372d" 
                                 "363c78373e783a393b3736") 
                            (decode-hex)))

(def alpha? (set " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"))
(alpha? \B)

(defn char-freq
  [s]
  (transduce (filter alpha?) 
             (completing (fn [[n m] k] 
               (vector (inc n) (update m k (fnil inc 0)))))
               [0 {}] (string/lower-case s)))

(string/lower-case (apply str [\a \b \C]))

(defn char-freq
  [s]
  (reduce (fn [[n m] k] 
            (vector (inc n) (update m k (fnil inc 0)))) [0 {}] (string/lower-case (apply str s))))


(defn update-values 
  [m f & args]
  (reduce (fn [r [k v]] 
            (assoc r k (apply f v args))) 
          {} m))

(defn char-freq-percent
  [s]
  (as-> (char-freq s) [n m]
        (update-values m #(* (/ 1.0 n) %))))

(def english-freq (-> (io/resource "challenge3.txt")
                      (slurp)
                      (#(filter alpha? %))
                      (char-freq-percent)))

(print english-freq)

(defn nilf
  [f k]
  (comp (fnil identity k) f))

(defn score-map
  "Scores given map m by perfect map p using measure function f"
  [m p f]
  (as-> (map #(apply f %) (map (juxt m (nilf p 0)) (keys m))) diffs
    (reduce + 0.0 diffs)))


(defn l2-norm
  [a b]
  (as-> (- b a) x
    (* x x)))

(defn l1-norm
  [a b]
  (java.lang.Math/abs (- b a)))

(score-map {\a 0.7 \b 0.1} {\b 0.4} l1-norm)

(defn single-byte-xor-decipher
  "Given bytes and a map of average character frequencies (scorer),
   finds most likely ciphers assuming a single byte was xor'ed with
   everything"
  [bs scorer norm]
  (reduce (fn [m xor]
            (let [xored (-> (b/xor bs (repeat xor))
                            (encode-ascii))]
              (assoc m [xor xored] 
                     (score-map (char-freq-percent xored) scorer norm))))
            {} (map unchecked-byte (range 256))))

(defn sort-by-val
  [m]
  (into (sorted-map-by (fn [k1 k2]
                   (compare (m k1) (m k2)))) m))

(defn decipher-xor 
  [bs]
  (-> (single-byte-xor-decipher bs english-freq l1-norm)
      (sort-by-val)
      (first)))

(decipher-xor test-single-cipher)

;;; CHALLENGE 4 ################################################################

(def xored-lines (as-> (io/resource "challenge4.txt") x
                       (slurp x)
                       (string/split x #"\n")
                       (map decode-hex x)))

(def decipher-xored-lines 
  (-> (fn [lines]
        (map decipher-xor xored-lines))
      (memoize)))

(defn find-xor-encrypted
  [lines]
  (let [results (decipher-xored-lines lines)
        min-score (apply min (vals results))] 
    (filter #(<= (val %) min-score) results)))

; find xor'ed string
(find-xor-encrypted xored-lines)

; reverse to hex (found match on line 171)
(-> (find-xor-encrypted xored-lines)
    (first)
    (key)
    ((fn [[xor s]] 
       (as-> (decode-ascii s) x
         (b/xor x (repeat xor))
         (encode-hex x)))))

;;; CHALLENGE 5 ################################################################

(def test-xor-repeat (str "Burning 'em, if you ain't quick " 
                          "and nimble\nI go crazy when I hear a cymbal"))

(defn xor-repeating
  [db kb]
  (-> (b/xor db (cycle kb))))

(-> (xor-repeating (decode-ascii test-xor-repeat) (decode-ascii "ICE"))
    (encode-base64))

;;; CHALLENGE 6 ################################################################

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!"))
