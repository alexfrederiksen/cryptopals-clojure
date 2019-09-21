(ns cryptopals.core
  (:require [cryptopals.codecs :refer :all]
            [cryptopals.bytestring-utils :as b]
            [clojure.java.io :as io]
            [clojure.string :as string]
            [clojure.test :refer :all]
            [eftest.runner :as eftest])
  (:gen-class))

;;; ############################################################################
;;;  TESTING
;;; ############################################################################

;;; CHALLENGE 1 ################################################################

(def test-hex (str "49276d206b696c6c696e6720796f" 
                   "757220627261696e206c696b6520" 
                   "6120706f69736f6e6f7573206d75" 
                   "7368726f6f6d"))

(deftest test-challenge1
  (testing "Challenge 1"
    (is (-> (decode-hex test-hex)
            (encode-base64)
            (= (str "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWt" 
                    "lIGEgcG9pc29ub3VzIG11c2hyb29t"))))))

;;; CHALLENGE 2 ################################################################

(def test-xor1 (decode-hex "1c0111001f010100061a024b53535009181c"))
(def test-xor2 (decode-hex "686974207468652062756c6c277320657965"))

(deftest test-challenge2
  (testing "Challenge 2"
    (is (-> (b/xor test-xor1 test-xor2) 
            (encode-hex)
            (= "746865206b696420646f6e277420706c6179")))))

;;; CHALLENGE 3 ################################################################

(def test-single-cipher (-> (str "1b37373331363f78151b7f2" 
                                 "b783431333d78397828372d" 
                                 "363c78373e783a393b3736") 
                            (decode-hex)))

(def alpha? (set " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"))

(defn char-freq
  [s]
  (reduce (fn [[n m] k] 
            (vector (inc n) (update m k (fnil inc 0)))) [0 {}] 
          (string/lower-case (apply str s))))


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

(defn nilf
  [f k]
  (comp (fnil identity k) f))

(defn score-map
  "Scores given map m by perfect map p using measure function f"
  [m p f]
  (as-> (map #(apply f %) (map (juxt m (nilf p -10)) (keys m))) diffs
    (reduce + 0.0 diffs)))


(defn l2-norm
  [a b]
  (as-> (- b a) x
    (* x x)))

(defn l1-norm
  [a b]
  (java.lang.Math/abs (- b a)))

(defn score-xor
  ([bs xor]
   (score-xor bs xor english-freq l1-norm))
  ([bs xor good-freqs norm]
   (-> (b/xor bs (repeat xor))
       (encode-ascii)
       (char-freq-percent)
       (score-map good-freqs norm))))

(defn decrypt-single-xor
  [bs]
  (apply min-key #(score-xor bs %) (range 256)))

;(as-> (decipher-xor test-single-cipher) xor
;      (b/xor test-single-cipher (repeat xor))
;      (encode-ascii xor))

(deftest test-challenge3
  (testing "Challenge 3"
    (is (-> (decrypt-single-xor test-single-cipher)
            (= 88)))))

;;; CHALLENGE 4 ################################################################

(def xored-lines (as-> (io/resource "challenge4.txt") x
                       (slurp x)
                       (string/split x #"\n")
                       (map decode-hex x)
                       (vec x)))

(def decrypt-all-xor 
  "Returns [score xor line-number]"
  (-> (fn [lines]
        (map #(let [xor (decrypt-single-xor %1)
                    score (score-xor %1 xor)]
                (vector score xor %2)) 
             lines (range)))
      (memoize)))

(defn find-xor-encrypted
  "Returns [score xor line-number]"
  [lines]
  (let [decrypted (decrypt-all-xor lines)]
    (apply min-key first decrypted)))

;(decrypt-all-xor xored-lines)

; find xor'ed string
(deftest test-challenge4
  (testing "Challenge 4"
    (let [[score xor line-number] (find-xor-encrypted xored-lines)
           line (xored-lines line-number)]
      (is (= xor 53))
      (is (= line-number 170)))))

;;; CHALLENGE 5 ################################################################

(def test-xor-repeat (str "Burning 'em, if you ain't quick " 
                          "and nimble\nI go crazy when I hear a cymbal"))


(defn xor-repeating
  [db kb]
  (b/xor db (cycle kb)))

(deftest test-challenge5
  (testing "Challenge 5"
    (is (= (-> (xor-repeating (decode-ascii test-xor-repeat) (decode-ascii "ICE"))
               (encode-hex))
           (str "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d6"
                "3343c2a26226324272765272a282b2f20430a652e2c652a3124"
                "333a653e2b2027630c692b20283165286326302e27282f")))))
        
;;; CHALLENGE 6 ################################################################

(def repeat-xored-data (as-> (io/resource "challenge6.txt") x
                        (slurp x)
                        (string/split x #"\n")
                        (string/join x)
                        (decode-base64 x)))

(defn test-keysize
  [bs ksize n]
  (let [dists (map #(/ (apply b/hamming-dist %) (double ksize)) 
        (take n (partition 2 1 (partition ksize bs))))]
    (/ (apply + dists) (double (count dists)))))

(defn find-keysize
  "Returns sorted vector of likely keysizes"
  [bs]
  (as-> (map #(vector (test-keysize bs % 20) %) (range 2 40)) x
        (sort x)
        (map second x)))

(defn decrypt-blocks
  [bs ksize]
  (as-> (partition ksize bs) x
    (apply map vector x)
    (map decrypt-single-xor x)))

(deftest test-challenge6
  (testing "Challenge 6:"
    (testing "Hamming distance"
      (is (= (b/hamming-dist (decode-ascii "this is a test")
                             (decode-ascii "wokka wokka!!!")) 
             37)))
    (testing "Repeating key decryption"
      (let [ksize (-> (find-keysize repeat-xored-data)
                      (first))
            k (-> (decrypt-blocks repeat-xored-data ksize)
                  (encode-ascii))] 
        (is (= ksize 29))
        (is (= k "Terminator X: Bring the noise"))))))

(defn testall
  []
  (eftest/run-tests (eftest/find-tests *ns*)))

;;; CHALLENGE 7 ################################################################



(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!"))
