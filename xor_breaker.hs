{-# LANGUAGE OverloadedStrings #-}
import           Data.Bits              (popCount, xor, (.&.))
import           Data.ByteString.Base64 (decodeLenient)
import           Data.ByteString.Char8  (ByteString)
import qualified Data.ByteString.Char8  as C8
import qualified Data.Char              as C
import           Data.Function          (on)
import qualified Data.IntMap.Strict     as IntMap
import           Data.List.Extra        (maximumOn, minimumOn)
import           Data.Tuple.Extra       (first, (&&&))

import           System.Directory       (doesFileExist)

import           Options.Applicative
import           Data.Semigroup         ((<>))

data Args = Args
  { fname    :: FilePath
  , outname  :: FilePath
  , base64 :: Bool }

args :: Parser Args
args = Args
  <$> strArgument
      ( metavar "FILENAME" )
  <*> strOption
      ( long "output"
     <> short 'o'
     <> metavar "OUTFILE"
     <> value "decrypted.txt"
     <> help "The file to output the decrypted contents to." )
  <*> switch
      ( long "base64"
     <> short 'b'
     <> help "Is the input file base64 encoded?" )

main :: IO ()
main = decrypt =<< execParser opts
  where
    opts = info (args <**> helper)
      ( fullDesc
     <> progDesc "Decrypt a file encrypted with repeating key XOR." )

decrypt :: Args -> IO ()
decrypt (Args fname outname base64) = do
  raw <- C8.readFile fname
  let enc = case base64 of
              True -> decodeLenient raw
              False -> raw

  C8.writeFile outname $ breakXOR enc
  putStrLn $ "Decrypted using key: " ++ show (getKey enc)

getKey :: ByteString -> String
getKey enc = map getKeyForBlock . C8.transpose . chunksOf keylen $ enc
  where
    keylen = minimumOn (scoreKeyLen enc) [2..40]

getKeyForBlock :: ByteString -> Char
getKeyForBlock enc = C.chr $ maximumOn (score . flip xorByte enc) [0..0x100]

breakXOR :: ByteString -> ByteString
breakXOR enc = C8.concat
               . C8.transpose
               . map break1
               . C8.transpose
               . chunksOf keylen $ enc
  where
    keylen = minimumOn (scoreKeyLen enc) [2..40]

break1 :: ByteString -> ByteString
break1 = maximumOn score . zipWith xorByte [0..0x100] . repeat

xorByte :: Int -> ByteString -> ByteString
xorByte byte = C8.map (C.chr . xor byte . C.ord)

score :: ByteString -> Int
score = uncurry (+) . (letterScore &&& unprintableScore) . C8.unpack
  where
    letterScore = sum . map (flip (IntMap.findWithDefault (-10)) charScores . C.ord . C.toLower)
    unprintableScore = (*) (-100) . length . filter (not . (C.isAscii .&&. C.isPrint))
    charScores = IntMap.fromDistinctAscList . map (first C.ord) $ [
                   (' ', 0),
                   ('a', 9),
                   ('b', 2),
                   ('c', 3),
                   ('d', 5),
                   ('e', 14),
                   ('f', 3),
                   ('g', 3),
                   ('h', 7),
                   ('i', 8),
                   ('j', 1),
                   ('k', 2),
                   ('l', 5),
                   ('m', 3),
                   ('n', 8),
                   ('o', 9),
                   ('p', 3),
                   ('q', 1),
                   ('r', 7),
                   ('s', 7),
                   ('t', 11),
                   ('u', 4),
                   ('v', 2),
                   ('w', 4),
                   ('x', 1),
                   ('y', 3),
                   ('z', 1) ]

(.&&.) :: (a -> Bool) -> (a -> Bool) -> a -> Bool
(f .&&. g) a = f a && g a

hammingDistance :: ByteString -> ByteString -> Int
hammingDistance a b
  | C8.length a == C8.length b = sum . map popCount $ C8.zipWith (xor `on` C.ord) a b
  | otherwise = error "Lengths of both strings must be equal."

scoreKeyLen :: ByteString -> Int -> Int
scoreKeyLen enc n = sum distances
  where
    blocks = init . chunksOf n $ enc
    distances = zipWith hammingDistance blocks (tail blocks)

chunksOf :: Int -> ByteString -> [ByteString]
chunksOf _ "" = []
chunksOf n bs = C8.take n bs : chunksOf n (C8.drop n bs)
