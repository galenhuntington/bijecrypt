--  A bijective encryption method.

{-# LANGUAGE OverloadedStrings, BangPatterns #-}

import Prelude() 
import BasePrelude

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL

--  For now use SHA-256; SHAKE128 might be preferable.
import qualified Crypto.Hash.SHA256 as H

import Crypto.Cipher.AES128 hiding (blockSize)

import Data.Time

type Key = BS.ByteString

blockSize = 16 :: Int


--  This is all just plumbing for the functions below.

__ = True

bsxor :: BS.ByteString -> BS.ByteString -> BS.ByteString
bsxor a b = BS.pack $ BS.zipWith xor a b

--  buildKey only considers first 128 bits.
mkKey :: Key -> AESKey128
mkKey = fromJust . buildKey . H.hash

--  "Safe" version of splitAt that returns Nothing if string index doesn't exist.
--  No good generic or efficient support for this natural operation.
class Splittable x where
   splitAtM :: Int -> x -> Maybe (x, x)

instance Splittable BS.ByteString where
   splitAtM n msg | BS.length msg < n = Nothing
                  | __     = Just $ BS.splitAt n msg

instance Splittable BL.ByteString where
   --  We don't want to ask for the whole length.
   splitAtM n_ msg = case BL.splitAt n msg of
      spl@(blk, _) | BL.length blk < n -> Nothing
                   | __                -> Just spl
      where n = fromIntegral n_

--  Split into block-sized chunks with flag for full.
--  The last block is never full, but instead may be empty.
toBBlocks :: Splittable x => x -> [(Bool, x)]
toBBlocks = loop where
   loop blob = case splitAtM blockSize blob of
      Just (blk, rest) -> (True, blk) : loop rest
      _                -> [(False, blob)]


--  Operations.

encrypt :: Key -> BS.ByteString -> BS.ByteString
encrypt key msg = BS.concat $ reverse (endgame : encs) where
   --  Null-padded if short.  If this is unsuitable, you must pad yourself.
   msg' = msg <> BS.replicate (blockSize - BS.length msg) 0
   blocks = map snd $ toBBlocks msg'
   rem : penult : rest = reverse blocks
   prehash = H.hashlazy $ BL.fromChunks $ reverse rest
   aes = encryptBlock (mkKey key)
   encs = tail $ scanl' (\lst blk -> aes (lst`bsxor`blk)) endgame rest
   endgame = aes (e1a <> e2b) <> e2a where
      splitaes = BS.splitAt (BS.length rem) . aes
      (e1a, e1b) = splitaes $ penult `bsxor` prehash
      (e2a, e2b) = splitaes $ rem <> e1b

--  Lazy in, lazy out.
decryptLazy :: Key -> BL.ByteString -> BL.ByteString
decryptLazy key enc = BL.fromChunks startloop where
   bblocks = map (second BL.toStrict) $ toBBlocks enc
   startloop = let (_, start) : rest = bblocks in loop H.init start rest
   loop !cx blk ((full, next) : rest)
      | full = dec : loop (H.update cx dec) next rest
      | __   = [ aes (e1a <> e1b) `bsxor` H.finalize cx, ult ]
      where
         aes = decryptBlock (mkKey key)
         dec = aes blk `bsxor` next
         --  Endgame case.
         splitaes = BS.splitAt (BS.length next) . aes
         (e1a, e2b) = splitaes blk
         (ult, e1b) = splitaes $ next <> e2b

--  Obligatory inverse of encrypt; better to use lazy version.
decrypt key = BL.toStrict . decryptLazy key . BL.fromStrict

