module Main where

import Criterion.Main

import Crypto.Cipher.RC4
import qualified Data.ByteString as B
import Control.DeepSeq

instance NFData Ctx where
    rnf (Ctx c) = c `seq` ()

main = defaultMain
    [ bgroup "init"
        [ bench "1"    $ whnf initCtx b1
        , bench "8"    $ whnf initCtx b8
        , bench "32"   $ whnf initCtx b32
        , bench "64"   $ whnf initCtx b64
        , bench "256"  $ whnf initCtx b256
        ]
    , bgroup "encrypt"
        [ bench "8"    $ nf (encrypt ctx) b8
        , bench "32"   $ nf (encrypt ctx) b32
        , bench "64"   $ nf (encrypt ctx) b64
        , bench "256"  $ nf (encrypt ctx) b256
        , bench "1024" $ nf (encrypt ctx) b1024
        ]
    ]
    where b1    = B.replicate 1 0xf7
          b8    = B.replicate 8 0xf7
          b32   = B.replicate 32 0xf7
          b64   = B.replicate 64 0x7f
          b256  = B.replicate 256 0x7f
          b1024 = B.replicate 1024 0x7f
          ctx   = initCtx $ B.pack [1..10]
