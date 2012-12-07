{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import Control.Applicative
import Control.Monad

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Test.QuickCheck
import Test.QuickCheck.Test
import Test.Framework.Providers.QuickCheck2 (testProperty)

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Crypto.Cipher.RC4 as RC4

-- taken from wikipedia pages
kats :: [ (B.ByteString, B.ByteString, B.ByteString) ]
kats =
    [   ("Key"
        ,"Plaintext"
        ,B.pack [0xBB,0xF3,0x16,0xE8,0xD9,0x40,0xAF,0x0A,0xD3]
        )
    ,   ("Wiki"
        ,"pedia"
        ,B.pack [0x10,0x21,0xBF,0x04,0x20]
        )
    ,   ("Secret"
        ,"Attack at dawn"
        ,B.pack [0x45,0xA0,0x1F,0x64,0x5F,0xC3,0x5B,0x38,0x35,0x52,0x54,0x4B,0x9B,0xF5]
        )
    ]

runKat (key,plainText,cipherText) =
       snd (RC4.combine ctx plainText)  == cipherText
    && snd (RC4.combine ctx cipherText) == plainText
    where ctx = RC4.initCtx $ key

katToTestProperty (kat, i) = testProperty ("KAT " ++ show i) (runKat kat)

data RC4Unit = RC4Unit B.ByteString B.ByteString
    deriving (Show)

instance Arbitrary RC4Unit where
    arbitrary = RC4Unit <$> generateKey <*> generatePlaintext

generateKey = choose (1, 284) >>= \sz -> (B.pack <$> replicateM sz arbitrary)
generatePlaintext = choose (0,324) >>= \sz -> (B.pack <$> replicateM sz arbitrary)

runOp f1 f2 (RC4Unit key plainText) =
    let ctx = RC4.initCtx key
     in (snd $ f2 ctx $ snd $ f1 ctx plainText) == plainText

tests =
    [ testGroup "KAT-RC4" $ map katToTestProperty $ zip kats [0..]
    , testGroup "id"
        [ testProperty "combine.combine" (runOp RC4.combine RC4.combine)
        ]
    ]

main = defaultMain tests
