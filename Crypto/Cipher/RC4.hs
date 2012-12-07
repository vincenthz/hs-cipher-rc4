{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Cipher.RC4
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Initial FFI implementation by Peter White <peter@janrain.com>
--
-- Reorganized and simplified to have an opaque context.
--
module Crypto.Cipher.RC4
    ( Ctx(..)
    , encrypt
    , decrypt
    , initCtx
    ) where

import Data.Word
import Foreign.Ptr
import Foreign.ForeignPtr
import System.IO.Unsafe (unsafeDupablePerformIO)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import Control.Applicative ((<$>))

----------------------------------------------------------------------

-- | The encryption context for RC4
newtype Ctx = Ctx B.ByteString

instance Show Ctx where
    show _ = "RC4.Ctx"

-- | C Call for initializing the encryptor
foreign import ccall unsafe "rc4.h rc4_init"
    c_initCtx :: Ptr Word8 ->   -- ^ The encryption key
                 Word32    ->   -- ^ The key length
                 Ptr Ctx   ->   -- ^ The context
                 IO ()

foreign import ccall unsafe "rc4.h rc4_encrypt"
    c_rc4 :: Ptr Ctx        -- ^ Pointer to the permutation
          -> Ptr Word8      -- ^ Pointer to the clear text
          -> Word32         -- ^ Length of the clear text
          -> Ptr Word8      -- ^ Output buffer
          -> IO ()

withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f = withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = B.toForeignPtr b

-- | RC4 context initialization.
--
-- seed the context with an initial key. the key size need to be
-- adequate otherwise 
initCtx :: B.ByteString -- ^ The key
        -> Ctx          -- ^ The RC4 context with the key mixed in
initCtx key = unsafeDupablePerformIO $
    Ctx <$> (B.create 264 $ \ctx -> B.useAsCStringLen key $ \(keyPtr,keyLen) -> c_initCtx (castPtr keyPtr) (fromIntegral keyLen) (castPtr ctx))

-- | RC4 encryption
encrypt :: Ctx                 -- ^ The encryption context
        -> B.ByteString        -- ^ The plaintext
        -> (Ctx, B.ByteString) -- ^ The new encryption context, and the ciphertext
encrypt (Ctx cctx) clearText = unsafeDupablePerformIO $
    B.mallocByteString 264 >>= \dctx ->
    B.mallocByteString len >>= \outfptr ->
    withByteStringPtr clearText $ \clearPtr ->
    withByteStringPtr cctx $ \srcCtx ->
    withForeignPtr dctx $ \dstCtx -> do
    withForeignPtr outfptr $ \outptr -> do
        B.memcpy dstCtx srcCtx 264
        c_rc4 (castPtr dstCtx) clearPtr (fromIntegral len) outptr
        return $! (Ctx $! B.PS dctx 0 264, B.PS outfptr 0 len)
    where len = B.length clearText

-- | RC4 decryption. For RC4, decrypt = encrypt
--
--   See comments under the encrypt function.
--
decrypt :: Ctx -> B.ByteString -> (Ctx, B.ByteString)
decrypt = encrypt
