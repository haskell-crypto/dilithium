-- |
-- Module      : Crypto.Signing.Dilithium
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
--
-- Provide a bindings to the dilithium library at
-- <https://github.com/pq-crystals/dilithium>
--
-- All the cryptographic material are using dilithium mode 2
--
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.Signing.Dilithium
    ( SecretKey
    , PublicKey
    , generate
    , sign
    , verify
    ) where

import           Data.Word
import           Foreign.Ptr
import           Foreign.C.Types
import           Foreign.Storable
import           Foreign.Marshal.Alloc (alloca, allocaBytes)

import           Crypto.Error
import           Data.ByteArray (ByteArrayAccess, Bytes, ScrubbedBytes, withByteArray)
import qualified Data.ByteArray as B
import           Data.Memory.PtrMethods as B (memCopy)
import           Basement.NormalForm
import           System.IO.Unsafe (unsafePerformIO)

import           Crypto.Signing.Dilithium.Bindings

-- | A Dilithium Secret key (3504 bytes)
newtype SecretKey = SecretKey ScrubbedBytes
    deriving (Show,Eq,ByteArrayAccess)

-- | A Dilithium Public key (1472 bytes)
newtype PublicKey = PublicKey Bytes
    deriving (Show,Eq,ByteArrayAccess)

-- | Dilithium signature (2701 bytes)
newtype Signature = Signature Bytes
    deriving (Show,Eq,ByteArrayAccess)

-- | Generate a new dilithium keypair.
--
-- The API doesn't provide a deterministic way to create keypair
generate :: IO (PublicKey, SecretKey)
generate = do
    (pubKey, secKey) <- B.allocRet secretkeyBytes $ \s ->
                        B.alloc publickeyBytes    $ \p -> c_sign_keypair p s
    pure (PublicKey pubKey, SecretKey secKey)
{-# NOINLINE generate #-}

-- | Sign a message using the key pair
--
-- Due to the API provided, allocate a temporary continuous buffer of the message and the signature
-- before extracting the signature only.
sign :: ByteArrayAccess ba => SecretKey -> ba -> Signature
sign secret message = unsafePerformIO $ do
    !sigBuf <- B.alloc signatureBytes $ \sig -> allocaBytes outputSize $ \sigMsg -> do
                    withByteArray secret  $ \sec ->
                        withByteArray message $ \msg -> alloca $ \tmp -> do
                            c_sign sigMsg tmp msg (toCULL msgLen) sec
                    memCopy sig sigMsg signatureBytes
    pure $ Signature $ sigBuf
  where
    outputSize = signatureBytes + msgLen
    !msgLen = B.length message
{-# NOINLINE sign #-}

-- | Verify a message using a dilithium signature against a dilithium public key
--
-- Note that because of the way the binding is setup, the signature and message
-- are copied to a temporary continuous buffer containing a copy of both
-- before calling verification.
verify :: ByteArrayAccess ba => PublicKey -> ba -> Signature -> Bool
verify public message signatureVal = unsafePerformIO $ allocaBytes outputSize $ \sigMsg ->
    withByteArray signatureVal $ \sig ->
    withByteArray public       $ \pub ->
    withByteArray message      $ \msg ->
    alloca                     $ \(tmp :: Ptr CULLong) -> do
        memCopy sigMsg                            sig signatureBytes
        memCopy (sigMsg `plusPtr` signatureBytes) msg msgLen
        !r <- c_sign_open sigMsg tmp sigMsg (toCULL outputSize) pub
        return $! result r
  where
    result :: CSignOpenResult -> Bool
    result CSignOpenSuccess = True
    result _                = False

    !msgLen = B.length message
    !outputSize = msgLen + signatureBytes
{-# NOINLINE verify #-}

toCULL = fromIntegral
