{-# LANGUAGE PatternSynonyms #-}
module Crypto.Signing.Dilithium.Bindings
    ( publickeyBytes
    , secretkeyBytes
    , signatureBytes
    , CMessage
    , CSignedMessage
    , CSignOpenResult
    , pattern CSignOpenSuccess
    , c_sign_keypair
    , c_sign
    , c_sign_open
    ) where

import           Foreign.C.Types
import           Data.Word
import           Foreign.Ptr

#include "api.h"

publickeyBytes, secretkeyBytes, signatureBytes :: Int
publickeyBytes = (#const CRYPTO_PUBLICKEYBYTES)
secretkeyBytes = (#const CRYPTO_SECRETKEYBYTES)
signatureBytes = (#const CRYPTO_BYTES)

type CPublicKey = Ptr Word8
type CSecretKey = Ptr Word8

type CSignedMessage = Ptr Word8
type CMessage = Ptr Word8

type ULL = CULLong

newtype CSignOpenResult = CSignOpenResult CInt

pattern CSignOpenSuccess = CSignOpenResult 0

foreign import ccall unsafe "crypto_sign_keypair"
    c_sign_keypair :: CPublicKey -> CSecretKey -> IO ()

foreign import ccall unsafe "crypto_sign"
    c_sign :: CSignedMessage -> Ptr ULL
           -> CMessage -> ULL
           -> CSecretKey
           -> IO ()

foreign import ccall unsafe "crypto_sign_open"
    c_sign_open :: CMessage -> Ptr ULL
                -> CSignedMessage -> ULL
                -> CPublicKey
                -> IO CSignOpenResult
