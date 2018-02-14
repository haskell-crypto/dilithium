
import           Crypto.Signing.Dilithium
import qualified Data.ByteArray as B
import           Data.ByteArray (Bytes)
import           Data.ByteArray.Encoding

main :: IO ()
main = do
    (pub, sec) <- generate

    let signAndVerify x = do
            let msg = B.replicate x (fromIntegral x) :: Bytes

            let signature = sign sec msg
            putStrLn $ show (convertToBase Base16 signature :: Bytes)

            let verified = verify pub msg signature
            putStrLn ("verified: " ++ show verified)

    mapM_ signAndVerify [31..64]

