{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module SmallCheck where

import           Test.SmallCheck.Series

import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as ByteString
import           Data.LargeWord
import           Data.Text              (Text)
import qualified Data.Text              as Text
import           Data.Word

import           Network.STUN.Internal


instance Monad m => Serial m STUNMessage where
  series = localDepth (const 4) $ cons3 STUNMessage

instance Monad m => Serial m STUNType where
  series = cons0 BindingRequest \/ cons0 BindingResponse

instance Monad m => Serial m STUNAttribute where
  series = cons2 MappedAddressIPv4
           \/ cons2 MappedAddressIPv6
           \/ cons2 ChangeRequest
           \/ cons1 Username
           \/ cons1 MessageIntegrity
           \/ cons1 Fingerprint
           \/ cons1 Realm
           \/ cons1 Software


--------------------------------------------------------------------------------
-- Required instances (orphans)

instance Monad m => Serial m Word8 where
  series = (fromIntegral :: Int -> Word8) <$> series

instance Monad m => Serial m Word16 where
  series = (fromIntegral :: Int -> Word16) <$> series

instance Monad m => Serial m Word32 where
  series = (fromIntegral :: Integer -> Word32) <$> series

instance Monad m => Serial m Word64 where
  series = (fromIntegral :: Integer -> Word64) <$> series

instance Monad m => Serial m Word96 where
  series = cons2 LargeKey

instance Monad m => Serial m Text where
  series = cons1 Text.pack

instance Monad m => Serial m ByteString where
  series = cons1 ByteString.pack
