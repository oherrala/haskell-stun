{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module SmallCheck where

import           Test.SmallCheck.Series
import           Test.SmallCheck.Series.Instances ()

import           Network.STUN.Internal


instance Monad m => Serial m STUNMessage where
  series = localDepth (const 3) $ cons3 STUNMessage

instance Monad m => Serial m STUNType where
  series = cons0 BindingRequest \/ cons0 BindingResponse
           \/ cons0 AllocateRequest \/ cons0 AllocateResponse
           \/ cons0 AllocateError

instance Monad m => Serial m STUNAttribute where
  series = cons2 MappedAddressIPv4
           \/ cons2 MappedAddressIPv6
           \/ cons2 ChangeRequest
           \/ cons1 Username
           \/ cons1 (ErrorCode 400)
           \/ cons1 Realm
           \/ cons1 Nonce
           \/ cons1 Software
           \/ cons1 Lifetime
           \/ cons1 RequestedTransport
