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
  series = cons2 STUNType

instance Monad m => Serial m Method where
  series = cons0 Binding
           \/ cons0 Allocate
           \/ cons0 Refresh
           \/ cons0 Send
           \/ cons0 Data
           \/ cons0 CreatePermission
           \/ cons0 ChannelBind
           \/ cons1 UnknownMethod

instance Monad m => Serial m Class where
  series = cons0 Request
           \/ cons0 Response
           \/ cons0 Error
           \/ cons0 Indication


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
