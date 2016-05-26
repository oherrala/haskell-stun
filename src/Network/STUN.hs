{-# LANGUAGE OverloadedStrings #-}

{-|
Module      : Network.STUN
Description : Implementation of STUN from RFC5389
Copyright   : (c) Ossi Herrala, 2016
License     : MIT
Maintainer  : oherrala@gmail.com
Stability   : experimental
Portability : portable

Implementation of STUN (Session Traversal Utilities for NAT) protocol
as specified in RFC5389. https://tools.ietf.org/html/rfc5389

-}

module Network.STUN
  (
    -- * Send and receive STUN Binding Request/Response
    sendBindingRequest
  , recvBindingRequest
  ) where

import           Crypto.Random             (getSystemDRG, randomBytesGenerate)

import           Data.LargeWord            (LargeKey (..), Word96)
import           Data.Serialize            (decode)

import qualified Network.Socket            as Socket hiding (recv, recvFrom,
                                                      send, sendTo)
import qualified Network.Socket.ByteString as Socket

import           Network.STUN.RFC5389


software :: STUNAttribute
software = Software "Haskell STUN"


------------------------------------------------------------------------
-- STUN Binding Request/Response

-- | Send STUN Binding Request, then wait and return Binding Response
bindingRequest :: Socket.Socket -> IO StunMessage
bindingRequest sock = do
  transId <- sendBindingRequest sock
  return $! recvBindingRequest sock transId


-- | Send STUN Binding Request
-- Returns Transaction ID
sendBindingRequest :: Socket.Socket -> STUNAttributes -> IO Word96
sendBindingRequest sock attrs = do
  transId <- genTransactionId
  let
    attrs'   = software : attrs
    stunMsg  = STUNMessage BindingRequest transId attrs'
    datagram = produceSTUNMessage stunMsg
  _ <- Socket.send sock datagram
  return transId


-- | Receive STUN Binding Response
-- This function waits until correct Binding Response is received
recvBindingRequest :: Word96 -> Socket.Socket -> IO STUNMessage
recvBindingRequest = recvLoop
  where
    recvLoop transId sock = do
      packet <- Socket.recv sock 65536
      let response = parseSTUNMessage packet
      case response of
        Right result@(STUNMessage BindingResponse transId' _) ->
          if transId == transId'
          then return result
          else recvLoop transId sock
        _ -> recvLoop transId sock


------------------------------------------------------------------------
-- Utils

-- | Generate 96 bit Transaction ID
genTransactionId :: IO Word96
genTransactionId = do
  -- FIXME: Not secure way?
  drg <- getSystemDRG
  let (bytes, _)  = randomBytesGenerate 12 drg
      (Right w32) = decode bytes
      (Right w64) = decode bytes
  return $! LargeKey w32 w64
