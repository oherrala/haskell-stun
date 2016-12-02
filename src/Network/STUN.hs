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
    -- * Request STUN binding and return Binding response
    sendBinding
    -- * Send and receive STUN Binding Request/Response
  , sendBindingRequest
  , recvBindingResponse
    -- Wait STUN binding and return Binding response
  , recvBinding
  , recvBindingRequest
  , sendBindingResponse
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
-- STUN Binding Request/Response (client)

-- | Send STUN Binding Request, then wait and return Binding Response
sendBinding :: Socket.Socket -> IO STUNMessage
sendBinding sock = do
  transId <- sendBindingRequest sock []
  recvBindingResponse sock transId

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
recvBindingResponse :: Socket.Socket -> Word96 -> IO STUNMessage
recvBindingResponse sock transId = do
  packet <- Socket.recv sock 65536
  let response = parseSTUNMessage packet
  case response of
    Right result@(STUNMessage BindingResponse transId' _) ->
      if transId == transId'
      then return result
      else recvBindingResponse sock transId
    _ -> recvBindingResponse sock transId


------------------------------------------------------------------------
-- STUN Binding Request/Response (server)

-- | Wait STUN Binding Request, then respond with Binding Response
recvBinding :: Socket.Socket -> IO ()
recvBinding sock = do
  (request, from) <- recvBindingRequest sock
  print request
  case request of
    STUNMessage BindingRequest transId _ ->
      sendBindingResponse sock from transId
    _ -> recvBinding sock

-- | Receive STUN Binding Request
recvBindingRequest :: Socket.Socket -> IO (STUNMessage, Socket.SockAddr)
recvBindingRequest sock = do
  (packet, from) <- Socket.recvFrom sock 65536
  let request = parseSTUNMessage packet
  case request of
    Right result@(STUNMessage BindingRequest _ _) ->
      return (result, from)
    _ -> recvBindingRequest sock


-- | Send STUN Binding Response
sendBindingResponse :: Socket.Socket -> Socket.SockAddr -> TransactionID -> IO ()
sendBindingResponse sock from transId = do
  let packet = produceSTUNMessage response
  print response
  _ <- Socket.sendTo sock packet from
  return ()
  where
    mappedAddr =
      case from of
        Socket.SockAddrInet port addr ->
          XORMappedAddressIPv4 addr (fromIntegral port)
        Socket.SockAddrInet6 port _ addr _ ->
          XORMappedAddressIPv6 addr (fromIntegral port) transId
        _ -> error "We shouldn't be here"
    attrs = [software, mappedAddr]
    response = STUNMessage BindingResponse transId attrs


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
