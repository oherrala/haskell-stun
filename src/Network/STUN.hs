{-# LANGUAGE OverloadedStrings #-}

{-|
Module      : Network.STUN
Description : Implementation of Session Traversal Utilities for NAT (STUN) protocol
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
    -- * Types
    STUNMessage(..)
  , STUNType(..)
  , STUNAttributes
  , STUNAttribute(..)
  , TransactionID
  , MessageIntegrityValue(..)

    -- * Pure parser and producer
  , parseSTUNMessage
  , produceSTUNMessage

    -- * Request STUN binding and return Binding response
  , sendBinding

    -- * Send and receive STUN Binding Request/Response
  , sendBindingRequest
  , recvBindingResponse

    -- * Wait STUN binding and return Binding response
  , recvBinding
  , recvBindingRequest
  , sendBindingResponse

    -- * Utils
  , addrToXorMappedAddress
  , addrToXorRelayedAddress
  , shortTermKey
  , longTermKey

    -- * Checks for attributes
  , hasFingerprint
  , hasRealm

    -- * Get values out from attributes
  , getUsername
  ) where

import           Crypto.Random             (getSystemDRG, randomBytesGenerate)

import           Data.Word                 (Word16)

import qualified Network.Socket            as Socket hiding (recv, recvFrom,
                                                      send, sendTo)
import qualified Network.Socket.ByteString as Socket

import           Network.STUN.Internal

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
sendBindingRequest :: Socket.Socket -> STUNAttributes -> IO TransactionID
sendBindingRequest sock attrs = do
  transId <- genTransactionId
  let
    attrs'   = software : attrs
    stunMsg  = STUNMessage BindingRequest transId attrs'
    datagram = produceSTUNMessage stunMsg
  _ <- Socket.send sock datagram
  return transId

-- | Receive STUN Binding Response
-- This function waits until matching Binding Response is received
recvBindingResponse :: Socket.Socket -> TransactionID -> IO STUNMessage
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
  case request of
    STUNMessage BindingRequest transId _ ->
      sendBindingResponse sock from transId
    _ -> recvBinding sock

-- | Receive STUN Binding Request
recvBindingRequest :: Socket.Socket -> IO (STUNMessage, Socket.SockAddr)
recvBindingRequest sock = do
  (packet, from) <- Socket.recvFrom sock 65536
  putStrLn $ "Request from " ++ show from
  let request = parseSTUNMessage packet
  case request of
    Right result@(STUNMessage BindingRequest _ _) ->
      return (result, from)
    _ -> recvBindingRequest sock

-- | Send STUN Binding Response
sendBindingResponse :: Socket.Socket -> Socket.SockAddr -> TransactionID -> IO ()
sendBindingResponse sock from transId = do
  let packet = produceSTUNMessage response
  _ <- Socket.sendTo sock packet from
  return ()
  where
    mappedAddr = addrToXorMappedAddress from transId
    attrs = [software, mappedAddr, Fingerprint Nothing]
    response = STUNMessage BindingResponse transId attrs


addrToXorAddress :: (Socket.HostAddress -> Word16 -> STUNAttribute)
                 -> (Socket.HostAddress6 -> Word16 -> TransactionID -> STUNAttribute)
                 -> Socket.SockAddr -> TransactionID
                 -> STUNAttribute
addrToXorAddress ipv4 ipv6 sockAddr transId =
  case sockAddr of
    Socket.SockAddrInet port addr      -> ipv4 addr (fromIntegral port)
    Socket.SockAddrInet6 port _ addr _ -> ipv6 addr (fromIntegral port) transId
    _                                  -> error "Unsupported socket type"

-- | Map Socket's SockAddr into STUN Mapped-Address attribute
addrToXorMappedAddress :: Socket.SockAddr -> TransactionID -> STUNAttribute
addrToXorMappedAddress =
  addrToXorAddress XORMappedAddressIPv4 XORMappedAddressIPv6

-- | Map Socket's SockAddr into STUN Relayed-Address attribute
addrToXorRelayedAddress :: Socket.SockAddr -> TransactionID -> STUNAttribute
addrToXorRelayedAddress =
  addrToXorAddress XORRelayedAddressIPv4 XORRelayedAddressIPv6


-- | Generate 96 bit Transaction ID
genTransactionId :: IO TransactionID
genTransactionId = do
  -- FIXME: Not secure way?
  drg <- getSystemDRG
  -- Need 12 bytes of random, but lets take some extra (24 bytes)
  let (bs1, _)  = randomBytesGenerate 24 drg
      (w1, bs2) = bsToWord32 bs1
      (w2, bs3) = bsToWord32 bs2
      (w3, _)   = bsToWord32 bs3
  return (w1, w2, w3)
