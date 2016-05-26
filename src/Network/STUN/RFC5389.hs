{-# LANGUAGE Trustworthy #-}

{-|
Module      : Network.STUN.RFC5389
Description : Implementation of STUN from RFC5389
Copyright   : (c) Ossi Herrala, 2016
License     : MIT
Maintainer  : oherrala@gmail.com
Stability   : experimental
Portability : portable

Implementation of STUN (Session Traversal Utilities for NAT) protocol
as specified in RFC5389. https://tools.ietf.org/html/rfc5389

-}

module Network.STUN.RFC5389
       (
         -- * Types
         STUNAttribute(..)
       , STUNAttributes
       , STUNMessage(..)
       , STUNType(..)

         -- * STUN parser (ByteString -> STUNMessage)
       , parseSTUNMessage

         -- * STUN producer (STUNMessage -> ByteString)
       , produceSTUNMessage
       ) where

import           Control.Monad      (unless)

import           Data.Bits          (xor)

import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as ByteString

import           Data.LargeWord

import           Data.Serialize

import           Data.Text          (Text)
import qualified Data.Text          as Text
import qualified Data.Text.Encoding as Text

import           Data.Word          (Word16, Word32)

import           Network.Socket     (HostAddress, HostAddress6)


------------------------------------------------------------------------
-- Types

data STUNMessage = STUNMessage STUNType TransactionID STUNAttributes
                 deriving (Show, Eq)

data STUNType = BindingRequest
                -- ^ RFC5389 Binding Request message type
              | BindingResponse
                -- ^ RFC5389 Binding Response message type
              | UnknownStunMessage Word16
                -- ^ Unknown message
              deriving (Show, Eq)

type TransactionID = Word96

type STUNAttributes = [STUNAttribute]

data STUNAttribute = MappedAddressIPv4 HostAddress Word16
                     -- ^ IPv4 (XOR-)MAPPED-ADDRESS Attribute
                   | MappedAddressIPv6 HostAddress6 Word16
                     -- ^ IPv6 (XOR-)MAPPED-ADDRESS Attribute
                   | Username Text
                     -- ^ USERNAME Attribute
                   | MessageIntegrity ByteString
                     -- ^ MESSAGE-INTEGRITY Attribute
                   | Fingerprint Word32
                     -- ^ FINGERPRINT Attribute
                   | Realm Text
                     -- ^ REALM Attribute
                   | Software Text
                     -- ^ SOFTWARE Attribute
                   | UnknownAttribute Word16 ByteString
                     -- ^ Unknown attribute
                   deriving (Show, Eq)


------------------------------------------------------------------------
-- Parse and produce STUN messages

-- | Parse STUN message
parseSTUNMessage :: ByteString -> Either String STUNMessage
parseSTUNMessage = runGet getSTUNMessage


-- | Produce STUN message
produceSTUNMessage :: STUNMessage -> ByteString
produceSTUNMessage = runPut . putSTUNMessage


------------------------------------------------------------------------
-- | Get / Put STUN Message
--
-- STUN Message - https://tools.ietf.org/html/rfc5389#section-6
--

-- | Get one STUN Message
getSTUNMessage :: Get STUNMessage
getSTUNMessage = do
  msgType    <- toStunType <$> getWord16be
  msgLen     <- fromIntegral <$> getWord16be
  msgCookie  <- getWord32be
  unless (msgCookie == 0x2112A442) $ fail "Magic cookie 0x2112A442 not found"
  msgTransId <- getWord96be
  msgAttrs   <- isolate msgLen (getSTUNAttributes msgTransId)
  return $! STUNMessage msgType msgTransId msgAttrs

-- | Put one STUN Message
putSTUNMessage :: STUNMessage -> Put
putSTUNMessage (STUNMessage msgType msgTransId msgAttrs) = do
  let attrs = runPut $ putSTUNAttributes msgAttrs
  putWord16be $ fromStunType msgType
  putWord16be . fromIntegral . ByteString.length $ attrs
  putWord32be 0x2112A442 -- magic cookie
  putWord96be msgTransId
  putByteString attrs

toStunType :: Word16 -> STUNType
toStunType 0x0001 = BindingRequest
toStunType 0x0101 = BindingResponse
toStunType x      = UnknownStunMessage x

fromStunType :: STUNType -> Word16
fromStunType BindingRequest         = 0x0001
fromStunType BindingResponse        = 0x0101
fromStunType (UnknownStunMessage x) = x


------------------------------------------------------------------------
-- | Get / Put STUN Attributes
--
-- STUN Attributes - https://tools.ietf.org/html/rfc5389#section-15

-- | Get STUN Attributes
getSTUNAttributes :: Word96 -> Get STUNAttributes
getSTUNAttributes transId = do
  left <- remaining
  if left < 4
    then return []
    else do
    attr <- getSTUNAttribute transId
    attrs <- getSTUNAttributes transId
    return $! attr : attrs

-- | Get one STUN Attribute
getSTUNAttribute :: Word96 -> Get STUNAttribute
getSTUNAttribute transId = do
  msgType <- getWord16be
  msgLen  <- getWord16be
  let len = fromIntegral msgLen

  msgValue <- case msgType of
    0x0001 -> getMappedAddress                 -- RFC5389 15.1. MAPPED-ADDRESS
    0x0020 -> getXORMappedAddress transId      -- RFC5389 15.2. XOR-MAPPED-ADDRESS
    -- FIXME: verify max length
    0x0006 -> Username <$> getUTF8 len         -- RFC5389 15.3. USERNAME
    0x0008 -> MessageIntegrity <$> getBytes 20 -- RFC5389 15.4. MESSAGE-INTEGRITY
    -- FIXME: Calculate XOR
    0x8028 -> Fingerprint <$> getWord32be      -- RFC5389 15.5. FINGERPRINT
                                               -- RFC5389 15.6. ERROR-CODE
    -- FIXME: verify max length
    0x0014 -> Realm <$> getUTF8 len            -- RFC5389 15.7. REALM
                                               -- RFC5389 15.8. NONCE
                                               -- RFC5389 15.9. UNKNOWN-ATTRIBUTES
    -- FIXME: verify max length
    0x8022 -> Software <$> getUTF8 len         -- RFC5389 15.10. SOFTWARE
                                               -- RFC5389 15.11. ALTERNATE-SERVER
    _ -> do                                    -- Catch all unknown attributes
      bytes <- getBytes len
      return $! UnknownAttribute msgType bytes

  --Padding to next full 32 bits = 4 bytes
  _ <- getBytes $ 4 * ceiling (fromIntegral len / 4 :: Float) - len
  return $! msgValue


-- | Put STUN Attributes
putSTUNAttributes :: STUNAttributes -> Put
putSTUNAttributes = mapM_ putSTUNAttribute


-- | Put STUN Attribute
putSTUNAttribute :: STUNAttribute -> Put

putSTUNAttribute (MappedAddressIPv4 addr port) = do
  putWord16be 0x0001 -- type
  putWord16be 64     -- length
  putWord16be 0x0001 -- value - family
  putWord16be port   --       - port
  putWord32be addr   --       - IPv4 address

putSTUNAttribute (MappedAddressIPv6 addr port) = do
  let (addr1, addr2, addr3, addr4) = addr
  putWord16be 0x0001 -- type
  putWord16be 160    -- length
  putWord16be 0x0002 -- value - family
  putWord16be port   --       - port
  putWord32be addr1  --       - IPv6 address
  putWord32be addr2  --       - IPv6 address
  putWord32be addr3  --       - IPv6 address
  putWord32be addr4  --       - IPv6 address

putSTUNAttribute (Username text) = do
  putWord16be 0x0006                              -- type
  putWord16be . fromIntegral . Text.length $ text -- length
  putByteString $ Text.encodeUtf8 text            -- value

putSTUNAttribute (MessageIntegrity _)         = undefined
putSTUNAttribute (Fingerprint _)              = undefined

putSTUNAttribute (Realm text) = do
  putWord16be 0x0014                              -- type
  putWord16be . fromIntegral . Text.length $ text -- length
  putByteString $ Text.encodeUtf8 text            -- value

putSTUNAttribute (Software text) = do
  putWord16be 0x0022                              -- type
  putWord16be . fromIntegral . Text.length $ text -- length
  putByteString $ Text.encodeUtf8 text            -- value

putSTUNAttribute _ = fail "Unknown STUN Attribute"

-- | Get STUN MAPPED-ADDRESS
getMappedAddress :: Get STUNAttribute
getMappedAddress = do
  family <- getWord16be
  port   <- getWord16be
  case family of
    -- IPv4
    0x0001 -> do
      addr <- getWord32be
      return $! MappedAddressIPv4 addr port
    -- IPv6
    0x0002 -> do
      addr1 <- getWord32be
      addr2 <- getWord32be
      addr3 <- getWord32be
      addr4 <- getWord32be
      return $! MappedAddressIPv6 (addr1, addr2, addr3, addr4) port
    _ -> fail "Unknown type in MAPPED-ADDRESS attribute"


-- | Get STUN XOR-MAPPED-ADDRESS
getXORMappedAddress :: Word96 -> Get STUNAttribute
getXORMappedAddress transId = do
  family <- getWord16be

  -- X-Port is computed by taking the mapped port in host byte order,
  -- XOR'ing it with the most significant 16 bits of the magic cookie,
  -- and then the converting the result to network byte order.
  -- .. yeah, right..
  -- Just take the port in network byte order and XOR with 0x2112
  xPort <- getWord16be
  let port =  xPort `xor` 0x2112

  case family of
    -- IPv4
    0x0001 -> do
      -- If the IP address family is IPv4, X-Address is computed by
      -- taking the mapped IP address in host byte order, XOR'ing it
      -- with the magic cookie, and converting the result to network
      -- byte order.
      -- .. See above X-Port.. :)
      xAddr <- getWord32be
      let addr = xAddr `xor` 0x2112A442
      return $! MappedAddressIPv4 addr port
    -- IPv6
    0x0002 -> do
      -- If the IP address family is IPv6, X-Address is computed by
      -- taking the mapped IP address in host byte order, XOR'ing it
      -- with the concatenation of the magic cookie and the 96-bit
      -- transaction ID, and converting the result to network byte
      -- order.
      xAddr1 <- getWord32be
      xAddr2 <- getWord32be
      xAddr3 <- getWord32be
      xAddr4 <- getWord32be
      let Right (w2, w3, w4) = runGet getThreeWord32be (runPut $ putWord96be transId)
          addr1              = xAddr1 `xor` 0x2112A442
          addr2              = xAddr2 `xor` w2
          addr3              = xAddr3 `xor` w3
          addr4              = xAddr4 `xor` w4
      return $! MappedAddressIPv6 (addr1, addr2, addr3, addr4) port
    _ -> fail "Unknown type in MAPPED-ADDRESS attribute"


------------------------------------------------------------------------
-- Utilities to work with Data.Serialize.Get and Data.Serialize.Put

-- | Read a Word64 in big endian format.
getWord96be :: Get Word96
getWord96be = do
  (b1, b2) <- getTwoOf getWord32be getWord64be
  return $! LargeKey b1 b2

-- | Put a Word64 in big endian format.
putWord96be :: Word96 -> Put
putWord96be value = do
  putWord32be $ loHalf value
  putWord64be $ hiHalf value

-- | Read three Word32s
getThreeWord32be :: Get (Word32, Word32, Word32)
getThreeWord32be = do
  b1 <- getWord32be
  b2 <- getWord32be
  b3 <- getWord32be
  return (b1, b2, b3)

-- | Pull n bytes from the input, as a strict Data.Text.
getUTF8 :: Int -> Get Text
getUTF8 len = do
  text <- getBytes len
  return $! Text.decodeUtf8 text
