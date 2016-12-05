{-# LANGUAGE Trustworthy #-}

{-|
Module      : Network.STUN.Internal
Description : Implementation of STUN
Copyright   : (c) Ossi Herrala, 2016
License     : MIT
Maintainer  : oherrala@gmail.com
Stability   : experimental
Portability : portable

Implementation of STUN (Session Traversal Utilities for NAT) protocol
as specified in:

 RFC5389 https://tools.ietf.org/html/rfc5389
 RFC5780 https://tools.ietf.org/html/rfc5780
-}

module Network.STUN.Internal where

import           Control.Monad      (replicateM, unless, when)

import           Data.Bits          (setBit, testBit, xor)
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as ByteString
import           Data.Text          (Text)
import qualified Data.Text.Encoding as Text
import           Data.Word          (Word16, Word32)

import           Data.Serialize

import           Network.Socket     (HostAddress, HostAddress6)
import qualified Network.Socket     as Socket


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

type TransactionID = (Word32, Word32, Word32)

type STUNAttributes = [STUNAttribute]

data STUNAttribute = MappedAddressIPv4 HostAddress Word16
                     -- ^ IPv4 (XOR-)MAPPED-ADDRESS Attribute
                   | XORMappedAddressIPv4 HostAddress Word16
                   -- ^ IPv4 XOR-MAPPED-ADDRESS Attribute
                   | ChangeRequest Bool Bool
                     -- ^ CHANGE-REQUEST Attribute
                   | MappedAddressIPv6 HostAddress6 Word16
                     -- ^ IPv6 (XOR-)MAPPED-ADDRESS Attribute
                   | XORMappedAddressIPv6 HostAddress6 Word16 TransactionID
                   -- ^ IPv6 XOR-MAPPED-ADDRESS Attribute
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
-- | Parse and produce STUN messages

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
  -- RFC5389 section 6: The most significant 2 bits of every STUN
  -- message MUST be zeroes.
  type' <- getWord16be
  when (testBit type' 15 || testBit type' 14) $ fail "Not a STUN Message"
  let msgType = toStunType type'

  -- RFC5389 section 6: The message length MUST contain the size, in
  -- bytes, of the message not including the 20-byte STUN header.
  -- Since all STUN attributes are padded to a multiple of 4 bytes,
  -- the last 2 bits of this field are always zero.
  msgLen <- fromIntegral <$> getWord16be
  unless (msgLen `mod` 4 == 0) $ fail "Length not multiple of 4"

  -- RFC5389 section 6: The magic cookie field MUST contain the fixed
  -- value 0x2112A442 in network byte order.
  msgCookie  <- getWord32be
  unless (msgCookie == 0x2112A442) $ fail "Magic cookie 0x2112A442 not found"

  msgTransId <- getTransactionID
  msgAttrs   <- isolate msgLen (getSTUNAttributes msgTransId)
  return $! STUNMessage msgType msgTransId msgAttrs

-- | Put one STUN Message
putSTUNMessage :: STUNMessage -> Put
putSTUNMessage (STUNMessage msgType msgTransId msgAttrs) = do
  let attrs = runPut $ putSTUNAttributes msgAttrs
  putWord16be $ fromStunType msgType
  putWord16be . fromIntegral . ByteString.length $ attrs
  putWord32be 0x2112A442 -- magic cookie
  putTransactionID msgTransId
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
getSTUNAttributes :: TransactionID -> Get STUNAttributes
getSTUNAttributes transId = do
  left <- remaining
  if left < 4
    then return []
    else do
    attr <- getSTUNAttribute transId
    attrs <- getSTUNAttributes transId
    return $! attr : attrs

-- | Get one STUN Attribute
getSTUNAttribute :: TransactionID -> Get STUNAttribute
getSTUNAttribute transId = do
  msgType <- getWord16be
  msgLen  <- getWord16be
  let len = fromIntegral msgLen

  msgValue <- case msgType of
    0x0001 -> getMappedAddress                 -- RFC5389 15.1. MAPPED-ADDRESS
    0x0003 -> getChangeRequest                 -- RFC5780 7.2.  CHANGE-REQUEST
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


-- Helper for encoding STUN Attributes
attrTLV :: Word16 -> Put -> Put
attrTLV type' value = do
  let payload = runPut value
      length' = fromIntegral (ByteString.length payload)
      padding = fromIntegral ((4 - (length' `mod` 4)) `mod` 4)
      bytes = ByteString.pack (take padding [0x00, 0x00, 0x00, 0x00])
  putWord16be type'
  putWord16be length'
  putByteString payload
  when (padding > 0) $ putByteString bytes

-- | Put STUN Attribute
putSTUNAttribute :: STUNAttribute -> Put

putSTUNAttribute (MappedAddressIPv4 addr port) = do
  let (b1, b2, b3, b4) = Socket.hostAddressToTuple addr
  attrTLV 0x0001 $ do
    putWord16be 0x0001              -- family
    putWord16be port                -- port
    mapM_ putWord8 [b1, b2, b3, b4] -- IPv4 address

putSTUNAttribute (XORMappedAddressIPv4 addr port) = do
  -- See getXORMappedAddress function for how XOR encoding works
  let (b1, b2, b3, b4) = Socket.hostAddressToTuple addr
  let xPort = port `xor` 0x2112
      x1 = b1 `xor` 0x21
      x2 = b2 `xor` 0x12
      x3 = b3 `xor` 0xA4
      x4 = b4 `xor` 0x42
  attrTLV 0x0020 $ do
    putWord16be 0x0001              -- family
    putWord16be xPort               -- port
    mapM_ putWord8 [x1, x2, x3, x4] -- IPv4 address

putSTUNAttribute (MappedAddressIPv6 addr port) = do
  let (addr1, addr2, addr3, addr4) = addr
  attrTLV 0x0001 $ do
    putWord16be 0x0002 -- family
    putWord16be port   -- port
    putWord32be addr1  -- IPv6 address
    putWord32be addr2  -- IPv6 address
    putWord32be addr3  -- IPv6 address
    putWord32be addr4  -- IPv6 address

putSTUNAttribute (XORMappedAddressIPv6 addr port transId) = do
  let (addr1, addr2, addr3, addr4) = addr
      w1 = 0x2112A442
      (w2, w3, w4) = transId
  let xPort = port `xor` 0x2112
      xAddr1 = addr1 `xor` w1
      xAddr2 = addr2 `xor` w2
      xAddr3 = addr3 `xor` w3
      xAddr4 = addr4 `xor` w4
  attrTLV 0x0020 $ do
    putWord16be 0x0002 -- family
    putWord16be xPort  -- port
    putWord32be xAddr1 -- IPv6 address
    putWord32be xAddr2 -- IPv6 address
    putWord32be xAddr3 -- IPv6 address
    putWord32be xAddr4 -- IPv6 address

putSTUNAttribute (ChangeRequest changeIP changePort) =
  attrTLV 0x0003 $ do
  let flags = 0
        + (if changeIP then 0 `setBit` 2 else 0)
        + (if changePort then 0 `setBit` 3 else 0)
  putWord32be flags

putSTUNAttribute (Username text) =
  attrTLV 0x0006 (putByteString . Text.encodeUtf8 $ text)

putSTUNAttribute (MessageIntegrity _)         = undefined

putSTUNAttribute (Fingerprint fp) = attrTLV 0x8028 (putWord32be fp)

putSTUNAttribute (Realm text) =
  attrTLV 0x0014 (putByteString . Text.encodeUtf8 $ text)

putSTUNAttribute (Software text) =
  attrTLV 0x8022 (putByteString . Text.encodeUtf8 $ text)

putSTUNAttribute attr = fail $ "Unknown STUN Attribute: " ++ show attr

-- | Get STUN MAPPED-ADDRESS
getMappedAddress :: Get STUNAttribute
getMappedAddress = do
  family <- getWord16be
  port   <- getWord16be
  case family of
    -- IPv4
    0x0001 -> do
      [b1, b2, b3, b4] <- replicateM 4 getWord8
      let addr = Socket.tupleToHostAddress (b1, b2, b3, b4)
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
getXORMappedAddress :: TransactionID -> Get STUNAttribute
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
      let w1           = 0x2112A442
          (w2, w3, w4) = transId
          addr1        = xAddr1 `xor` w1
          addr2        = xAddr2 `xor` w2
          addr3        = xAddr3 `xor` w3
          addr4        = xAddr4 `xor` w4
      return $! MappedAddressIPv6 (addr1, addr2, addr3, addr4) port
    _ -> fail "Unknown type in MAPPED-ADDRESS attribute"

-- | Get STUN CHANGE-REQUEST
-- RFC5780 7.2 https://tools.ietf.org/html/rfc5780#section-7.2
getChangeRequest :: Get STUNAttribute
getChangeRequest = do
  flags <- getWord32be
  let changeIP   = testBit flags 2
      changePort = testBit flags 3
  return $! ChangeRequest changeIP changePort

------------------------------------------------------------------------
-- Utilities to work with Data.Serialize.Get and Data.Serialize.Put

-- | Read TransactionID
getTransactionID :: Get TransactionID
getTransactionID = do
  w1 <- getWord32be
  w2 <- getWord32be
  w3 <- getWord32be
  return (w1, w2, w3)

-- | Put TransactionID
putTransactionID :: TransactionID -> Put
putTransactionID (w1, w2, w3) = mapM_ putWord32be [w1, w2, w3]

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
