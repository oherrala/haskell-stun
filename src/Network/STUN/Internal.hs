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

import           Data.Bits          (setBit, shiftL, testBit, xor)
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as ByteString
import           Data.Digest.CRC32
import           Data.List          (find, sort)
import           Data.Text          (Text)
import qualified Data.Text          as Text
import qualified Data.Text.Encoding as Text
import           Data.Word          (Word16, Word32, Word8)

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
              | AllocateRequest
                -- ^ RFC5766 Allocate Request
              | AllocateResponse
                -- ^ RFC5766 Allocate Success Response
              | AllocateError
                -- ^ RFC5766 Allocate Error Response
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
                   | Fingerprint (Maybe Word32)
                     -- ^ FINGERPRINT Attribute
                   | ErrorCode Word16 Text
                     -- ^ ERROR-Code Attribute
                   | Realm Text
                     -- ^ REALM Attribute
                   | Nonce ByteString
                     -- ^ NONCE Attribute
                   | Software Text
                     -- ^ SOFTWARE Attribute

                   --
                   -- TURN Attributes
                   --
                   | Lifetime Word32
                     -- ^ RFC5766 LIFETIME
                   | RequestedTransport Word8
                     -- ^ RFC5766 REQUESTED-TRANSPORT
                   | RelayedAddressIPv4 HostAddress Word16
                   -- ^ IPv4 (XOR-)RELAYED-ADDRESS Attribute
                   | RelayedAddressIPv6 HostAddress6 Word16
                   -- ^ IPv6 (XOR-)RELAYED-ADDRESS Attribute
                   | XORRelayedAddressIPv4 HostAddress Word16
                   -- ^ IPv4 XOR-RELAYED-ADDRESS Attribute
                   | XORRelayedAddressIPv6 HostAddress6 Word16 TransactionID
                   -- ^ IPv6 XOR-RELAYED-ADDRESS Attribute

                   | UnknownAttribute Word16 ByteString
                     -- ^ Unknown attribute
                   deriving (Show, Eq)

instance Ord STUNAttribute where
  -- STUN Attributes should be ordered so that:
  --
  --   [everything else, MessageIntegrity, Fingerprint]
  --
  -- See: https://tools.ietf.org/html/rfc5389#section-15.4
  -- See: https://tools.ietf.org/html/rfc5389#section-15.5
  --
  compare (Fingerprint _) (MessageIntegrity _) = GT
  compare (MessageIntegrity _) _               = GT
  compare (Fingerprint _) _                    = GT
  compare _ _                                  = EQ


------------------------------------------------------------------------
-- | Parse and produce STUN messages

-- | Parse STUN message
parseSTUNMessage :: ByteString -> Either String STUNMessage
parseSTUNMessage bytes = do
  msg@(STUNMessage _ _ attrs) <- runGet getSTUNMessage bytes
  if hasFingerprint attrs
    then if verifyFingerprint msg bytes
         then return msg
         else fail "STUN Message fingerprint verification failed"
    else return msg


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
putSTUNMessage = putSTUNMessage' . addFingerprint' . sortAttrs'

-- | Helper for putSTUNMessage
--
-- The actual Putter for STUNMessage
putSTUNMessage' :: STUNMessage -> Put
putSTUNMessage' (STUNMessage msgType msgTransId msgAttrs) = do
  let attrs = runPut (putSTUNAttributes msgAttrs)
      attrsLen = fromIntegral . ByteString.length $ attrs
  putWord16be (fromStunType msgType)
  putWord16be attrsLen
  putWord32be 0x2112A442 -- magic cookie
  putTransactionID msgTransId
  putByteString attrs

-- | Helper for putSTUNMessage
--
-- Return new STUNMessage with attributes sorted
sortAttrs' :: STUNMessage -> STUNMessage
sortAttrs' (STUNMessage typ tid attrs) = STUNMessage typ tid (sort attrs)

-- | Helper for putSTUNMessage
--
-- Return new STUNMessage with Fingerprint attribute calculated or old
-- STUNMessage if no fingerprint attribute present.
addFingerprint' :: STUNMessage -> STUNMessage
addFingerprint' msg@(STUNMessage msgType transId attrs) =
  if hasFingerprint attrs
  then let bytes    = runPut (putSTUNMessage' msg)
           crc      = calculateFingerprint msg bytes
           oldAttrs = filter (not . isFingerprint) attrs
           newAttrs = oldAttrs ++ [Fingerprint (Just crc)]
  in STUNMessage msgType transId newAttrs
  else msg


toStunType :: Word16 -> STUNType
toStunType 0x0001 = BindingRequest
toStunType 0x0101 = BindingResponse
toStunType 0x0003 = AllocateRequest
toStunType 0x0103 = AllocateResponse
toStunType 0x0113 = AllocateError
toStunType x      = UnknownStunMessage x

fromStunType :: STUNType -> Word16
fromStunType BindingRequest         = 0x0001
fromStunType BindingResponse        = 0x0101
fromStunType AllocateRequest        = 0x0003
fromStunType AllocateResponse       = 0x0103
fromStunType AllocateError          = 0x0113
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
  len     <- fromIntegral <$> getWord16be

  msgValue <- case msgType of
    0x0001 -> getMappedAddress                 -- RFC5389 15.1. MAPPED-ADDRESS
    0x0003 -> getChangeRequest                 -- RFC5780 7.2.  CHANGE-REQUEST
    0x0020 -> getXORMappedAddress transId      -- RFC5389 15.2. XOR-MAPPED-ADDRESS
    0x0006 -> Username <$> getUTF8 len (MaxBytes 512) -- RFC5389 15.3. USERNAME
    0x0008 -> MessageIntegrity <$> getBytes 20 -- RFC5389 15.4. MESSAGE-INTEGRITY

    0x8028 -> Fingerprint . Just <$> getWord32be -- RFC5389 15.5. FINGERPRINT
    0x0009 -> getErrorCode len                 -- RFC5389 15.6. ERROR-CODE
    0x0014 -> Realm <$> getUTF8 len (MaxChars 127) -- RFC5389 15.7. REALM
    -- FIXME: Verify max length
    0x0015 -> Nonce <$> getBytes len           -- RFC5389 15.8. NONCE
                                               -- RFC5389 15.9. UNKNOWN-ATTRIBUTES
    0x8022 -> Software <$> getUTF8 len (MaxChars 127) -- RFC5389 15.10. SOFTWARE
                                               -- RFC5389 15.11. ALTERNATE-SERVER

    0x000D -> Lifetime <$> getWord32be         -- RFC5766 14.2. LIFETIME
    0x0016 -> getXORRelayedAddress transId     -- RFC5766 xx.x. XOR-RELAYED-ADDRESS
    0x0019 -> getRequestedTransport            -- RFC5766 14.7. REQUESTED-TRANSPORT

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
--
{- 0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Type                  |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Value (variable)                ....
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-}
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

putSTUNAttribute (MappedAddressIPv6 addr port) = do
  let (addr1, addr2, addr3, addr4) = addr
  attrTLV 0x0001 $ do
    putWord16be 0x0002 -- family
    putWord16be port   -- port
    putWord32be addr1  -- IPv6 address
    putWord32be addr2  -- IPv6 address
    putWord32be addr3  -- IPv6 address
    putWord32be addr4  -- IPv6 address

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

putSTUNAttribute (XORRelayedAddressIPv4 addr port) = do
  -- See getXORMappedAddress function for how XOR encoding works
  let (b1, b2, b3, b4) = Socket.hostAddressToTuple addr
  let xPort = port `xor` 0x2112
      x1 = b1 `xor` 0x21
      x2 = b2 `xor` 0x12
      x3 = b3 `xor` 0xA4
      x4 = b4 `xor` 0x42
  attrTLV 0x0016 $ do
    putWord16be 0x0001              -- family
    putWord16be xPort               -- port
    mapM_ putWord8 [x1, x2, x3, x4] -- IPv4 address

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

putSTUNAttribute (MessageIntegrity _) = undefined

putSTUNAttribute (Fingerprint value) =
  attrTLV 0x8028 $
  case value of
    Just fp -> putWord32be fp
    Nothing -> putWord32be 0xdeadbeef -- 0xdeadbeef should not appear on wire


putSTUNAttribute (ErrorCode errorCode reason) =
  attrTLV 0x009 $ do
  putWord16be 0
  -- The Class represents the hundreds digit of the error code.
  putWord8 (fromIntegral $ errorCode `quot` 100)
  -- The Number represents the error code modulo 100.
  putWord8 (fromIntegral $ errorCode `mod` 100)
  putByteString . Text.encodeUtf8 $ reason

putSTUNAttribute (Realm text) =
  attrTLV 0x0014 (putByteString . Text.encodeUtf8 $ text)

putSTUNAttribute (Nonce bytes) = attrTLV 0x0015 (putByteString bytes)

putSTUNAttribute (Software text) =
  attrTLV 0x8022 (putByteString . Text.encodeUtf8 $ text)

-- RFC5766 LIFETIME
putSTUNAttribute (Lifetime seconds) =
  attrTLV 0x000D (putWord32be seconds)

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


getXORAddress :: TransactionID
              -> (HostAddress -> Word16 -> STUNAttribute)
              -- ^ MappedAddressIPv4 or (XOR)RelayedAddressIPv4 constructor
              -> (HostAddress6 -> Word16 -> STUNAttribute)
              -- ^ MappedAddressIPv6 or (XOR)RelayedAddressIPv6 constructor
              -> Get STUNAttribute
getXORAddress transId ipv4 ipv6 = do
  family <- getWord16be

  -- X-Port is computed by taking the mapped port in host byte order,
  -- XOR'ing it with the most significant 16 bits of the magic cookie,
  -- and then the converting the result to network byte order.
  xPort <- getWord16be
  let port =  xPort `xor` 0x2112

  case family of
    -- IPv4
    0x0001 -> do
      -- If the IP address family is IPv4, X-Address is computed by
      -- taking the mapped IP address in host byte order, XOR'ing it
      -- with the magic cookie, and converting the result to network
      -- byte order.
      xAddr1 <- getWord8
      xAddr2 <- getWord8
      xAddr3 <- getWord8
      xAddr4 <- getWord8
      let addr = Socket.tupleToHostAddress
                 ( xAddr1 `xor` 0x21
                 , xAddr2 `xor` 0x12
                 , xAddr3 `xor` 0xA4
                 , xAddr4 `xor` 0x42
                 )
      return $! ipv4 addr port
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
      return $! ipv6 (addr1, addr2, addr3, addr4) port
    _ -> fail "Unknown family in attribute"

-- | Get STUN XOR-MAPPED-ADDRESS
getXORMappedAddress :: TransactionID -> Get STUNAttribute
getXORMappedAddress transId =
  getXORAddress transId MappedAddressIPv4 MappedAddressIPv6

-- | Get STUN XOR-RELAYED-ADDRESS
getXORRelayedAddress :: TransactionID -> Get STUNAttribute
getXORRelayedAddress transId =
  -- FIXME: Should these not be XOR addresses below?
  getXORAddress transId RelayedAddressIPv4 RelayedAddressIPv6


-- | Get ERROR-CODE
-- RFC5389 15.6. https://tools.ietf.org/html/rfc5389#section-15.6
getErrorCode :: Int -> Get STUNAttribute
getErrorCode len = do
  _reserved  <- getWord16be
  errorClass <- fromIntegral <$> getWord8
  number     <- fromIntegral <$> getWord8

  let errorCode = errorClass*100 + number
  unless (300 >= errorCode && errorCode <= 699) $
    fail ("Invalid error code " ++ show errorCode)

  reason <- getUTF8 (len-32) (MaxChars 127)
  return $! ErrorCode errorCode reason


-- | Get STUN CHANGE-REQUEST
-- RFC5780 7.2. https://tools.ietf.org/html/rfc5780#section-7.2
getChangeRequest :: Get STUNAttribute
getChangeRequest = do
  flags <- getWord32be
  let changeIP   = testBit flags 2
      changePort = testBit flags 3
  return $! ChangeRequest changeIP changePort

-- | GET TURN REQUESTED-TRANSPORT
-- RFC5766 14.7. https://tools.ietf.org/html/rfc5766#section-14.7
getRequestedTransport :: Get STUNAttribute
getRequestedTransport = do
  protocol <- getWord8
  _rffu1   <- getWord8
  _rffu2   <- getWord16be
  return $! RequestedTransport protocol


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

data UTF8Max = MaxBytes Int
             | MaxChars Int

getUTF8 :: Int -> UTF8Max -> Get Text
getUTF8 byteLen (MaxBytes maxLen) = do
  when (byteLen > maxLen) $ fail "Too many bytes to read"
  fmap Text.decodeUtf8 (getBytes byteLen)

getUTF8 byteLen (MaxChars maxLen) = do
  text <- Text.decodeUtf8 <$> getBytes byteLen
  when (Text.length text > maxLen) $ fail "Too many characters in UTF-8 string"
  return text

-- | Take Word32 out from ByteString
--
-- FIXME: If given bytestring is too short, this throws exception
bsToWord32 :: ByteString -> (Word32, ByteString)
bsToWord32 bs = (word32, ByteString.drop 4 bs)
  where
    [b4, b3, b2, b1] =
      map fromIntegral . ByteString.unpack . ByteString.take 4 $ bs
    word32 = b4 `shiftL` 24 + b3 `shiftL` 16 + b2 `shiftL` 8 + b1


hasRealm :: STUNAttributes -> Bool
hasRealm = any isRealm
  where
    isRealm (Realm _) = True
    isRealm _         = False

isFingerprint :: STUNAttribute -> Bool
isFingerprint (Fingerprint _) = True
isFingerprint _               = False

hasFingerprint :: STUNAttributes -> Bool
hasFingerprint = any isFingerprint


-- | Calculate CRC32 over STUN Message
--
-- This function expects the message has Fingerprint as last
-- attribute.
calculateFingerprint :: STUNMessage -> ByteString -> Word32
calculateFingerprint (STUNMessage _ _ attrs) bytes =
  if hasFingerprint attrs
  then let len     = ByteString.length bytes
           partial = ByteString.take (len-8) bytes
           -- STUN's CRC is xorred with magic value
           crc     = crc32 partial `xor` 0x5354554e
       in crc
  else error "Fingerprint attribute missing from message"


-- | Verify Fingerprint (CRC32) in STUN Message
--
verifyFingerprint :: STUNMessage -> ByteString -> Bool
verifyFingerprint msg@(STUNMessage _ _ attrs) bytes =
  case find isFingerprint attrs of
    Just (Fingerprint (Just fp)) ->
      let crc = calculateFingerprint msg bytes
      in crc == fp
    _ -> False
