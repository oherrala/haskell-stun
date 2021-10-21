{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Trustworthy       #-}

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

import           Data.Bits          (setBit, shiftL, testBit, xor, (.&.), shiftR, (.|.))
import           Data.ByteArray     (convert)
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as ByteString
import           Data.Digest.CRC32
import           Data.List          (find, sort)
import           Data.Maybe         (isJust)
import           Data.Text          (Text)
import qualified Data.Text          as Text
import qualified Data.Text.Encoding as Text
import           Data.Word          (Word16, Word32, Word8, Word64)

import           Network.Socket     (HostAddress, HostAddress6)
import qualified Network.Socket     as Socket

import           Crypto.Hash        (MD5 (..), SHA1, hashWith)
import           Crypto.MAC.HMAC    (HMAC, hmac)

import           Data.Serialize


------------------------------------------------------------------------
-- Types

data STUNMessage = STUNMessage STUNType TransactionID STUNAttributes
                 deriving (Show, Eq)

data Method = Binding
            | Allocate
            | Refresh
            | Send
            | Data
            | CreatePermission
            | ChannelBind
            | UnknownMethod Word16
            deriving(Eq,Show)

data Class = Request
           | Response
           | Error
           | Indication
           deriving(Eq,Show)

data STUNType = STUNType Method Class
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
                   | MessageIntegrity MessageIntegrityValue
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
                   
                   | ChannelNumber Word16
                     -- ^ RFC8656 CHANNEL-NUMBER
                   | PeerAddressIPv4 HostAddress Word16
                     -- ^ RFC8656 XOR-PEER-ADDRESS
                   | PeerAddressIPv6 HostAddress6 Word16
                     -- ^ RFC8656 XOR-PEER-ADDRESS
                   | XORPeerAddressIPv4 HostAddress Word16
                     -- ^ RFC8656 XOR-PEER-ADDRESS
                   | XORPeerAddressIPv6 HostAddress6 Word16 TransactionID
                     -- ^ RFC8656 XOR-PEER-ADDRESS
                   | DataValue ByteString
                     -- ^ RFC8656 DATA
                   | RequestedAddressFamily Socket.Family
                     -- ^ RFC8656 REQUESTED-ADDRESS-FAMILY
                   | EvenPort Bool
                     -- ^ RFC8656 EVEN-PORT
                   | DontFragment
                     -- ^ RFC8656 DONT-FRAGMENT
                   | ReservationToken ByteString
                     -- ^ RFC8656 RESERVATION-TOKEN
                   | AdditionalAddressFamily Socket.Family
                     -- ^ RFC8656 ADDITIONAL-ADDRESS-FAMILY
                   | AddressErrorCode Socket.Family Word8 Word8 Text
                     -- ^ RFC8656 ADDRESS-ERROR-CODE
                   | Icmp Word8 Word16 Word32
                     -- ^ RFC8656 ICMP

                   --
                   -- ICE Attributes
                   --
                   | Priority Word32
                     -- ^ RFC8445 PRIORITY
                   | UseCandidate
                     -- ^ RFC8445 USE-CANDIDATE
                   | IceControlled Word64
                     -- ^ RFC8445 ICE-CONTROLLED
                   | IceControlling Word64
                     -- ^ RFC8445 ICE-CONTROLLING
                   
                   | XNetworkIdCost Word16 Word16
                     -- ^ https://www.ietf.org/mail-archive/web/ice/current/msg00247.html
                     -- https://tools.ietf.org/html/draft-thatcher-ice-network-cost-00 section 5

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
  compare (MessageIntegrity _) (Fingerprint _) = LT
  compare (MessageIntegrity _) _               = GT
  compare (Fingerprint _) _                    = GT
  compare _ _                                  = EQ


-- | Message-Integrity value
-- When producing STUN Message, place Password value here
-- When STUN Message is parsed, HMAC value should be present
data MessageIntegrityValue = MAC ByteString
                           | Key STUNKey
  deriving (Show, Eq)


------------------------------------------------------------------------
-- | Parse and produce STUN messages

-- | Parse STUN message
--
-- This function verifies the Fingerprint attribute if present in STUN
-- Message. Message-Integrity attribute is not verified and should be
-- done after parsing the message.
parseSTUNMessage :: ByteString -> Either String STUNMessage
parseSTUNMessage bytes = do
  msg@(STUNMessage _ _ attrs) <- runGet getSTUNMessage bytes
  when (hasFingerprint attrs) (
    unless (verifyFingerprint msg bytes) $
      fail "STUN Message fingerprint verification failed"
    )
  return msg

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

  -- FIXME: With the exception of the FINGERPRINT attribute, which
  -- appears after MESSAGE-INTEGRITY, agents MUST ignore all other
  -- attributes that follow MESSAGE-INTEGRITY.
  -- See: https://tools.ietf.org/html/rfc5389#section-15.4

  return $! STUNMessage msgType msgTransId msgAttrs


-- | Put one STUN Message
putSTUNMessage :: STUNMessage -> Put
putSTUNMessage = putSTUNMessage'
                 . addFingerprint'
                 . addMessageIntegrity'
                 . sortAttrs'

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
-- Return new STUNMessage with Message-Integrity attribute calculated
-- or old STUNMessage if no Message-Integrity attribute present.
addMessageIntegrity' :: STUNMessage -> STUNMessage
addMessageIntegrity' msg@(STUNMessage msgType transId attrs) =
  case find isMessageIntegrity attrs of
    Just (MessageIntegrity (Key key)) ->
      let bytes    = runPut (putSTUNMessage' msg)
          mac      = convert (calculateMessageIntegrity msg bytes key)
          oldAttrs = takeWhile (not . isMessageIntegrity) attrs
          fp       = filter isFingerprint attrs
          mi       = MessageIntegrity (MAC mac)
          newAttrs = oldAttrs ++ [mi] ++ fp
      in
        STUNMessage msgType transId newAttrs
    _ -> msg

-- | Helper for putSTUNMessage
--
-- Return new STUNMessage with Fingerprint attribute calculated or old
-- STUNMessage if no Fingerprint attribute present.
addFingerprint' :: STUNMessage -> STUNMessage
addFingerprint' msg@(STUNMessage msgType transId attrs) =
  if hasFingerprint attrs
  then let bytes    = runPut (putSTUNMessage' msg)
           crc      = calculateFingerprint msg bytes
           oldAttrs = takeWhile (not . isFingerprint) attrs
           newAttrs = oldAttrs ++ [Fingerprint (Just crc)]
  in STUNMessage msgType transId newAttrs
  else msg

encodeMethod :: Method -> Word16
encodeMethod Binding          = 0x001
encodeMethod Allocate         = 0x003
encodeMethod Refresh          = 0x004
encodeMethod Send             = 0x006
encodeMethod Data             = 0x007
encodeMethod CreatePermission = 0x008
encodeMethod ChannelBind      = 0x009
encodeMethod (UnknownMethod x) = x .&. 0x3eef

decodeMethod :: Word16 -> Method
decodeMethod 0x001 = Binding
decodeMethod 0x003 = Allocate
decodeMethod 0x004 = Refresh
decodeMethod 0x006 = Send
decodeMethod 0x007 = Data
decodeMethod 0x008 = CreatePermission
decodeMethod 0x009 = ChannelBind
decodeMethod x = UnknownMethod (x .&. 0x3eef)

decodeClass :: Word16 -> Class
decodeClass 0x0000 = Request
decodeClass 0x0100 = Response
decodeClass 0x0110 = Error
decodeClass 0x0010 = Indication
decodeClass x = decodeClass (x .&. 0x0110)

encodeClass :: Class -> Word16
encodeClass Request    = 0x0000
encodeClass Response   = 0x0100
encodeClass Error      = 0x0110
encodeClass Indication = 0x0010

toStunType :: Word16 -> STUNType
toStunType w = let methodBits = w .&. 0x3eef
                   classBits  = w .&. 0x0110
               in STUNType (decodeMethod methodBits) (decodeClass classBits)

fromStunType :: STUNType -> Word16
fromStunType (STUNType method cls) = (encodeMethod method) .|. (encodeClass cls)



------------------------------------------------------------------------
-- | Parse and produce STUN attributes
--
-- These are intended to help testing

parseSTUNAttribute :: ByteString -> TransactionID -> Either String STUNAttribute
parseSTUNAttribute bytes transId = runGet (getSTUNAttribute transId) bytes

-- | Produce STUN attribute
produceSTUNAttribute :: STUNAttribute -> ByteString
produceSTUNAttribute = runPut . putSTUNAttribute


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

    -- RFC5389 15.4. MESSAGE-INTEGRITY
    0x0008 -> do
      sha1 <- getByteString 20
      return . MessageIntegrity . MAC . convert $ sha1

    0x8028 -> Fingerprint . Just <$> getWord32be -- RFC5389 15.5. FINGERPRINT
    0x0009 -> getErrorCode len                 -- RFC5389 15.6. ERROR-CODE
    0x0014 -> Realm <$> getUTF8 len (MaxChars 127) -- RFC5389 15.7. REALM
    -- FIXME: Verify max length
    0x0015 -> Nonce <$> getByteString len      -- RFC5389 15.8. NONCE
                                               -- RFC5389 15.9. UNKNOWN-ATTRIBUTES
    0x8022 -> Software <$> getUTF8 len (MaxChars 127) -- RFC5389 15.10. SOFTWARE
                                               -- RFC5389 15.11. ALTERNATE-SERVER

    0x000D -> Lifetime <$> getWord32be         -- RFC5766 14.2. LIFETIME
    0x0016 -> getXORRelayedAddress transId     -- RFC5766 xx.x. XOR-RELAYED-ADDRESS
    0x0019 -> getRequestedTransport            -- RFC5766 14.7. REQUESTED-TRANSPORT

    -- RFC8445 ICE
    0x0024 -> Priority <$> getWord32be         -- RFC8445 7.1.1 PRIORITY
    0x0025 -> return UseCandidate              -- RFC8445 16.1 USE-CANDIDATE
    0x8029 -> IceControlled <$> getWord64be    -- RFC8445 7.1.3 ICE-CONTROLLED
    0x802a -> IceControlling <$> getWord64be   -- RFC8445 7.1.3 ICE-CONTROLLING

    -- generated by Chrome WebRTC implementation
    0xc057 -> XNetworkIdCost <$> getWord16be <*> getWord16be -- experimental "network cost"

    -- RFC8656, missing TURN-related
    0x000c -> ChannelNumber <$> do cn <- getWord16be
                                   skip 2
                                   return cn
    0x0012 -> getXORPeerAddress transId
    0x0013 -> DataValue <$> getByteString len
    0x0017 -> RequestedAddressFamily <$> getAddressFamily
    0x0018 -> EvenPort <$> (\b -> (b .&. 0x80) /= 0) <$> getWord8
    0x001a -> pure DontFragment
    0x0022 -> ReservationToken <$> getByteString 8
    0x8000 -> AdditionalAddressFamily <$> getAddressFamily
    0x8001 -> getAddressErrorCode len
    0x8004 -> getIcmp
      
    _ -> do                                    -- Catch all unknown attributes
      bytes <- getByteString len
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
  attrTLV 0x0020 $ putXORAddress4 addr port

putSTUNAttribute (XORRelayedAddressIPv4 addr port) = do
  attrTLV 0x0016 $ putXORAddress4 addr port

putSTUNAttribute (XORMappedAddressIPv6 addr port transId) =
  attrTLV 0x0020 $ putXORAddress6 addr port transId

putSTUNAttribute (XORRelayedAddressIPv6 addr port transId) =
  attrTLV 0x0016 $ putXORAddress6 addr port transId

putSTUNAttribute (ChangeRequest changeIP changePort) =
  attrTLV 0x0003 $ do
  let flags = 0
        + (if changeIP then 0 `setBit` 2 else 0)
        + (if changePort then 0 `setBit` 3 else 0)
  putWord32be flags

putSTUNAttribute (Username text) =
  attrTLV 0x0006 (putByteString . Text.encodeUtf8 $ text)

putSTUNAttribute (MessageIntegrity value) =
  attrTLV 0x0008 $
  case value of
    MAC mac -> putByteString mac
    Key _   -> putByteString (ByteString.pack deadbeef)
  where
    deadbeef = concat (replicate 5 [0xde, 0xad, 0xbe, 0xef])

putSTUNAttribute (Fingerprint value) =
  attrTLV 0x8028 $
  case value of
    Just fp -> putWord32be fp
    Nothing -> putWord32be 0xdeadbeef -- 0xdeadbeef should not appear on wire

putSTUNAttribute (ErrorCode errorCode reason) =
  attrTLV 0x0009 $ do
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

putSTUNAttribute (Lifetime seconds) =
  attrTLV 0x000D (putWord32be seconds)

-- https://tools.ietf.org/html/rfc5766#section-14.7
putSTUNAttribute (RequestedTransport transport) =
  attrTLV 0x0019 $ do
  putWord8 transport
  putWord8 0
  putWord16be 0

putSTUNAttribute (Priority prio) =
  attrTLV 0x0024 (putWord32be prio)

putSTUNAttribute (UseCandidate) =
  attrTLV 0x0025 (return ())

putSTUNAttribute (IceControlled tiebreaker) =
  attrTLV 0x8029 (putWord64be tiebreaker)

putSTUNAttribute (IceControlling tiebreaker) =
  attrTLV 0x802a (putWord64be tiebreaker)

putSTUNAttribute (XNetworkIdCost netid netcost) =
  attrTLV 0xc057 (putWord16be netid >> putWord16be netcost)

-- RFC8656 missing TURN-related
putSTUNAttribute (ChannelNumber cn) =
  attrTLV 0x000c (putWord16be cn >> putWord16be 0)

putSTUNAttribute (XORPeerAddressIPv4 addr port) =
  attrTLV 0x0012 $ putXORAddress4 addr port
  
putSTUNAttribute (XORPeerAddressIPv6 addr port transId) =
  attrTLV 0x0012 $ putXORAddress6 addr port transId

putSTUNAttribute (DataValue bs) =
  attrTLV 0x0013 $ putByteString bs

putSTUNAttribute (RequestedAddressFamily af) =
  attrTLV 0x0017 $ putAddressFamily af

putSTUNAttribute (EvenPort b) =
  attrTLV 0x0018 $ putWord8 $ if b then 0x80 else 0x00

putSTUNAttribute (DontFragment) =
  attrTLV 0x001a $ return ()

putSTUNAttribute (ReservationToken bs) =
  attrTLV 0x0022 $ putByteString $ ByteString.take 8 bs

putSTUNAttribute (AdditionalAddressFamily af) =
  attrTLV 0x8000 $ putAddressFamily af

putSTUNAttribute (AddressErrorCode af cls num txt) =
  attrTLV 0x8001 $ putAddressErrorCode af cls num txt

putSTUNAttribute (Icmp typ cod dat) =
  attrTLV 0x8004 $ putIcmp typ cod dat
  
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

-- | Get STUN XOR-PEER-ADDRESS
getXORPeerAddress :: TransactionID -> Get STUNAttribute
getXORPeerAddress transId =
  getXORAddress transId PeerAddressIPv4 PeerAddressIPv6


-- | Get ERROR-CODE
-- RFC5389 15.6. https://tools.ietf.org/html/rfc5389#section-15.6
getErrorCode :: Int -> Get STUNAttribute
getErrorCode len = do
  _reserved  <- getWord16be
  errorClass <- fromIntegral <$> getWord8
  number     <- fromIntegral <$> getWord8

  let errorCode = errorClass*100 + number
  unless (300 <= errorCode && errorCode <= 699) $
    fail ("Invalid error code " ++ show errorCode)

  -- reserved, errorClass and number take first 32 bits = 4 bytes
  reason <- getUTF8 (len-4) (MaxChars 127)
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

getAddressFamily :: Get Socket.Family
getAddressFamily = do
  af <- toAddressFamily <$> getWord8
  skip 3
  return af

toAddressFamily :: Word8 -> Socket.Family
toAddressFamily 0x01 = Socket.AF_INET
toAddressFamily 0x02 = Socket.AF_INET6
toAddressFamily _ = error "Invalid address family encoded value"

getAddressErrorCode :: Int -> Get STUNAttribute
getAddressErrorCode len = do
  af <- toAddressFamily <$> getWord8
  skip 1
  cls <- getWord8
  num <- getWord8
  txt <- getUTF8 (len-4) (MaxChars 128)
  return $ AddressErrorCode af (cls .&. 7) num txt

getIcmp :: Get STUNAttribute
getIcmp = do
  skip 2
  typcod <- getWord16be
  let typ = fromIntegral $ typcod `shiftR` 9
      cod = typcod .&. 0x01ff
  dat <- getWord32be
  return $ Icmp typ cod dat

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
  when (byteLen > maxLen) $ fail "getUTF8: Too many bytes to read"
  fmap Text.decodeUtf8 (getByteString byteLen)

getUTF8 byteLen (MaxChars maxLen) = do
  text <- Text.decodeUtf8 <$> getByteString byteLen
  when (Text.length text > maxLen) $
    fail "getUTF8: Too many characters in UTF-8 string"
  return text

putUTF8 :: Text -> Put
putUTF8 = putByteString . Text.encodeUtf8

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
hasRealm = isJust . getRealm

hasNonce :: STUNAttributes -> Bool
hasNonce = isJust . getNonce

hasUsername :: STUNAttributes -> Bool
hasUsername = isJust . getRealm

hasFingerprint :: STUNAttributes -> Bool
hasFingerprint = isJust . getFingerprint

hasMessageIntegrity :: STUNAttributes -> Bool
hasMessageIntegrity = any isMessageIntegrity

getRealm :: STUNAttributes -> Maybe Text
getRealm attrs = do
  (Realm realm) <- find isRealm attrs
  return realm

getNonce :: STUNAttributes -> Maybe ByteString
getNonce attrs = do
  (Nonce nonce) <- find isNonce attrs
  return nonce

getUsername :: STUNAttributes -> Maybe Text
getUsername attrs = do
  (Username name) <- find isUsername attrs
  return name

getFingerprint :: STUNAttributes -> Maybe (Maybe Word32)
getFingerprint attrs = do
  (Fingerprint fp) <- find isFingerprint attrs
  return fp

getMessageIntegrity :: STUNAttributes -> Maybe MessageIntegrityValue
getMessageIntegrity attrs = do
  (MessageIntegrity fp) <- find isMessageIntegrity attrs
  return fp

isRealm :: STUNAttribute -> Bool
isRealm (Realm _) = True
isRealm _         = False

isNonce :: STUNAttribute -> Bool
isNonce (Nonce _) = True
isNonce _         = False

isUsername :: STUNAttribute -> Bool
isUsername (Username _) = True
isUsername _            = False

isFingerprint :: STUNAttribute -> Bool
isFingerprint (Fingerprint _) = True
isFingerprint _               = False

isMessageIntegrity :: STUNAttribute -> Bool
isMessageIntegrity (MessageIntegrity _) = True
isMessageIntegrity _                    = False


-- | Calculate CRC32 over STUN Message
--
-- This function expects the message has Fingerprint as last
-- attribute.
calculateFingerprint :: STUNMessage -> ByteString -> Word32
calculateFingerprint (STUNMessage _ _ attrs) bytes =
  if not . hasFingerprint $ attrs
  then error "Fingerprint attribute missing from message"
  else
    let len     = ByteString.length bytes
        partial = ByteString.take (len-8) bytes
        -- STUN's CRC is xorred with magic value
        crc     = crc32 partial `xor` 0x5354554e
    in crc


-- | Verify Fingerprint (CRC32) in STUN Message
--
verifyFingerprint :: STUNMessage -> ByteString -> Bool
verifyFingerprint msg@(STUNMessage _ _ attrs) bytes =
  case find isFingerprint attrs of
    Just (Fingerprint (Just fp)) ->
      let crc = calculateFingerprint msg bytes
      in crc == fp
    _ -> False


data STUNKey = STUNKey ByteString deriving (Show, Eq)

-- For short-term credentials:
-- key = SASLprep(password)
shortTermKey :: Text -> STUNKey
shortTermKey = STUNKey . Text.encodeUtf8

-- For long-term credentials, the key is 16 bytes:
-- key = MD5(username ":" realm ":" SASLprep(password))
longTermKey :: Text -> Text -> Text -> STUNKey
longTermKey realm username password = STUNKey key
  where
    keyLine = Text.concat [ username, ":", realm, ":", password ]
    key = convert . hashWith MD5 . Text.encodeUtf8 $ keyLine


-- | Calculate Message Integrity (HMAC SHA1) over STUN Message
--
-- Requires password as SASLprep'd Text
calculateMessageIntegrity :: STUNMessage -> ByteString -> STUNKey -> HMAC SHA1
calculateMessageIntegrity (STUNMessage _ _ attrs) bytes (STUNKey key) =
  if not . hasMessageIntegrity $ attrs
  then error "Message-Integrity attribute missing from message"
  else
    let (msgType, rest1)    = ByteString.splitAt 2 bytes
        (msgLen, rest2)     = ByteString.splitAt 2 rest1
        (msgCookie, rest3)  = ByteString.splitAt 4 rest2
        (transId, msgAttrs) = ByteString.splitAt 12 rest3

        fpLen = if hasFingerprint attrs then 8 else 0

        len = let lenWords = map fromIntegral (ByteString.unpack msgLen)
              in head lenWords `shiftL` 8 + (lenWords !! 1) :: Word16

        lenForMac = runPut . putWord16be $ len - fpLen
        attrsForMac = ByteString.take (fromIntegral (len - fpLen - 24)) msgAttrs

        bytes' = msgType
                 `mappend` lenForMac
                 `mappend` msgCookie
                 `mappend` transId
                 `mappend` attrsForMac
        mac = hmac key bytes'
    in
      mac


-- | Verify Message Integrity (HMAC SHA1) in STUN Message
--
-- Requires password as SASLprep'd Text
verifyMessageIntegrity :: STUNMessage -> ByteString -> STUNKey -> Bool
verifyMessageIntegrity msg@(STUNMessage _ _ attrs) bytes key =
  case find isMessageIntegrity attrs of
    Just (MessageIntegrity (MAC oldMac)) ->
      let mac = calculateMessageIntegrity msg bytes key
      in convert mac == oldMac
    _ -> False

putXORAddress4 :: HostAddress -> Word16 -> Put
putXORAddress4 addr port = do
  let (b1, b2, b3, b4) = Socket.hostAddressToTuple addr
  let xPort = port `xor` 0x2112
      x1 = b1 `xor` 0x21
      x2 = b2 `xor` 0x12
      x3 = b3 `xor` 0xA4
      x4 = b4 `xor` 0x42
  putWord16be 0x0001              -- family
  putWord16be xPort               -- port
  mapM_ putWord8 [x1, x2, x3, x4] -- IPv4 address

putXORAddress6 :: HostAddress6 -> Word16 -> TransactionID -> Put
putXORAddress6 addr port transId = do
  let (addr1, addr2, addr3, addr4) = addr
      w1 = 0x2112A442
      (w2, w3, w4) = transId
  let xPort = port `xor` 0x2112
      xAddr1 = addr1 `xor` w1
      xAddr2 = addr2 `xor` w2
      xAddr3 = addr3 `xor` w3
      xAddr4 = addr4 `xor` w4
  putWord16be 0x0002 -- family
  putWord16be xPort  -- port
  putWord32be xAddr1 -- IPv6 address
  putWord32be xAddr2 -- IPv6 address
  putWord32be xAddr3 -- IPv6 address
  putWord32be xAddr4 -- IPv6 address

putAddressFamily :: Socket.Family -> Put
putAddressFamily Socket.AF_INET  = putWord32be 0x01000000
putAddressFamily Socket.AF_INET6 = putWord32be 0x02000000
putAddressFamily _ = error "Invalid address family for STUN"

putAddressErrorCode :: Socket.Family -> Word8 -> Word8 -> Text -> Put
putAddressErrorCode af cls num txt = do
  case af of
    Socket.AF_INET -> putWord8 0x01
    Socket.AF_INET6 -> putWord8 0x02
    _ -> error "Invalid address family for STUN"
  putWord8 0
  putWord8 cls
  putWord8 num
  putUTF8 txt

putIcmp :: Word8 -> Word16 -> Word32 -> Put
putIcmp typ cod dat = do
  putWord16be 0
  let typcod = (((fromIntegral typ) .&. 0x8f) `shiftL` 9) .|. (cod .&. 0x1ff)
  putWord16be typcod
  putWord32be dat
