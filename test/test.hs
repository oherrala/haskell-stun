{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.SmallCheck

import           Data.ByteArray        (convert)
import qualified Data.ByteString       as BS
import           Data.Either           (isLeft)
import           Data.List             (sort)

import qualified Network.Socket        as Socket

import           Network.STUN
import           Network.STUN.Internal

import qualified PacketSamples
import qualified RFC5769
import           SmallCheck            ()

main :: IO ()
main = defaultMain tests


tests :: TestTree
tests = testGroup "Tests" [ rfc5769Tests
                          , samplePacketTests
                          , unitTests
                          , negativeTests
                          , scProps
                          ]


rfc5769Tests :: TestTree
rfc5769Tests = testGroup "RFC5769 Test Vectors"
  [ testCase "2.1. Sample Request" $
    let bytes = RFC5769.sampleRequest
        Right msg = parseSTUNMessage bytes
        STUNMessage stunType transID attrs = msg
        username = "evtj:h6vY"
        key = shortTermKey "VOkJxbRl1RmTxUk/WvJxBt"
        software = "STUN test client"
    in sequence_
       [ stunType @=? (STUNType Binding Request)
       , transID @=? (0xb7e7a701, 0xbc34d686, 0xfa87dfae)
       , assertBool "Software attribute" $ elem (Software software) attrs
       , assertBool "Username attribute" $ elem (Username username) attrs
       , assertBool "Message-Integrity attribute" $
         verifyMessageIntegrity msg bytes key
       , assertBool "Fingerprint attribute" $ verifyFingerprint msg bytes
       ]

  , testCase "2.2. Sample IPv4 Response" $
    let bytes = RFC5769.sampleIPv4Response
        Right msg = parseSTUNMessage bytes
        STUNMessage stunType transID attrs = msg
        key = shortTermKey "VOkJxbRl1RmTxUk/WvJxBt"
        software = "test vector"
        ipAddr = Socket.tupleToHostAddress (192,0,2,1)
        port = 32853
    in sequence_
       [ stunType @=? (STUNType Binding Response)
       , transID @=? (0xb7e7a701, 0xbc34d686, 0xfa87dfae)
       , assertBool "Software attribute" $ elem (Software software) attrs
       , assertBool "Mapped-Address attribute" $
         elem (MappedAddressIPv4 ipAddr port) attrs
       , assertBool "Message-Integrity attribute" $
         verifyMessageIntegrity msg bytes key
       , assertBool "Fingerprint attribute" $ verifyFingerprint msg bytes
       ]

  , testCase "2.3. Sample IPv6 Response" $
    let bytes = RFC5769.sampleIPv6Response
        (Right msg) = parseSTUNMessage bytes
        (STUNMessage stunType transID attrs) = msg
        key = shortTermKey "VOkJxbRl1RmTxUk/WvJxBt"
        software = "test vector"
        ipAddr = Socket.tupleToHostAddress6
                 (0x2001,0xdb8,0x1234,0x5678,0x11,0x2233,0x4455,0x6677)
        port = 32853
    in sequence_
       [ stunType @=? (STUNType Binding Response)
       , transID @=? (0xb7e7a701, 0xbc34d686, 0xfa87dfae)
       , assertBool "Software attribute" $ elem (Software software) attrs
       , assertBool "Mapped-Address attribute" $
         elem (MappedAddressIPv6 ipAddr port) attrs
       , assertBool "Message-Integrity attribute" $
         verifyMessageIntegrity msg bytes key
       , assertBool "Fingerprint attribute" $ verifyFingerprint msg bytes
       ]

  , testCase "2.4. Sample Request with Long-Term Authentication" $
    let bytes = RFC5769.sampleReqWithLongTermAuth
        (Right msg) = parseSTUNMessage bytes
        (STUNMessage stunType transID attrs) = msg
        realm = "example.org"
        username = "マトリックス"
        password = "TheMatrIX"
        nonce = "f//499k954d6OL34oL9FSTvy64sA"
        key = longTermKey realm username password
    in sequence_
       [ stunType @=? (STUNType Binding Request)
       , transID @=? (0x78ad3433, 0xc6ad72c0, 0x29da412e)
       , assertBool "Realm attribute" $ elem (Realm realm) attrs
       , assertBool "Nonce attribute" $ elem (Nonce nonce) attrs
       , assertBool "Message-Integrity attribute" $
         verifyMessageIntegrity msg bytes key
       , assertBool "Fingerprint attribute" $ not (verifyFingerprint msg bytes)
       ]
  ]

samplePacketTests :: TestTree
samplePacketTests = testGroup "Sample Packets"
  [ testCase "Allocate Request without authentication" $
    let bytes = PacketSamples.allocateRequestNoAuth
        Right msg = parseSTUNMessage bytes
        STUNMessage stunType transID attrs = msg
    in sequence_
       [ stunType @=? (STUNType Allocate Request)
       , transID @=? (0xce2f7065, 0x5f265751, 0x9c40fa8f)
       , assertBool "Lifetime attribute" $ elem (Lifetime 3600) attrs
       , assertBool "Fingerprint attribute" $ verifyFingerprint msg bytes
       , assertBool "Fingerprint calculation" $
         calculateFingerprint msg bytes == 0x14209668
       ]

  , testCase "Allocate Request with authentication" $
    let bytes = PacketSamples.allocateRequestWithAuth
        Right msg = parseSTUNMessage bytes
        STUNMessage stunType transID attrs = msg
        realm    = "Ankh-Morpork"
        username = "donotuseme"
        password = "notasecret"
        nonce = "This is fine nonce-nse"
        key = longTermKey realm username password
    in sequence_
       [ stunType @=? (STUNType Allocate Request)
       , transID @=? (0x91191b8c, 0x0aca8aac, 0xe7660f12)
       , assertBool "Username attribute" $ elem (Username username) attrs
       , assertBool "Realm attribute" $ elem (Realm realm) attrs
       , assertBool "Nonce attribute" $ elem (Nonce nonce) attrs
       , assertBool "Message-Integrity attribute" $
         verifyMessageIntegrity msg bytes key
       , assertBool "Fingerprint attribute" $ verifyFingerprint msg bytes
       , assertBool "MessageIntegrity calculation" $
         let mac = convert (calculateMessageIntegrity msg bytes key)
         in mac == BS.pack [ 0xad, 0xf3, 0xa1, 0x96, 0xcb, 0xcb, 0xe0, 0xc9
                           , 0x50, 0xce, 0x7d, 0x44, 0x1d, 0xd8, 0x05, 0x8b
                           , 0xf8, 0x53, 0xce, 0xd8 ]
       , assertBool "Fingerprint calculation" $
         calculateFingerprint msg bytes == 0xa841046a
       ]
  ]

negativeTests :: TestTree
negativeTests = testGroup "Negative Tests"
  [ testCase "Empty bytestring" $
    let response = parseSTUNMessage BS.empty
    in assertBool "" $ isLeft response

  , testCase "One null byte" $
    let response = parseSTUNMessage "\0"
    in assertBool "" $ isLeft response

  , testCase "One million null bytes" $
    let nulls = BS.pack (replicate 1000000 0x00)
        response = parseSTUNMessage nulls
    in assertBool "" $ isLeft response

  , testCase "Incomplete STUN Binding Request (first 17 bytes)" $
    let response = parseSTUNMessage $ BS.take 17 RFC5769.sampleRequest
    in assertBool "" $ isLeft response

  , testCase "Incomplete STUN Binding Request (lost first 17 bytes)" $
    let response = parseSTUNMessage $ BS.drop 17 RFC5769.sampleRequest
    in assertBool "" $ isLeft response

  , testCase "Incomplete STUN Binding Response (first 13 bytes)" $
    let response = parseSTUNMessage $ BS.take 13 RFC5769.sampleIPv4Response
    in assertBool "" $ isLeft response

  , testCase "Incomplete STUN Binding Response (lost first 13 bytes)" $
    let response = parseSTUNMessage $ BS.drop 13 RFC5769.sampleIPv4Response
    in assertBool "" $ isLeft response
  ]


unitTests :: TestTree
unitTests = testGroup "Unit Tests" [stunAttrsSortTests, miscTests]

stunAttrsSortTests :: TestTree
stunAttrsSortTests = testGroup "STUNAttributes sorting"
  [ testCase "sort [Fingerprint, MessageIntegrity, Username]" $
    let fp    = Fingerprint (Just 1)
        mi    = MessageIntegrity (Key (shortTermKey "foo"))
        ui    = Username "trimp"
        attrs = [fp, mi, ui]
    in [ui, mi, fp] @=? sort attrs

  , testCase "sort [Fingerprint, MessageIntegrity, Username, Fingerprint, MessageIntegrity]" $
    let fp    = Fingerprint (Just 1)
        mi    = MessageIntegrity (Key (shortTermKey "foo"))
        ui    = Username "trimp"
        attrs = [fp, mi, ui, fp, mi]
    in [ui, mi, mi, fp, fp] @=? sort attrs

  , testCase "sort [Fingerprint, Username]" $
    let fp    = Fingerprint (Just 1)
        ui    = Username "trimp"
        attrs = [fp, ui]
    in [ui, fp] @=? sort attrs

  , testCase "sort [MessageIntegrity, Username]" $
    let mi    = MessageIntegrity (Key (shortTermKey "foo"))
        ui    = Username "trimp"
        attrs = [mi, ui]
    in [ui, mi] @=? sort attrs

  , testCase "sort [Lifetime, Username]" $
    let attrs = [Lifetime 1, Username "trimp"]
    in [Lifetime 1, Username "trimp"] @=? sort attrs
  ]

miscTests :: TestTree
miscTests = testGroup "Misc Tests"
  [ testCase "bsToWord32 [0x01, 0x02, 0x03, 0x04, 0x05]" $
    let bs = BS.pack [0x01, 0x02, 0x03, 0x04, 0x05]
    in (0x01020304, BS.pack [0x05]) @=? bsToWord32 bs

  , testCase "Messate-Integrity with Short-Term Authentication" $
    let key = shortTermKey "swordfish"
        msg = STUNMessage (STUNType Binding Request) (12, 654, 2) [MessageIntegrity (Key key)]
        bytes = produceSTUNMessage msg
        (Right parsed) = parseSTUNMessage bytes
    in assertBool "" $ verifyMessageIntegrity parsed bytes key

  , testCase "Messate-Integrity with Long-Term Authentication" $
    let realm = "Moria"
        user = "Gandalf"
        password = "mellon"
        key = longTermKey realm user password
        nonce = "This is nonce-nse"
        attrs = [ Realm realm
                , Username user
                , Nonce nonce
                , MessageIntegrity (Key key) ]
        msg = STUNMessage (STUNType Binding Request) (12, 654, 2) attrs
        bytes = produceSTUNMessage msg
        (Right parsed) = parseSTUNMessage bytes
    in assertBool "" $ verifyMessageIntegrity parsed bytes key

  , testCase "Messate-Integrity with Long-Term Authentication but Username missing" $
    let realm = "Moria"
        user = "Gandalf"
        password = "mellon"
        key = longTermKey realm user password
        nonce = "This is nonce-nse"
        attrs = [ Realm realm
                , Nonce nonce
                , MessageIntegrity (Key key) ]
        msg = STUNMessage (STUNType Binding Request) (1, 33, 7) attrs
        bytes = produceSTUNMessage msg
        (Right parsed) = parseSTUNMessage bytes
    in assertBool "" $ verifyMessageIntegrity parsed bytes key
  ]


scProps :: TestTree
scProps = testGroup "SmallCheck properties"
  [ testProperty "STUNMessage == parseSTUNMessage . produceSTUNMessage" $
    \msg -> let (Right msg') = parseSTUNMessage . produceSTUNMessage $ msg
            in msg' == msg

  , testProperty "STUNAttribute == parseSTUNAttribute . produceSTUNAttribute" $
    \attr ->
      let bytes = produceSTUNAttribute attr
          parsed = parseSTUNAttribute bytes (0,0,0)
      in case parsed of
        Left _ -> False
        Right attr' -> attr' == attr

  , testProperty "STUNMessage fingerprint" $
    \(STUNMessage msgType transId attrs) ->
      let msg          = STUNMessage msgType transId (fp : attrs)
          fp           = Fingerprint Nothing
          bytes        = produceSTUNMessage msg
          (Right msg') = parseSTUNMessage bytes
      in verifyFingerprint msg' bytes

  , testProperty "STUNMessage message-integrity" $
    \(STUNMessage msgType transId attrs) ->
      let msg          = STUNMessage msgType transId (msgInt : attrs)
          key          = shortTermKey "Nice password"
          msgInt       = MessageIntegrity (Key key)
          bytes        = produceSTUNMessage msg
          (Right msg') = parseSTUNMessage bytes
      in verifyMessageIntegrity msg' bytes key

  , testProperty "STUNMessage message-integrity and fingerprint" $
    \(STUNMessage msgType transId attrs) ->
      let msg          = STUNMessage msgType transId (attrs ++ [msgInt, fp])
          key          = shortTermKey "Nice password"
          msgInt       = MessageIntegrity (Key key)
          fp           = Fingerprint Nothing
          bytes        = produceSTUNMessage msg
          (Right msg') = parseSTUNMessage bytes
      in verifyMessageIntegrity msg' bytes key && verifyFingerprint msg' bytes
  ]
