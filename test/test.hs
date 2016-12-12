{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.SmallCheck

import qualified Data.ByteString       as BS
import           Data.Either           (isLeft)
import           Data.List             (sort)

import qualified Network.Socket        as Socket

import           Network.STUN
import           Network.STUN.Internal

import qualified RFC5769
import           SmallCheck            ()

main :: IO ()
main = defaultMain tests


tests :: TestTree
tests = testGroup "Tests" [rfc5769Tests, unitTests, negativeTests, scProps]


rfc5769Tests :: TestTree
rfc5769Tests = testGroup "RFC5769 Test Vectors"
  [ testCase "2.1. Sample Request" $
    let (Right stunMessage) = parseSTUNMessage RFC5769.sampleRequest
        (STUNMessage stunType transID attrs) = stunMessage
    in sequence_
       [ stunType @=? BindingRequest
       , transID @=? (0xb7e7a701, 0xbc34d686, 0xfa87dfae)
       , assertBool "Software attribute" $ elem (Software "STUN test client") attrs
       , assertBool "Username attribute" $ elem (Username "evtj:h6vY") attrs
       , assertBool "Fingerprint attribute" $ verifyFingerprint stunMessage RFC5769.sampleRequest
       ]

  , testCase "2.2. Sample IPv4 Response" $
    let (Right stunMessage) = parseSTUNMessage RFC5769.sampleIPv4Response
        (STUNMessage stunType transID attrs) = stunMessage
        ipAddr = Socket.tupleToHostAddress (192,0,2,1)
        port = 32853
    in sequence_
       [ stunType @=? BindingResponse
       , transID @=? (0xb7e7a701, 0xbc34d686, 0xfa87dfae)
       , assertBool "Software attribute" $ elem (Software "test vector") attrs
       , assertBool "Mapped-Address attribute" $ elem (MappedAddressIPv4 ipAddr port) attrs
       , assertBool "Fingerprint attribute" $ verifyFingerprint stunMessage RFC5769.sampleIPv4Response
       ]

  , testCase "2.3. Sample IPv6 Response" $
    let (Right stunMessage) = parseSTUNMessage RFC5769.sampleIPv6Response
        (STUNMessage stunType transID attrs) = stunMessage
    in sequence_
       [ stunType @=? BindingResponse
       , transID @=? (0xb7e7a701, 0xbc34d686, 0xfa87dfae)
       , assertBool "Software attribute" $ elem (Software "test vector") attrs
       , assertBool "Fingerprint attribute" $ verifyFingerprint stunMessage RFC5769.sampleIPv6Response
       ]

  , testCase "2.4. Sample Request with Long-Term Authentication" $
    let (Right stunMessage) = parseSTUNMessage RFC5769.sampleReqWithLongTermAuth
        (STUNMessage stunType transID attrs) = stunMessage
    in sequence_
       [ stunType @=? BindingRequest
       , transID @=? (0x78ad3433, 0xc6ad72c0, 0x29da412e)
       , assertBool "Realm attribute" $ elem (Realm "example.org") attrs
       , assertBool "Fingerprint attribute" $ not (verifyFingerprint stunMessage RFC5769.sampleReqWithLongTermAuth)
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
    let attrs = [Fingerprint (Just 1), MessageIntegrity "foo", Username "trimp"]
    in [Username "trimp", MessageIntegrity "foo", Fingerprint (Just 1)] @=? sort attrs

  , testCase "sort [Fingerprint, Username]" $
    let attrs = [Fingerprint (Just 1), Username "trimp"]
    in [Username "trimp", Fingerprint (Just 1)] @=? sort attrs

  , testCase "sort [MessageIntegrity, Username]" $
    let attrs = [MessageIntegrity "foo", Username "trimp"]
    in [Username "trimp", MessageIntegrity "foo"] @=? sort attrs

  , testCase "sort [Lifetime, Username]" $
    let attrs = [Lifetime 1, Username "trimp"]
    in [Lifetime 1, Username "trimp"] @=? sort attrs
  ]

miscTests :: TestTree
miscTests = testGroup "Misc Tests"
  [ testCase "bsToWord32 [0x01, 0x02, 0x03, 0x04, 0x05]" $
    let bs = BS.pack [0x01, 0x02, 0x03, 0x04, 0x05]
    in (0x01020304, BS.pack [0x05]) @=? bsToWord32 bs
  ]


scProps :: TestTree
scProps = testGroup "SmallCheck properties"
  [ testProperty "STUNMessage == parseSTUNMessage . produceSTUNMessage" $
    \msg -> let (Right msg') = parseSTUNMessage . produceSTUNMessage $ msg
            in msg' == msg

  , testProperty "STUNMessage fingerprint" $
    \(STUNMessage msgType transId attrs) ->
      let msg = STUNMessage msgType transId (Fingerprint Nothing : attrs)
          bytes = produceSTUNMessage msg
          (Right msg') = parseSTUNMessage bytes
      in verifyFingerprint msg' bytes
  ]
