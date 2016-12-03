{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.SmallCheck

import qualified Data.ByteString       as BS
import           Data.Either           (isLeft)

import           Network.STUN
import           Network.STUN.Internal

import qualified RFC5769
import           SmallCheck            ()

main :: IO ()
main = defaultMain tests


tests :: TestTree
tests = testGroup "Tests" [rfc5769Tests, negativeTests, scProps]


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
       , assertBool "Fingerprint attribute" $ elem (Fingerprint 0xe57a3bcf) attrs
       ]

  , testCase "2.2. Sample IPv4 Response" $
    let (Right stunMessage) = parseSTUNMessage RFC5769.sampleIPv4Response
        (STUNMessage stunType transID attrs) = stunMessage
    in sequence_
       [ stunType @=? BindingResponse
       , transID @=? (0xb7e7a701, 0xbc34d686, 0xfa87dfae)
       , assertBool "Software attribute" $ elem (Software "test vector") attrs
       , assertBool "Mapped-Address attribute" $ elem (MappedAddressIPv4 3221225985 32853) attrs
       , assertBool "Fingerprint attribute" $ elem (Fingerprint 0xc07d4c96) attrs
       ]

  , testCase "2.3. Sample IPv6 Response" $
    let (Right stunMessage) = parseSTUNMessage RFC5769.sampleIPv6Response
        (STUNMessage stunType transID attrs) = stunMessage
    in sequence_
       [ stunType @=? BindingResponse
       , transID @=? (0xb7e7a701, 0xbc34d686, 0xfa87dfae)
       , assertBool "Software attribute" $ elem (Software "test vector") attrs
       , assertBool "Fingerprint attribute" $ elem (Fingerprint 0xc8fb0b4c) attrs
       ]

  , testCase "2.4. Sample Request with Long-Term Authentication" $
    let (Right stunMessage) = parseSTUNMessage RFC5769.sampleReqWithLongTermAuth
        (STUNMessage stunType transID attrs) = stunMessage
    in sequence_
       [ stunType @=? BindingRequest
       , transID @=? (0x78ad3433, 0xc6ad72c0, 0x29da412e)
       , assertBool "Realm attribute" $ elem (Realm "example.org") attrs
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


scProps :: TestTree
scProps = testGroup "SmallCheck properties"
  [ testProperty "STUNMessage == parseSTUNMessage . produceSTUNMessage" $
    \msg -> let (Right msg') = parseSTUNMessage . produceSTUNMessage $ msg
            in msg' == msg
  ]
