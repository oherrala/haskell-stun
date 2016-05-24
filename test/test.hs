{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Test.Tasty
import           Test.Tasty.HUnit

import           Data.LargeWord       (LargeKey (..))

import           Network.STUN.RFC5389
import qualified Network.STUN.RFC5769 as RFC5769

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [rfc5769Tests]

rfc5769Tests :: TestTree
rfc5769Tests = testGroup "RFC5769 Test Vectors"
  [ testCase "2.1. Sample Request" $
    let (Right stunMessage) = parseSTUNMessage RFC5769.sampleRequest
        (STUNMessage stunType transID attrs) = stunMessage
    in sequence_
       [ stunType @=? BindingRequest
       , transID @=? LargeKey 0xb7e7a701 0xbc34d686fa87dfae
       , assertBool "Software attribute" $ elem (Software "STUN test client") attrs
       , assertBool "Username attribute" $ elem (Username "evtj:h6vY") attrs
       , assertBool "Fingerprint attribute" $ elem (Fingerprint 0xe57a3bcf) attrs
       ]

  , testCase "2.2. Sample IPv4 Response" $
    let (Right stunMessage) = parseSTUNMessage RFC5769.sampleIPv4Response
        (STUNMessage stunType transID attrs) = stunMessage
    in sequence_
       [ stunType @=? BindingResponse
       , transID @=? LargeKey 0xb7e7a701 0xbc34d686fa87dfae
       , assertBool "Software attribute" $ elem (Software "test vector") attrs
       , assertBool "Mapped-Address attribute" $ elem (MappedAddressIPv4 3221225985 32853) attrs
       , assertBool "Fingerprint attribute" $ elem (Fingerprint 0xc07d4c96) attrs
       ]

  , testCase "2.2. Sample IPv6 Response" $
    let (Right stunMessage) = parseSTUNMessage RFC5769.sampleIPv6Response
        (STUNMessage stunType transID attrs) = stunMessage
    in sequence_
       [ stunType @=? BindingResponse
       , transID @=? LargeKey 0xb7e7a701 0xbc34d686fa87dfae
       , assertBool "Software attribute" $ elem (Software "test vector") attrs
       , assertBool "Fingerprint attribute" $ elem (Fingerprint 0xc8fb0b4c) attrs
       ]
  ]
