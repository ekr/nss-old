/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef tls_connect_h_
#define tls_connect_h_

#include "sslt.h"

#include "tls_agent.h"

#define GTEST_HAS_RTTI 0
#include "gtest/gtest.h"

namespace nss_test {

class TlsConnectTestBase : public ::testing::Test {
 public:
  TlsConnectTestBase(Mode mode);
  virtual ~TlsConnectTestBase();

  void SetUp();
  void TearDown();
  void Init();
  void Reset();

  void EnsureTlsSetup();
  void Handshake();
  void Connect();
  void ConnectExpectFail();

  void EnableSomeECDHECiphers();
  void ConfigureSessionCache(SessionResumptionMode client,
                            SessionResumptionMode server);
  void CheckResumption(SessionResumptionMode expected);
  void EnableAlpn();
  void EnableSrtp();
  void CheckSrtp();
  void ExpectExtendedMasterSecret(bool expected);

 protected:
  void CheckExtendedMasterSecret();

  Mode mode_;
  TlsAgent* client_;
  TlsAgent* server_;
  uint16_t version_;
  std::vector<std::vector<uint8_t>> session_ids_;
  bool expect_extended_master_secret_;
};

class TlsConnectTest : public TlsConnectTestBase {
 public:
  TlsConnectTest() : TlsConnectTestBase(STREAM) {}
};

class DtlsConnectTest : public TlsConnectTestBase {
 public:
  DtlsConnectTest() : TlsConnectTestBase(DGRAM) {}
};

// A generic test class that can be either STREAM or DGRAM.  This is configured
// in ssl_loopback_unittest.cc.  All uses of this should use TEST_P().
class TlsConnectGeneric : public TlsConnectTestBase,
                          public ::testing::WithParamInterface<std::string> {
 public:
  TlsConnectGeneric();
};

} // namespace nss_test

#endif
